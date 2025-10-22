"""
MCD Token Validator - Core Implementation

This module implements all MCD requirements with inline documentation.
Each requirement from the PRD is marked with a comment.
"""

import time
import base64
import json
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass

import httpx
from jose import jwt, jwk
from jose.exceptions import JWTError, JWKError

from errors import (
    ConfigurationError,
    IssuerValidationError,
    JWKSFetchError,
    TokenValidationError
)


@dataclass
class ValidationContext:
    """
    Requirement: SDK must provide request context to issuer resolver
    
    Context information passed to dynamic issuer validation functions.
    Allows multi-tenant scenarios where issuer validity depends on request.
    """
    token_issuer: str
    request_domain: Optional[str] = None
    request_headers: Optional[Dict[str, str]] = None
    request_url: Optional[str] = None


class IssuerValidator:
    """
    Validates token issuers using one of three methods:
    1. Single domain (e.g., domain="tenant.auth0.com")
    2. Static list (e.g., issuers=["https://a.com", "https://b.com"])
    3. Dynamic resolver (e.g., resolver=my_function)
    
    Caches validation results to improve performance.
    """
    
    def __init__(
        self,
        domain: Optional[str] = None,
        issuers: Optional[List[str]] = None,
        resolver: Optional[Callable] = None,
        cache_ttl: int = 3600
    ):
        # Ensure exactly one method is provided
        config_count = sum([domain is not None, issuers is not None, resolver is not None])
        if config_count == 0:
            raise ConfigurationError("Must provide domain, issuers, or resolver")
        if config_count > 1:
            raise ConfigurationError("Provide only one: domain, issuers, or resolver")
        
        # Store configuration
        self.domain = domain
        self.issuers = issuers
        self.resolver = resolver
        self.cache_ttl = cache_ttl
        
        # Normalize issuers to standard format (add https://, remove trailing /)
        if domain:
            self._allowed_issuer = self._normalize(domain)
        elif issuers:
            self._allowed_issuers = [self._normalize(iss) for iss in issuers]
        
        # Cache: {issuer: (is_valid, timestamp)}
        self._cache: Dict[str, Tuple[bool, float]] = {}
    
    def _normalize(self, issuer: str) -> str:
        """Convert 'tenant.auth0.com' to 'https://tenant.auth0.com'"""
        issuer = issuer.strip()
        if not issuer.startswith("http"):
            issuer = f"https://{issuer}"
        return issuer.rstrip("/")
    
    async def validate(self, context: ValidationContext) -> bool:
        """
        Check if the token's issuer is allowed.
        Uses cache to avoid repeated validation.
        """
        issuer = context.token_issuer
        
        # Check cache first
        if issuer in self._cache:
            is_valid, timestamp = self._cache[issuer]
            if time.time() - timestamp < self.cache_ttl:
                return is_valid  # Cache hit!
            else:
                del self._cache[issuer]  # Expired, remove it
        
        # Perform validation based on what was configured
        if self.domain:
            # Single domain mode: simple equality check
            result = (issuer == self._allowed_issuer)
        
        elif self.issuers:
            # Static list mode: check if in list
            result = (issuer in self._allowed_issuers)
        
        else:
            # Dynamic resolver mode: call the user's function
            try:
                result = self.resolver(context)
                # Handle async resolvers
                if hasattr(result, '__await__'):
                    result = await result
                result = bool(result)
            except Exception:
                # If resolver fails, reject for security
                result = False
        
        # Cache the result
        self._cache[issuer] = (result, time.time())
        return result
    
    def clear_cache(self) -> None:
        """Clear the validation cache"""
        self._cache.clear()


class JWKSManager:
    """
    Fetches JWKS (public keys) from issuers and caches them.
    JWKS URL format: {issuer}/.well-known/jwks.json
    """
    
    def __init__(self, cache_ttl: int = 600):
        self.cache_ttl = cache_ttl  # Default: 10 minutes
        self._cache: Dict[str, Tuple[Dict[str, Any], float]] = {}  # {issuer: (jwks, timestamp)}
    
    async def get_jwks(self, issuer: str) -> Dict[str, Any]:
        """Fetch JWKS from issuer, using cache if available"""
        
        # Check cache first
        if issuer in self._cache:
            jwks_data, timestamp = self._cache[issuer]
            if time.time() - timestamp < self.cache_ttl:
                return jwks_data  # Cache hit!
        
        # Fetch from issuer
        jwks_uri = f"{issuer}/.well-known/jwks.json"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(jwks_uri, timeout=10.0)
                response.raise_for_status()
                jwks_data = response.json()
            
            # Cache it
            self._cache[issuer] = (jwks_data, time.time())
            return jwks_data
            
        except Exception as e:
            raise JWKSFetchError(f"Failed to fetch JWKS: {e}", issuer=issuer, jwks_uri=jwks_uri) from e
    
    def clear_cache(self) -> None:
        self._cache.clear()


class TokenValidator:
    """
    Main JWT token validator.
    
    SECURITY-CRITICAL ORDER:
    1. Decode token (unverified) → extract 'iss' claim
    2. Validate issuer → check if allowed (BEFORE fetching JWKS!)
    3. Fetch JWKS → from validated issuer only
    4. Verify signature → using JWKS public key
    5. Validate claims → aud, exp, iat
    """
    
    def __init__(self, issuer_validator: IssuerValidator, jwks_manager: JWKSManager):
        self.issuer_validator = issuer_validator
        self.jwks_manager = jwks_manager
    
    async def validate(self, token: str, audience: str, request_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Validate a JWT token with Multi-Custom-Domain support.
        
        Returns the decoded claims if valid, raises exceptions if invalid.
        """
        
        # STEP 1: Decode token (unverified) to extract 'iss' claim
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise TokenValidationError("Invalid token format")
            
            # Decode payload (middle part)
            payload_b64 = parts[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)  # Add padding
            payload_data = base64.urlsafe_b64decode(payload_b64)
            unverified_claims = json.loads(payload_data)
            
            token_issuer_raw = unverified_claims.get("iss")
            if not token_issuer_raw:
                raise TokenValidationError("Token missing 'iss' claim")
            
            token_issuer = token_issuer_raw.rstrip("/")  # Normalize (remove trailing /)
        except TokenValidationError:
            raise
        except Exception as e:
            raise TokenValidationError(f"Failed to decode token: {e}") from e
        
        # STEP 2: Validate issuer BEFORE fetching JWKS (prevents SSRF attacks!)
        validation_context = ValidationContext(
            token_issuer=token_issuer,
            request_domain=request_context.get("domain") if request_context else None,
            request_headers=request_context.get("headers") if request_context else None,
            request_url=request_context.get("url") if request_context else None
        )
        
        is_valid = await self.issuer_validator.validate(validation_context)
        if not is_valid:
            raise IssuerValidationError(f"Issuer '{token_issuer}' is not allowed", issuer=token_issuer)
        
        # STEP 3: Fetch JWKS from validated issuer
        jwks_data = await self.jwks_manager.get_jwks(token_issuer)
        
        # STEP 4: Verify signature with JWKS
        try:
            # Decode header to get 'kid' (Key ID)
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header_data = base64.urlsafe_b64decode(header_b64)
            header = json.loads(header_data)
            kid = header.get("kid")
            
            if not kid:
                raise TokenValidationError("Token missing 'kid' in header")
            
            # Find matching key in JWKS
            matching_key = None
            for key in jwks_data.get("keys", []):
                if key.get("kid") == kid:
                    matching_key = key
                    break
            
            if not matching_key:
                raise TokenValidationError(f"No matching key for kid: {kid}")
            
            # Verify signature (this also validates aud, exp, iss)
            claims = jwt.decode(
                token,
                matching_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=token_issuer_raw  
            )
            
        except JWTError as e:
            raise TokenValidationError(f"Token validation failed: {e}") from e

        # STEP 5: Additional claim validation
        # Check expiration
        now = int(time.time())
        if "exp" not in claims or now >= claims["exp"]:
            raise TokenValidationError("Token is expired")
        
        # Check issued at
        if "iat" not in claims:
            raise TokenValidationError("Missing 'iat' claim")
        
        return claims
