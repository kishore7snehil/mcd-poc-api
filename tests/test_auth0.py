"""
Auth0 MCD Integration Test

Demonstrates all three issuer validation methods with real Auth0 tokens.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import httpx
from validator import TokenValidator, IssuerValidator, JWKSManager, ValidationContext


# CONFIGURATION

MODE = "dynamic"  # Options: "single", "static", "dynamic"
TEST_CACHING = False  # Set to True to test caching behavior

# Single domain mode
DOMAIN = "your-tenant.auth0.com"

# Static array mode
ISSUERS = [
    "https://your-tenant.us.auth0.com",
    "https://custom1.example.com",
    "https://custom2.example.com"
]

# Auth0 credentials
AUDIENCE = "https://api.example.com"
CLIENT_ID = "your_client_id"
CLIENT_SECRET = "your_client_secret"


async def main():
    """Main test: Fetch and validate tokens from configured issuers"""
    print("=" * 70)
    print("Auth0 MCD Integration Test")
    print("=" * 70)
    
    # Initialize validator based on mode
    print(f"\nMode: {MODE}")
    
    if MODE == "single":
        issuer_validator = IssuerValidator(domain=DOMAIN)
        test_issuers = [f"https://{DOMAIN}"]
        print(f"Domain: {DOMAIN}")
    elif MODE == "static":
        issuer_validator = IssuerValidator(issuers=ISSUERS)
        test_issuers = ISSUERS
        print(f"Issuers: {len(ISSUERS)}")
        for iss in ISSUERS:
            print(f"  - {iss}")
    elif MODE == "dynamic":
        issuer_validator = IssuerValidator(resolver=dynamic_resolver)
        test_issuers = ISSUERS
        print(f"Resolver: {dynamic_resolver.__name__}")
    else:
        print(f"Invalid MODE: {MODE}")
        return
    
    validator = TokenValidator(issuer_validator, JWKSManager())
    print(f"Audience: {AUDIENCE}")
    
    # Fetch and validate tokens
    print("\n" + "=" * 70)
    print("Fetching and Validating Tokens")
    print("=" * 70)
    
    results = []
    for issuer in test_issuers:
        print(f"\n[{issuer}]")
        print("  Fetching token...")
        token = await fetch_token(issuer)
        
        if not token:
            print("  Status: FAILED (could not fetch token)")
            results.append(False)
            continue
        
        print("  Validating token...")
        result = await validate_token(validator, token, issuer, MODE)
        results.append(result)
    
    # Summary
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    
    passed = sum(results)
    total = len(results)
    print(f"\nResults: {passed}/{total} tokens validated successfully")
    
    for i, (issuer, result) in enumerate(zip(test_issuers, results), 1):
        status = "PASS" if result else "FAIL"
        print(f"  {i}. [{status}] {issuer}")
    
    if passed == total:
        print("\nAll tokens validated successfully!")
    else:
        print(f"\n{total - passed} token(s) failed validation")


async def test_caching():
    """Test caching behavior for issuer validation and JWKS"""
    print("=" * 70)
    print("Caching Test")
    print("=" * 70)
    
    # Test issuer validation caching
    print("\n1. Issuer Validation Caching")
    print("-" * 70)
    
    async def resolver(context: ValidationContext):
        print(f"  [Resolver executing for: {context.token_issuer}]")
        return context.token_issuer.endswith(".auth0.com") or context.token_issuer.endswith(".acmetest.org")
    
    validator = IssuerValidator(resolver=resolver, cache_ttl=3600)
    context1 = ValidationContext(token_issuer="https://dev-skishore.us.auth0.com")
    context2 = ValidationContext(token_issuer="https://snehilmcd-1.acmetest.org")
    
    def print_cache():
        print(f"  Cache contents: {len(validator._cache)} entries")
        for issuer, (is_valid, timestamp) in validator._cache.items():
            print(f"    - {issuer}: valid={is_valid}")
    
    print("\nValidation 1 (new issuer):")
    await validator.validate(context1)
    print_cache()
    
    print("\nValidation 2 (same issuer - should use cache):")
    await validator.validate(context1)
    print_cache()
    
    print("\nValidation 3 (different issuer):")
    await validator.validate(context2)
    print_cache()
    
    print("\nValidation 4 (back to first issuer - should use cache):")
    await validator.validate(context1)
    print_cache()
    
    if len(validator._cache) == 2:
        print(f"\n✅ Issuer caching working: 2 cache entries for 2 unique issuers")
    else:
        print(f"\n❌ Caching issue: {len(validator._cache)} cache entries")
    
    # Test JWKS caching
    print("\n2. JWKS Caching")
    print("-" * 70)
    
    jwks_manager = JWKSManager(cache_ttl=600)
    issuer = "https://dev-skishore.us.auth0.com"
    
    def print_jwks_cache():
        print(f"  Cache contents: {len(jwks_manager._cache)} entries")
        for cached_issuer, (jwks_data, timestamp) in jwks_manager._cache.items():
            keys_count = len(jwks_data.get('keys', []))
            print(f"    - {cached_issuer}: {keys_count} keys")
    
    print(f"\nBefore any fetch:")
    print_jwks_cache()
    
    print(f"\nFirst JWKS fetch (will make HTTP request):")
    try:
        jwks1 = await jwks_manager.get_jwks(issuer)
        print(f"  ✅ Fetched {len(jwks1.get('keys', []))} keys")
        print_jwks_cache()
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return
    
    print(f"\nSecond JWKS fetch (should use cache):")
    try:
        jwks2 = await jwks_manager.get_jwks(issuer)
        print(f"  ✅ Retrieved {len(jwks2.get('keys', []))} keys")
        print_jwks_cache()
        
        if jwks1 == jwks2:
            print(f"\n✅ JWKS caching working: Same data returned from cache")
        else:
            print(f"\n❌ Cache issue: Different data returned")
    except Exception as e:
        print(f"  ❌ Error: {e}")



async def dynamic_resolver(context: ValidationContext):
    """
    Dynamic issuer resolver with request context access.
    Returns JWKS URL if issuer is valid, None if invalid.
    """
    is_valid_domain = (context.token_issuer.endswith(".auth0.com") or 
                       context.token_issuer.endswith(".acmetest.org"))
    
    # Demonstrate request context access
    if context.request_domain:
        print(f"    [Resolver] Request domain: {context.request_domain}")
    if context.request_headers:
        print(f"    [Resolver] Request headers available: {len(context.request_headers)} headers")
    
    # Return JWKS URL if valid, None if invalid
    if is_valid_domain:
        return f"{context.token_issuer}/.well-known/jwks.json"
    else:
        return None


async def fetch_token(issuer: str) -> str:
    """Fetch access token from issuer"""
    token_url = f"{issuer}/oauth/token"
    
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "audience": AUDIENCE,
        "grant_type": "client_credentials"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, json=payload, timeout=10.0)
            response.raise_for_status()
            data = response.json()
            return data.get("access_token")
    except Exception as e:
        print(f"  Error fetching token: {e}")
        return None


async def validate_token(validator: TokenValidator, token: str, issuer: str, mode: str):
    """Validate a token and display results"""
    if not token:
        print(f"  Status: SKIPPED (no token)")
        return False
    
    try:
        # Requirement: Pass request context to dynamic resolver
        request_context = None
        if mode == "dynamic":
            # Simulate request context (in real app, this comes from HTTP request)
            request_context = {
                "domain": "api.example.com",
                "headers": {
                    "user-agent": "MCD-PoC-Test/1.0",
                    "x-forwarded-for": "192.168.1.1"
                },
                "url": f"https://api.example.com/protected"
            }
        
        claims = await validator.validate(token, AUDIENCE, request_context)
        print(f"  Status: VALID")
        print(f"  Issuer: {claims.get('iss')}")
        print(f"  Subject: {claims.get('sub')}")
        print(f"  Expires: {claims.get('exp')}")
        return True
    except Exception as e:
        print(f"  Status: INVALID")
        print(f"  Error: {type(e).__name__}: {e}")
        return False


if __name__ == "__main__":
    if TEST_CACHING:
        asyncio.run(test_caching())
    else:
        asyncio.run(main())
