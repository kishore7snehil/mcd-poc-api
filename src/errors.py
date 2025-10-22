"""
MCD-specific error classes
"""


class MCDError(Exception):
    """Base exception for all MCD-related errors"""
    pass


class ConfigurationError(MCDError):
    """
    Requirement: SDK must validate configuration at initialization
    Raised when issuer configuration is invalid or missing
    """
    pass


class IssuerValidationError(MCDError):
    """
    Requirement: SDK must reject tokens with invalid issuers
    Raised when token issuer is not in the allowed list
    """
    def __init__(self, message: str, issuer: str = None):
        super().__init__(message)
        self.issuer = issuer


class JWKSFetchError(MCDError):
    """
    Requirement: SDK must handle JWKS fetch failures gracefully
    Raised when JWKS cannot be fetched from issuer
    """
    def __init__(self, message: str, issuer: str = None, jwks_uri: str = None):
        super().__init__(message)
        self.issuer = issuer
        self.jwks_uri = jwks_uri


class TokenValidationError(MCDError):
    """
    Raised when token validation fails (signature, claims, etc.)
    """
    pass
