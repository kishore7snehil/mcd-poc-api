"""
MCD (Multi-Custom Domain) Token Validator - Reference Implementation

A clean, framework-agnostic implementation of MCD requirements for JWT validation.
"""

from validator import TokenValidator, IssuerValidator, JWKSManager, ValidationContext
from errors import (
    MCDError,
    ConfigurationError,
    IssuerValidationError,
    JWKSFetchError,
    TokenValidationError
)

__version__ = "0.1.0"

__all__ = [
    "TokenValidator",
    "IssuerValidator",
    "JWKSManager",
    "ValidationContext",
    "MCDError",
    "ConfigurationError",
    "IssuerValidationError",
    "JWKSFetchError",
    "TokenValidationError"
]
