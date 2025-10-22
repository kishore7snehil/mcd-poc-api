# Multiple Custom Domain (MCD) Token Validator

Reference implementation of Multi-Custom Domain (MCD) support for JWT validation with Auth0.

## Features

### Three Issuer Validation Methods

**Method 1: Single Issuer**
```python
IssuerValidator(domain="tenant.auth0.com")
```

**Method 2: Static Array**
```python
IssuerValidator(issuers=["https://tenant.auth0.com", "https://custom.example.com"])
```

**Method 3: Dynamic Resolver**
```python
async def resolver(context):
    return context.token_issuer in await db.get_allowed_issuers()

IssuerValidator(resolver=resolver)
```

### Security

- Issuer validation BEFORE JWKS fetch (prevents SSRF)
- Per-issuer JWKS caching
- Issuer validation result caching
- Request context support for multi-tenant scenarios

## Quick Start

### 1. Create Virtual Environment

```bash
cd mcd-poc
python3 -m venv venv
source venv/bin/activate 
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Auth0 Credentials

Edit `tests/test_auth0.py` with your Auth0 details:

```python
# Choose validation mode
MODE = "static"  # or "single" or "dynamic"

# Configure based on mode
DOMAIN = "tenant.auth0.com"  # For single mode
ISSUERS = [
    "https://your-tenant.us.auth0.com",      # Your default domain
    "https://custom1.example.com",            # Custom domain 1
    "https://custom2.example.com"             # Custom domain 2
]

AUDIENCE = "https://your-api-identifier"     # From Auth0 API settings
CLIENT_ID = "your_client_id"                 # From M2M application
CLIENT_SECRET = "your_client_secret"         # From M2M application
```

### 4. Run the Test

```bash
python tests/test_auth0.py
```

The script will:
1. Fetch tokens from all configured issuers
2. Validate each token
3. Display detailed results

#### Testing Caching

Set `TEST_CACHING = True` in `tests/test_auth0.py` to see caching behavior:

```bash
python tests/test_auth0.py
```

This will demonstrate:
- Cache hits vs misses
- Cache contents inspection
- TTL expiration behavior

## Usage

### Programmatic Usage

```python
from validator import TokenValidator, IssuerValidator, JWKSManager

# Configure validator
issuer_validator = IssuerValidator(issuers=[
    "https://tenant.auth0.com",
    "https://custom.example.com"
])
validator = TokenValidator(issuer_validator, JWKSManager())

# Validate token
claims = await validator.validate(token, audience="https://api.example.com")
```

### Multi-Tenant with Request Context

```python
async def resolver(context):
    return context.token_issuer in await db.get_issuers(context.request_domain)

issuer_validator = IssuerValidator(resolver=resolver)
validator = TokenValidator(issuer_validator, JWKSManager())

claims = await validator.validate(
    token, 
    audience="https://api.example.com",
    request_context={"domain": "api.tenant1.com"}
)
```

## Implementation Details

See `src/validator.py` for the complete implementation:
- **IssuerValidator**: Handles all three validation methods automatically based on input
- **JWKSManager**: Fetches and caches JWKS per issuer
- **TokenValidator**: Main validation flow with security-critical ordering

