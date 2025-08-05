# AgentAuth

A comprehensive Python library for OAuth2 and OpenID Connect (OIDC) authentication with JWT token validation. This library supports machine-to-machine (M2M) authentication and works with any Identity Provider (IdP) that implements OAuth2/OIDC standards.

## Features

- **OAuth2/OIDC Client Credentials Flow**: Machine-to-machine authentication
- **JWT Token Validation**: Validate access tokens, ID tokens, and custom JWTs
- **Enhanced Security**: All tokens must have `exp` (expiration) claims
- **Sensitive Data Protection**: Prevents logging of sensitive JWT payload data
- **Audit Logging**: Comprehensive security event logging with data sanitization
- **JWKS (JSON Web Key Set) Support**: Automatic discovery and caching of public keys using simple dictionary storage
- **Security Documentation**: Comprehensive security guide with best practices
- **Multi-IdP Support**: Works with any IdP implementing OAuth2/OIDC standards
- **Comprehensive Error Handling**: Detailed error messages and logging
- **Caching**: Intelligent caching of tokens and JWKS for performance
- **Standalone Functions**: Utility functions for specific use cases

## Installation

### From Source

```bash
git clone https://github.com/agentauth/agentauth.git
cd agentauth
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/agentauth/agentauth.git
cd agentauth
pip install -e ".[dev]"
```

## Quick Start

### Basic Usage

```python
from agentauth.core.client import OAuth2OIDCClient
from agentauth.config.client_config import ClientConfig, ClientBuilder
from agentauth.config.security_config import SecurityConfig, SecurityBuilder

# Create security configuration
security_config = (SecurityBuilder()
                  .with_security_enabled(True)
                  .with_input_limits(max_token_length=8192)
                  .with_resource_limits(max_response_size=1024*1024)
                  .build())

# Create client configuration
client_config = (ClientBuilder()
                .with_idp("Google Cloud IAM", "https://accounts.google.com")
                .with_credentials("your-client-id", "your-client-secret")
                .with_scope("https://www.googleapis.com/auth/cloud-platform")
                .with_timeout(30)
                .with_security(security_config)
                .build())

# Initialize client (security enabled by default)
client = OAuth2OIDCClient(client_config)

# Authenticate and get access token
access_token = client.authenticate()

# Validate a token
payload = client.validate_token(
    token=access_token,
    audience="your-client-id",
    issuer="https://accounts.google.com"
)
```

## Environment Variables

The AgentAuth library uses several environment variables for configuration. All variables are optional and have secure defaults.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AGENTAUTH_DISABLE_SECURITY` | No | `false` | Disable security features (set to `true` to disable) |
| `AGENTAUTH_RATE_LIMIT_PER_MINUTE` | No | `3000` | Maximum requests per minute for rate limiting |
| `AGENTAUTH_MIN_TLS_VERSION` | No | `TLSv1.2` | Minimum TLS version (TLSv1.2, TLSv1.3) |
| `AGENTAUTH_VERIFY_SSL` | No | `true` | Enable SSL certificate verification |
| `AGENTAUTH_MAX_RESPONSE_SIZE` | No | `1048576` | Maximum response size in bytes (1MB) |
| `AGENTAUTH_MAX_PROCESSING_TIME` | No | `30` | Maximum processing time in seconds |
| `AGENTAUTH_MAX_CONCURRENT_REQUESTS` | No | `10` | Maximum concurrent requests |
| `AGENTAUTH_AUDIT_LOG_FILE` | No | `None` | Path to audit log file |
| `AGENTAUTH_ENABLE_DEBUG` | No | `false` | Enable debug mode for security components |
| `GOOGLE_CLOUD_CLIENT_ID` | No* | None | Google Cloud OAuth2 client ID (for Google Cloud examples) |
| `GOOGLE_CLOUD_CLIENT_SECRET` | No* | None | Google Cloud OAuth2 client secret (for Google Cloud examples) |
| `GOOGLE_CLOUD_PROJECT` | No* | None | Google Cloud project ID (for Google Cloud examples) |
| `GOOGLE_APPLICATION_CREDENTIALS` | No* | None | Path to Google Cloud service account key file |
| `PYTHONPATH` | No | None | Python module search path (for troubleshooting) |

*Required only when running Google Cloud IAM examples.

### Security Configuration

```bash
# Disable security features (not recommended for production)
export AGENTAUTH_DISABLE_SECURITY=true

# Configure rate limiting
export AGENTAUTH_RATE_LIMIT_PER_MINUTE=5000

# Configure TLS settings
export AGENTAUTH_MIN_TLS_VERSION=TLSv1.3
export AGENTAUTH_VERIFY_SSL=true

# Configure resource limits
export AGENTAUTH_MAX_RESPONSE_SIZE=1048576  # 1MB
export AGENTAUTH_MAX_PROCESSING_TIME=30     # 30 seconds
export AGENTAUTH_MAX_CONCURRENT_REQUESTS=10 # 10 concurrent

# Configure audit logging
export AGENTAUTH_AUDIT_LOG_FILE=/var/log/security.log
export AGENTAUTH_ENABLE_DEBUG=false
```

#### **Configurable Security Policies**

AgentAuth supports fine-grained security policy configuration using the SecurityBuilder pattern:

```python
from agentauth.config.security_config import SecurityBuilder

# High-security policy
high_security_config = (SecurityBuilder()
    .with_security_enabled(True)
    .with_input_limits(max_token_length=4096, max_url_length=1024)
    .with_resource_limits(max_response_size=512*1024, max_processing_time=15)
    .with_audit_logging(audit_log_file="/var/log/security.log", enable_debug=False)
    .with_rate_limiting(rate_limit_per_minute=1000)
    .with_tls_settings(min_tls_version="TLSv1.3", verify_ssl=True)
    .build())

# Development policy
dev_security_config = (SecurityBuilder()
    .with_security_enabled(True)
    .with_input_limits(max_token_length=8192, max_url_length=2048)
    .with_resource_limits(max_response_size=1024*1024, max_processing_time=30)
    .with_audit_logging(audit_log_file=None, enable_debug=True)
    .with_rate_limiting(rate_limit_per_minute=5000)
    .with_tls_settings(min_tls_version="TLSv1.2", verify_ssl=True)
    .build())
```

> **📖 For detailed security configuration examples, see [SECURITY.md](SECURITY.md)**

### Security Features

AgentAuth implements comprehensive security measures to protect sensitive data:

#### **Sensitive Data Protection**
- **JWT Payload Sanitization**: Sensitive claims in JWT payloads are automatically redacted
- **Token Hashing**: Raw tokens are never logged; only SHA-256 hashes are used for correlation
- **Input Validation**: All inputs are validated and sanitized to prevent injection attacks
- **Secure Error Handling**: Error messages are sanitized to prevent information disclosure

#### **Audit Logging**
- **Security Event Logging**: All security events are logged with sanitized data
- **Token Validation Tracking**: Token validation attempts are logged with hashes for correlation
- **Payload Access Logging**: JWT payload access is logged with sensitive claims redacted
- **Rate Limit Monitoring**: Rate limit violations are logged for threat detection

#### **Cryptographic Security**
- **Parameter Validation**: Cryptographic parameters are validated for security
- **Anti-Replay Protection**: Nonce-based protection against token replay attacks
- **SSRF Protection**: URL validation prevents Server-Side Request Forgery attacks
- **HMAC Authentication**: HMAC-based token generation and verification
- **Secure Random Generation**: Uses cryptographically secure random number generation
- **Memory Washing**: Securely wipes sensitive data from memory

#### **TLS/SSL Security**
- **TLS 1.3 Preferred**: Enforces TLS 1.3 with TLS 1.2 fallback for compatibility
- **Secure Cipher Suites**: Enforces AES-GCM, ChaCha20-Poly1305, and other strong ciphers
- **Certificate Validation**: Mandatory SSL certificate verification and hostname matching
- **Downgrade Protection**: Prevents downgrade to insecure protocols (SSLv2, SSLv3, TLSv1, TLSv1.1)

#### **Resource Limiting & DoS Protection**
- **Response Size Limits**: Prevents memory exhaustion attacks (1MB default limit)
- **Processing Time Limits**: CPU exhaustion protection (30-second timeout)
- **Concurrency Control**: Limits concurrent requests (10 max default)
- **Rate Limiting**: Prevents abuse (3000 requests/minute default)
- **Memory Usage Control**: Monitors and limits memory consumption

#### **Code Injection Protection**
- **Algorithm Validation**: Whitelist of allowed cryptographic algorithms
- **Key Type Validation**: Validates JWK key types against allowed list
- **Dangerous Pattern Detection**: Identifies code injection attempts in inputs
- **Input Content Validation**: Validates token and URL content for malicious patterns
- **Safe Value Checking**: Ensures all input values are safe before processing

#### **Configurable Security Policies**
- **Granular Control**: Fine-grained security policy configuration
- **Runtime Updates**: Dynamic security policy changes without restart
- **Environment-Specific**: Different policies for different environments
- **Security Builder Pattern**: Type-safe security configuration using builder pattern
- **Default Secure Settings**: Secure defaults for all configurations

#### **Security Framework Integration**
- **Unified Security Interface**: Single point of security control
- **Component Coordination**: Integrated security component management
- **Policy Enforcement**: Consistent security policy application across components
- **Security State Management**: Tracks security framework state

#### **Security Performance & Monitoring**
- **Security Performance Metrics**: Monitors security operation performance
- **Resource Usage Tracking**: Tracks CPU, memory, and network usage
- **Security Event Correlation**: Links related security events
- **Real-time Monitoring**: Live security event monitoring

#### **Developer Security Tools**
- **Security Testing**: Comprehensive security test suite (99 security tests)
- **Security Examples**: Secure implementation examples provided
- **Security Documentation**: Detailed security documentation and best practices
- **Security Utilities**: Helper functions for secure operations
- **Security Validation**: Built-in security validation tools

#### **Advanced Security Features**
- **SSRF Protection**: Blocks requests to private IP ranges and metadata endpoints
- **XSS Prevention**: Detects and blocks cross-site scripting attempts
- **Path Traversal Protection**: Prevents directory traversal attacks
- **Algorithm Confusion Protection**: Prevents algorithm confusion attacks
- **Key Size Validation**: Ensures minimum key sizes (2048-bit RSA minimum)

> **📖 For detailed security information, see [SECURITY.md](SECURITY.md)**

### Google Cloud Configuration

```bash
# Required for Google Cloud IAM examples
export GOOGLE_CLOUD_CLIENT_ID="your-client-id"
export GOOGLE_CLOUD_CLIENT_SECRET="your-client-secret"
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account-key.json"
```

### Troubleshooting

```bash
# Add current directory to Python path (if import errors occur)
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

## API Reference

### Configuration Classes

#### ClientConfig Class

Configuration class for OAuth2/OIDC client settings.

```python
from agentauth.config.client_config import ClientConfig

config = ClientConfig(
    idp_name="Google Cloud IAM",
    idp_endpoint="https://accounts.google.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    scope="https://www.googleapis.com/auth/cloud-platform",
    timeout=30,
    jwks_cache_ttl=3600,
    cert_chain="/path/to/certificate-chain.pem"
)
```

#### SecurityConfig Class

Configuration class for security settings.

```python
from agentauth.config.security_config import SecurityConfig

security_config = SecurityConfig(
    enable_security=True,
    max_token_length=8192,
    max_url_length=2048,
    max_response_size=1024*1024,
    max_processing_time=30,
    max_concurrent_requests=10,
    rate_limit_per_minute=3000,
    audit_log_file="/var/log/security.log",
    enable_debug=False,
    min_tls_version="TLSv1.2",
    verify_ssl=True
)
```

#### ErrorConfig Class

Configuration class for error handling settings.

```python
from agentauth.config.error_config import ErrorConfig

error_config = ErrorConfig(
    enable_debug=False,
    sanitize_error_messages=True,
    log_error_details=True,
    error_log_file="/var/log/errors.log",
    generate_error_ids=True,
    report_security_violations=True
)
```

### Builder Pattern Classes

#### ClientBuilder Class

Builder pattern for creating ClientConfig instances.

```python
from agentauth.config.client_config import ClientBuilder

client_config = (ClientBuilder()
    .with_idp("Google Cloud IAM", "https://accounts.google.com")
    .with_credentials("your-client-id", "your-client-secret")
    .with_scope("https://www.googleapis.com/auth/cloud-platform")
    .with_timeout(30)
    .with_jwks_cache_ttl(3600)
    .with_cert_chain("/path/to/certificate-chain.pem")
    .with_security(security_config)
    .build())
```

#### SecurityBuilder Class

Builder pattern for creating SecurityConfig instances.

```python
from agentauth.config.security_config import SecurityBuilder

security_config = (SecurityBuilder()
    .with_security_enabled(True)
    .with_input_limits(max_token_length=8192, max_url_length=2048, max_client_id_length=64)
    .with_resource_limits(max_response_size=1024*1024, max_processing_time=30, 
                         max_concurrent_requests=10, max_request_rate=3000)
    .with_audit_logging(audit_log_file="/var/log/security.log", enable_debug=False)
    .with_rate_limiting(rate_limit_per_minute=3000)
    .with_tls_settings(min_tls_version="TLSv1.2", verify_ssl=True)
    .build())
```

#### ErrorConfigBuilder Class

Builder pattern for creating ErrorConfig instances.

```python
from agentauth.config.error_config import ErrorConfigBuilder

error_config = (ErrorConfigBuilder()
    .with_debug_enabled(False)
    .with_error_sanitization(True)
    .with_error_logging(log_details=True, error_log_file="/var/log/errors.log")
    .with_error_correlation(True)
    .with_security_reporting(True)
    .build())
```

### OAuth2OIDCClient Class

The main class for OAuth2/OIDC operations.

#### Constructor

```python
from agentauth.core.client import OAuth2OIDCClient
from agentauth.config.client_config import ClientConfig

client = OAuth2OIDCClient(config: ClientConfig)
```

**Parameters:**
- `config`: ClientConfig object containing all client settings

#### Methods

##### authenticate(force_refresh: bool = False, auth_token: Optional[str] = None) -> str

Authenticate using OAuth2 client credentials flow and return access token.

**Parameters:**
- `force_refresh`: Force token refresh even if cached token is still valid
- `auth_token`: Optional authentication token for additional security

**Returns:**
- Access token string

**Example:**
```python
# Get access token
access_token = client.authenticate()

# Force refresh
access_token = client.authenticate(force_refresh=True)

# With authentication token
auth_token = auth.generate_hmac_token(client.client_id)
access_token = client.authenticate(auth_token=auth_token)
```

##### get_jwks(force_refresh: bool = False) -> Dict

Retrieve JWKS (JSON Web Key Set) from the IdP.

**Parameters:**
- `force_refresh`: Force JWKS refresh even if cached

**Returns:**
- JWKS dictionary containing public keys

**Example:**
```python
jwks = client.get_jwks()
print(f"Retrieved {len(jwks.get('keys', []))} keys")
```

##### validate_token(token: str, token_type: str = 'access_token', audience: Optional[str] = None, issuer: Optional[str] = None, auth_token: Optional[str] = None) -> Dict

Validate a JWT token and return its payload.

**Parameters:**
- `token`: JWT token string
- `token_type`: Type of token ('access_token', 'id_token', etc.)
- `audience`: Expected audience (aud) claim
- `issuer`: Expected issuer (iss) claim
- `auth_token`: Optional authentication token for additional security

**Returns:**
- Token payload as dictionary

**Example:**
```python
payload = client.validate_token(
    token=access_token,
    audience="your-client-id",
    issuer="https://accounts.google.com"
)
print(f"Token subject: {payload.get('sub')}")
```

##### validate_multiple_tokens(tokens: List[Dict], audience: Optional[str] = None, issuer: Optional[str] = None) -> List[Dict]

Validate multiple JWT tokens and return their payloads.

**Parameters:**
- `tokens`: List of token dictionaries with 'token' and 'type' keys
- `audience`: Expected audience (aud) claim
- `issuer`: Expected issuer (iss) claim

**Returns:**
- List of validation results with 'token', 'type', 'valid', 'payload', and 'error' keys

**Example:**
```python
tokens = [
    {'token': token1, 'type': 'access_token'},
    {'token': token2, 'type': 'id_token'}
]

results = client.validate_multiple_tokens(
    tokens=tokens,
    audience="your-client-id",
    issuer="https://accounts.google.com"
)

for result in results:
    if result['valid']:
        print(f"Token valid: {result['payload'].get('sub')}")
    else:
        print(f"Token invalid: {result['error']}")
```

##### get_token_info(token: str) -> Dict

Get information about a JWT token without validation.

**Parameters:**
- `token`: JWT token string

**Returns:**
- Dictionary containing token information

**Example:**
```python
token_info = client.get_token_info(access_token)
print(f"Token expires at: {token_info['expires_at']}")
print(f"Token issuer: {token_info['iss']}")
```

### Standalone Functions

#### discover_oidc_config(idp_endpoint: str, timeout: int = 30) -> Dict

Discover OIDC configuration from an IdP endpoint.

**Parameters:**
- `idp_endpoint`: Base URL of the IdP
- `timeout`: HTTP request timeout in seconds

**Returns:**
- OIDC configuration dictionary

**Example:**
```python
from agentauth.core.discovery import discover_oidc_config

config = discover_oidc_config("https://accounts.google.com")
print(f"Token endpoint: {config.get('token_endpoint')}")
print(f"JWKS URI: {config.get('jwks_uri')}")
```

#### retrieve_jwks(jwks_uri: str, timeout: int = 30) -> Dict

Retrieve JWKS from a specified URI.

**Parameters:**
- `jwks_uri`: URI of the JWKS endpoint
- `timeout`: HTTP request timeout in seconds

**Returns:**
- JWKS dictionary

**Example:**
```python
from agentauth.core.discovery import retrieve_jwks

jwks = retrieve_jwks("https://www.googleapis.com/oauth2/v1/certs")
print(f"Retrieved {len(jwks.get('keys', []))} keys")
```

#### validate_token_signature(token: str, jwks: Dict, audience: Optional[str] = None, issuer: Optional[str] = None) -> Dict

Validate JWT token signature using provided JWKS.

**Parameters:**
- `token`: JWT token string
- `jwks`: JWKS dictionary
- `audience`: Expected audience (aud) claim
- `issuer`: Expected issuer (iss) claim

**Returns:**
- Token payload as dictionary

**Example:**
```python
from agentauth.core.validation import validate_token_signature

payload = validate_token_signature(
    token=access_token,
    jwks=jwks,
    audience="your-client-id",
    issuer="https://accounts.google.com"
)
```

#### validate_multiple_token_signatures(tokens: List[Dict], jwks: Dict, audience: Optional[str] = None, issuer: Optional[str] = None) -> List[Dict]

Validate multiple JWT token signatures using provided JWKS.

**Parameters:**
- `tokens`: List of token dictionaries with 'token' and 'type' keys
- `jwks`: JWKS dictionary
- `audience`: Expected audience (aud) claim
- `issuer`: Expected issuer (iss) claim

**Returns:**
- List of validation results

**Example:**
```python
from agentauth.core.validation import validate_multiple_token_signatures

tokens = [
    {'token': token1, 'type': 'access_token'},
    {'token': token2, 'type': 'id_token'}
]

results = validate_multiple_token_signatures(
    tokens=tokens,
    jwks=jwks,
    audience="your-client-id",
    issuer="https://accounts.google.com"
)

for result in results:
    if result['valid']:
        print(f"Token valid: {result['payload'].get('sub')}")
    else:
        print(f"Token invalid: {result['error']}")
```

### Security Components

#### CryptographicAuthenticator Class

Cryptographic authentication for library access.

```python
from agentauth.security.authenticator import CryptographicAuthenticator

auth = CryptographicAuthenticator()

# Generate authentication token
auth_token = auth.generate_hmac_token("client_id_123")

# Verify token
is_valid = auth.verify_hmac_token(auth_token, "client_id_123")

# Check rate limit
allowed = auth.check_rate_limit("client_id_123")

# Verify nonce
nonce = generate_secure_nonce()
is_valid = auth.verify_nonce(nonce)
```

#### InputSanitizer Class

Enhanced input validation and sanitization.

```python
from agentauth.security.components.input_sanitizer import InputSanitizer

sanitizer = InputSanitizer()

# Sanitize JWT token
token = sanitizer.sanitize_jwt_token("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...")

# Sanitize URL
url = sanitizer.sanitize_url("https://api.example.com/jwks")

# Sanitize client ID
client_id = sanitizer.sanitize_client_id("client_123")

# Sanitize JWK
sanitized_jwk = sanitizer.sanitize_jwk(jwk_data)
```

#### ResourceLimiter Class

Resource limiting and DoS protection.

```python
from agentauth.security.components.resource_limiter import ResourceLimiter

limiter = ResourceLimiter()

# Limit response size
response = limiter.limit_response_size(response)

# Limit processing time
result = limiter.limit_processing_time(expensive_function, *args)

# Acquire request slot
limiter.acquire_request_slot(client_id)

# Release request slot
limiter.release_request_slot()

# Get resource usage stats
stats = limiter.get_resource_usage_stats()
```

#### SecurityAuditLogger Class

Advanced security audit logging.

```python
from agentauth.security.components.audit_logger import SecurityAuditLogger

audit_logger = SecurityAuditLogger(log_file="security_audit.log")

# Log authentication attempts
audit_logger.log_authentication_attempt("client_123", True)

# Log token validation
audit_logger.log_token_validation("token_hash", True, validation_details)

# Log security violations
audit_logger.log_security_violation("injection_attempt", details)

# Log rate limit violations
audit_logger.log_rate_limit_violation("client_123", 100)

# Get audit summary
summary = audit_logger.get_audit_summary(time_window_minutes=60)
```

#### CodeInjectionProtector Class

Protection against code injection attacks.

```python
from agentauth.security.components.injection_protector import CodeInjectionProtector

protector = CodeInjectionProtector()

# Validate JWK structure
if protector.validate_jwk_structure(jwk):
    sanitized_jwk = protector.sanitize_jwk_data(jwk)

# Validate algorithm name
if protector.validate_algorithm_name("RS256"):
    # Use algorithm safely
    pass

# Validate key type
if protector.validate_key_type("RSA"):
    # Use key type safely
    pass

# Get allowed algorithms
allowed_algorithms = protector.get_allowed_algorithms()

# Get allowed key types
allowed_key_types = protector.get_allowed_key_types()
```

#### SecureErrorHandler Class

Secure error handling to prevent information disclosure.

```python
from agentauth.security.components.error_handler import SecureErrorHandler

error_handler = SecureErrorHandler(enable_debug=False)

# Handle errors securely
try:
    # Some operation
    pass
except Exception as e:
    error_message = error_handler.handle_error(e, "operation_context")
    # error_message contains sanitized message for users

# Get detailed error information
error_details = error_handler.get_error_details(e, "operation_context")

# Log security violations
error_handler.log_security_violation("injection_attempt", details, "WARNING")

# Sanitize exception for logging
sanitized_exception = error_handler.sanitize_exception_for_logging(e)
```

#### SecureHTTPClient Class

Secure HTTP client with TLS 1.3 preferred, TLS 1.2 fallback.

```python
from agentauth.security.components.http_client import SecureHTTPClient, verify_tls_version

# Create secure HTTP client
http_client = SecureHTTPClient(timeout=30, verify_ssl=True)

# Make secure GET request
response = http_client.get("https://api.example.com/data")

# Verify TLS version
if verify_tls_version(response):
    print("✅ TLS 1.3 preferred, TLS 1.2 fallback working correctly")

# Make secure POST request
response = http_client.post("https://api.example.com/token", data=post_data)

# Close client
http_client.close()
```

### Security Utility Functions

#### generate_secure_nonce() -> str

Generate a secure nonce for anti-replay protection.

```python
from agentauth.utils.crypto import generate_secure_nonce

nonce = generate_secure_nonce()
```

#### secure_wipe_memory(data: bytes) -> None

Securely wipe sensitive data from memory.

```python
from agentauth.utils.crypto import secure_wipe_memory

sensitive_data = b"secret_token_data"
secure_wipe_memory(sensitive_data)
```

#### validate_cryptographic_parameters(jwk: Dict) -> bool

Validate cryptographic parameters in JWK.

```python
from agentauth.utils.crypto import validate_cryptographic_parameters

if validate_cryptographic_parameters(jwk):
    # Use key safely
    pass
else:
    raise SecurityError("Insecure cryptographic parameters")
```

## Examples

### Google Cloud IAM Example

See `examples/google_cloud_iam_example.py` for a complete example using Google Cloud IAM.

#### Setup for Google Cloud IAM

1. **Create a Google Cloud Project**
2. **Enable APIs**: Enable the APIs you need
3. **Create a Service Account**:
   ```bash
   gcloud iam service-accounts create my-service-account \
     --display-name="My Service Account"
   ```
4. **Download Service Account Key**:
   ```bash
   gcloud iam service-accounts keys create key.json \
     --iam-account=my-service-account@your-project.iam.gserviceaccount.com
   ```
5. **Set Environment Variables** (see [Environment Variables](#environment-variables) section):
   ```bash
   export GOOGLE_CLOUD_CLIENT_ID="your-client-id"
   export GOOGLE_CLOUD_CLIENT_SECRET="your-client-secret"
   ```
#### Running the Google Cloud IAM Example

```bash
python examples/google_cloud_iam_example.py
```

### Security Example

See `examples/security_example.py` for a comprehensive demonstration of AgentAuth's security features.

#### Running the Security Example

```bash
python examples/security_example.py
```

### Example Web Sequence

<img width="781" height="1076" alt="agentauth_example_web_sequence" src="https://github.com/user-attachments/assets/1609edbd-1a01-408e-8719-79bb15fe2163" />

## Testing

### Run Tests

```bash
# Run all tests with unittest (recommended)
python -m unittest discover tests -v

# Run comprehensive test suite
python tests/run_tests.py

# Run specific test file
python -m unittest tests.test_agentauth -v
python -m unittest tests.test_agentauth_security -v

# Run with pytest (if installed)
python -m pytest tests/ -v

# Run with coverage (if pytest-cov is installed)
python -m pytest tests/ --cov=agentauth

# Run specific test class
python -m unittest tests.test_agentauth.TestOAuth2OIDCClient -v

# Run specific test method
python -m unittest tests.test_agentauth.TestOAuth2OIDCClient.test_authenticate_success -v
```

### Test Documentation

For comprehensive test documentation, see [`tests/TEST_AGENTAUTH.md`](tests/TEST_AGENTAUTH.md).

### Test Coverage

The comprehensive test suite provides:

- ✅ **100% Function Coverage** - All 119 functions/classes tested
- ✅ **100% Success Rate** - 151/151 tests passing
- ✅ **Complete Mocking** - All HTTP requests properly mocked to avoid network dependencies
- ✅ **Security Testing** - All security components thoroughly tested
- ✅ **Error Scenarios** - Comprehensive error handling and edge case testing
- ✅ **Integration Testing** - End-to-end authentication flows
- ✅ **Performance Testing** - Timeout, caching, and resource limiting tests

### Test Categories

```bash
# Run core functionality tests only
python -m unittest tests.test_agentauth -v

# Run security component tests only
python -m unittest tests.test_agentauth_security -v

# Run configuration tests only
python -m unittest tests.test_config -v
```

> **Note:** The test suite uses comprehensive mocking to avoid real network requests. All HTTP calls are mocked to ensure reliable, deterministic test execution.

## Error Handling

The library provides comprehensive error handling with the `OAuth2OIDCError` and `SecurityError` exceptions.

### Common Error Scenarios

1. **Authentication Failures**:
   ```python
   try:
       access_token = client.authenticate()
   except OAuth2OIDCError as e:
       print(f"Authentication failed: {e}")
   ```

2. **Token Validation Failures**:
   ```python
   try:
       payload = client.validate_token(token)
   except OAuth2OIDCError as e:
       print(f"Token validation failed: {e}")
   ```

3. **JWKS Retrieval Failures**:
   ```python
   try:
       jwks = client.get_jwks()
   except OAuth2OIDCError as e:
       print(f"JWKS retrieval failed: {e}")
   ```

4. **Security Violations**:
   ```python
   try:
       # Some operation
       pass
   except SecurityError as e:
       print(f"Security violation: {e}")
   ```

## Supported IdPs

This library works with any IdP that implements OAuth2/OIDC standards, including:

- **Google Cloud IAM**
- **Azure Active Directory**
- **AWS Cognito**
- **Auth0**
- **Keycloak**
- **Okta**
- **Ping Identity**
- **Custom IdPs**

## Security Considerations

1. **Token Storage**: Store tokens securely and never log them
2. **Client Secrets**: Keep client secrets secure and rotate regularly
3. **Audience Validation**: Always validate the audience claim
4. **Issuer Validation**: Always validate the issuer claim
5. **Token Expiration**: Handle token expiration gracefully
6. **HTTPS**: Always use HTTPS for all communications

## Performance Optimization

1. **Caching**: The library automatically caches tokens and JWKS
2. **Connection Pooling**: Uses requests session for connection reuse
3. **Timeout Configuration**: Configure appropriate timeouts
4. **JWKS TTL**: Adjust JWKS cache TTL based on your needs

## Logging

The library provides comprehensive logging. Configure logging level as needed:

```python
import logging
logging.basicConfig(level=logging.INFO)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/agentauth/agentauth.git
cd agentauth

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=agentauth --cov-report=html

# Run linting
flake8 agentauth/
black agentauth/
mypy agentauth/
```

## License

This library is licensed under the Apache 2.0 License.

## Support

For issues and questions:
1. Check the documentation
2. Review the examples
3. Open an issue on GitHub

## Changelog

### Version 0.0.1
- Initial release
- OAuth2/OIDC client credentials flow
- JWT token validation
- JWKS support
- Google Cloud IAM example
- Comprehensive error handling 
