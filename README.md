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

### From PyPI (Recommended)

```bash
pip install agentauth
```

### From Source

```bash
git clone https://github.com/your-username/agentauth.git
cd agentauth
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/your-username/agentauth.git
cd agentauth
pip install -e ".[dev]"
```

## Quick Start

### Basic Usage

```python
from agentauth import OAuth2OIDCClient

# Initialize client (security enabled by default)
client = OAuth2OIDCClient(
    idp_name="Google Cloud IAM",
    idp_endpoint="https://accounts.google.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    scope="https://www.googleapis.com/auth/cloud-platform"
    # Security is enabled by default - set AGENTAUTH_DISABLE_SECURITY=true to disable
)

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
from agentauth import SecurityBuilder

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
```

## API Reference

### OAuth2OIDCClient Class

The main class for OAuth2/OIDC operations.

#### Constructor

```python
OAuth2OIDCClient(
    idp_name: str,
    idp_endpoint: str,
    client_id: str,
    client_secret: str,
    scope: Optional[str] = None,
    timeout: int = 30,
    jwks_cache_ttl: int = 3600,
    enable_security: Optional[bool] = None,
    cert_chain: Optional[str] = None
)
```

**Parameters:**
- `idp_name`: Name of the Identity Provider
- `idp_endpoint`: Base URL of the IdP
- `client_id`: OAuth2 client ID
- `client_secret`: OAuth2 client secret
- `scope`: OAuth2 scope(s) (optional)
- `timeout`: HTTP request timeout in seconds
- `jwks_cache_ttl`: JWKS cache TTL in seconds
- `enable_security`: Enable security features (defaults to True unless AGENTAUTH_DISABLE_SECURITY is set)
- `cert_chain`: Path to certificate chain for authentication

#### Methods

##### authenticate(force_refresh: bool = False) -> str

Authenticate using OAuth2 client credentials flow and return access token.

**Parameters:**
- `force_refresh`: Force token refresh even if cached token is still valid

**Returns:**
- Access token string

**Example:**
```python
# Get access token
access_token = client.authenticate()

# Force refresh
access_token = client.authenticate(force_refresh=True)
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

##### validate_token(token: str, token_type: str = 'access_token', audience: Optional[str] = None, issuer: Optional[str] = None) -> Dict

Validate a JWT token and return its payload.

**Parameters:**
- `token`: JWT token string
- `token_type`: Type of token ('access_token', 'id_token', etc.)
- `audience`: Expected audience (aud) claim
- `issuer`: Expected issuer (iss) claim

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
from agentauth import discover_oidc_config

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
from agentauth import retrieve_jwks

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
from agentauth import validate_token_signature

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
from agentauth import validate_multiple_token_signatures

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

### SecurityFramework Class

The unified security framework that coordinates all security components.

#### Constructor

```python
SecurityFramework(config: SecurityConfig)
```

**Parameters:**
- `config`: Security configuration object

#### Methods

##### validate_input(input_type: str, value: str) -> str

Validate and sanitize input based on type.

**Parameters:**
- `input_type`: Type of input ('token', 'url', 'client_id', 'jwk')
- `value`: Input value to validate

**Returns:**
- Sanitized input value

**Example:**
```python
from agentauth import SecurityFramework, SecurityConfig

security = SecurityFramework(SecurityConfig())
sanitized_token = security.validate_input('token', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...')
```

##### log_security_event(event_type: str, details: dict, severity: str = 'INFO')

Log a security event with sanitization.

**Parameters:**
- `event_type`: Type of security event
- `details`: Event details
- `severity`: Severity level

**Example:**
```python
security.log_security_event('authentication_attempt', {
    'client_id': 'client-123',
    'success': True
}, 'INFO')
```

##### handle_error(error: Exception, context: str = None) -> str

Handle errors securely without information disclosure.

**Parameters:**
- `error`: Exception to handle
- `context`: Additional context for logging

**Returns:**
- Error ID string for tracking

**Example:**
```python
try:
    # Some operation
    pass
except Exception as e:
    error_id = security.handle_error(e, 'authentication')
```

##### validate_token_secure(token: str, jwks: dict, **kwargs) -> dict

Validate token with enhanced security checks.

**Parameters:**
- `token`: JWT token to validate
- `jwks`: JWKS dictionary
- `**kwargs`: Additional validation parameters

**Returns:**
- Token payload

**Example:**
```python
payload = security.validate_token_secure(
    token=access_token,
    jwks=jwks,
    audience="your-client-id",
    issuer="https://accounts.google.com"
)
```

##### get_resource_usage_stats() -> dict

Get resource usage statistics.

**Returns:**
- Resource usage statistics

**Example:**
```python
stats = security.get_resource_usage_stats()
print(f"Active requests: {stats['active_requests']}")
print(f"Rate limit status: {stats['rate_limit_status']}")
```

> **📖 For detailed security framework information, see [SECURITY.md](SECURITY.md)**

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

- ✅ **100% Function Coverage** - All 67 functions/classes tested
- ✅ **100% Success Rate** - 140/140 tests passing
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

The library provides comprehensive error handling with the `OAuth2OIDCError` exception.

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
git clone https://github.com/your-username/agentauth.git
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

### Version 1.0.0
- Initial release
- OAuth2/OIDC client credentials flow
- JWT token validation
- JWKS support
- Google Cloud IAM example
- Comprehensive error handling 
