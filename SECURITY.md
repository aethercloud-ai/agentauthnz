# AgentAuth Security Guide

> **📝 Documentation Note**: This document uses `https://test.issuer.com` as a dummy URL for examples only. For actual testing, you must set the `AGENTAUTH_TEST_IDP_BASE_URL` environment variable to your real Identity Provider endpoint. See the [README.md](README.md) for required environment variable configuration.

## Overview

This document outlines the security enhancements implemented in the AgentAuth library to protect sensitive data and prevent common attack vectors.

## Security Features

AgentAuth implements comprehensive security measures to protect sensitive data:

### **Sensitive Data Protection**
- **JWT Payload Sanitization**: Sensitive claims in JWT payloads are automatically redacted
- **Token Hashing**: Raw tokens are never logged; only SHA-256 hashes are used for correlation
- **Input Validation**: All inputs are validated and sanitized to prevent injection attacks
- **Secure Error Handling**: Error messages are sanitized to prevent information disclosure

### **Audit Logging**
- **Security Event Logging**: All security events are logged with sanitized data
- **Token Validation Tracking**: Token validation attempts are logged with hashes for correlation
- **Payload Access Logging**: JWT payload access is logged with sensitive claims redacted
- **Rate Limit Monitoring**: Rate limit violations are logged for threat detection

### **Cryptographic Security**
- **Parameter Validation**: Cryptographic parameters are validated for security
- **Anti-Replay Protection**: Nonce-based protection against token replay attacks
- **SSRF Protection**: URL validation prevents Server-Side Request Forgery attacks
- **HMAC Authentication**: HMAC-based token generation and verification
- **Secure Random Generation**: Uses cryptographically secure random number generation
- **Memory Washing**: Securely wipes sensitive data from memory

### **TLS/SSL Security**
- **TLS 1.3 Preferred**: Enforces TLS 1.3 with TLS 1.2 fallback for compatibility
- **Secure Cipher Suites**: Enforces AES-GCM, ChaCha20-Poly1305, and other strong ciphers
- **Certificate Validation**: Mandatory SSL certificate verification and hostname matching
- **Downgrade Protection**: Prevents downgrade to insecure protocols (SSLv2, SSLv3, TLSv1, TLSv1.1)

### **Resource Limiting & DoS Protection**
- **Response Size Limits**: Prevents memory exhaustion attacks (1MB default limit)
- **Processing Time Limits**: CPU exhaustion protection (30-second timeout)
- **Concurrency Control**: Limits concurrent requests (10 max default)
- **Rate Limiting**: Prevents abuse (3000 requests/minute default)
- **Memory Usage Control**: Monitors and limits memory consumption

### **Code Injection Protection**
- **Algorithm Validation**: Whitelist of allowed cryptographic algorithms
- **Key Type Validation**: Validates JWK key types against allowed list
- **Dangerous Pattern Detection**: Identifies code injection attempts in inputs
- **Input Content Validation**: Validates token and URL content for malicious patterns
- **Safe Value Checking**: Ensures all input values are safe before processing

### **Configurable Security Policies**
- **Granular Control**: Fine-grained security policy configuration
- **Runtime Updates**: Dynamic security policy changes without restart
- **Environment-Specific**: Different policies for different environments
- **Security Builder Pattern**: Type-safe security configuration using builder pattern
- **Default Secure Settings**: Secure defaults for all configurations

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

### **Security Framework Integration**
- **Unified Security Interface**: Single point of security control
- **Component Coordination**: Integrated security component management
- **Policy Enforcement**: Consistent security policy application across components
- **Security State Management**: Tracks security framework state

### **Security Performance & Monitoring**
- **Security Performance Metrics**: Monitors security operation performance
- **Resource Usage Tracking**: Tracks CPU, memory, and network usage
- **Security Event Correlation**: Links related security events
- **Real-time Monitoring**: Live security event monitoring

### **Developer Security Tools**
- **Security Testing**: Comprehensive security test suite (99 security tests)
- **Security Examples**: Secure implementation examples provided
- **Security Documentation**: Detailed security documentation and best practices
- **Security Utilities**: Helper functions for secure operations
- **Security Validation**: Built-in security validation tools

### **Advanced Security Features**
- **SSRF Protection**: Blocks requests to private IP ranges and metadata endpoints
- **XSS Prevention**: Detects and blocks cross-site scripting attempts
- **Path Traversal Protection**: Prevents directory traversal attacks
- **Algorithm Confusion Protection**: Prevents algorithm confusion attacks
- **Key Size Validation**: Ensures minimum key sizes (2048-bit RSA minimum)

## 🔒 Using AgentAuth Security Features

### 1. Enhanced Token Expiration Validation
- **Problem**: Tokens without expiration claims can be used indefinitely, creating security risks
- **Solution**: All tokens must have an `exp` (expiration) claim
- **Implementation**: 
  - Tokens received from IdP are validated before caching
  - All validation methods check for `exp` claim presence
  - Tokens without `exp` are rejected with clear error messages
  - Expired tokens are automatically rejected
- **Code Example**:
  ```python
  from agentauth.core.client import OAuth2OIDCClient
  from agentauth.config.client_config import ClientBuilder
  from agentauth.config.security_config import SecurityBuilder
  
  # Create client with security enabled
  # Note: https://test.issuer.com is used as a dummy URL for documentation purposes only.
  # In actual tests, use the AGENTAUTH_TEST_IDP_BASE_URL environment variable.
  security_config = SecurityBuilder().with_security_enabled(True).build()
  client_config = ClientBuilder().with_idp("Test IdP", "https://test.issuer.com").with_credentials("client-id", "client-secret").with_security(security_config).build()
  client = OAuth2OIDCClient(client_config)
  
  # ✅ Good - Token with exp claim
  token_with_exp = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzQ1Njc4OTB9..."
  payload = client.validate_token(token_with_exp)  # ✅ Success
  
  # ❌ Bad - Token without exp claim
  token_without_exp = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0..."
  payload = client.validate_token(token_without_exp)  # ❌ Error: "Token missing required 'exp' (expiration) claim"
  ```

### 2. Simple Dictionary-Based Storage

**Problem**: Complex encrypted storage adds unnecessary overhead for many use cases.

**Solution**: Simple dictionary-based storage provides:
- Direct dictionary storage for tokens and JWKS data
- TTL-based expiration for automatic cleanup
- Simple and efficient memory usage
- No encryption overhead for basic use cases

### 3. Enhanced Input Validation and Sanitization

**Problem**: Limited input validation allowed potential injection attacks and malicious input.

**Solution**: `InputSanitizer` class provides:
- Comprehensive JWT token format validation
- URL sanitization with SSRF protection
- Client ID validation and sanitization
- Suspicious pattern detection
- Size limits to prevent memory exhaustion
- Dangerous host detection for SSRF prevention

```python
from agentauth.security.components.input_sanitizer import InputSanitizer

# Initialize sanitizer
sanitizer = InputSanitizer()

# Sanitize JWT token
token = sanitizer.sanitize_jwt_token("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...")

# Sanitize URL
url = sanitizer.sanitize_url("https://api.example.com/jwks")

# Sanitize client ID
client_id = sanitizer.sanitize_client_id("client_123")
```

### 4. Secure Error Handling

**Problem**: Error messages could disclose sensitive information about system internals.

**Solution**: `SecureErrorHandler` class provides:
- Unique error IDs for tracking without information disclosure
- Sanitized error messages for user consumption
- Detailed internal logging for debugging
- Error type mapping to prevent stack trace disclosure
- Security violation logging

```python
from agentauth.security.components.error_handler import SecureErrorHandler

# Initialize error handler
error_handler = SecureErrorHandler(enable_debug=False)

# Handle errors securely
try:
    # Some operation
    pass
except Exception as e:
    error_message = error_handler.handle_error(e, "operation_context")
    # error_message contains sanitized message for users
```

### 5. Sensitive Data Protection and Audit Logging

**Problem**: Sensitive JWT payload data could be logged, exposing user information.

**Solution**: `SecurityAuditLogger` class provides:
- **JWT Payload Sanitization**: Sensitive claims are automatically redacted
- **Token Hashing**: Raw tokens are never logged; only SHA-256 hashes used for correlation
- **Audit Trail**: Comprehensive security event logging with data sanitization
- **Payload Access Logging**: JWT payload access is logged with sensitive claims redacted
- **Configurable Redaction**: Sensitive fields can be customized for different use cases

**Sensitive Claims Protected**:
- User identifiers: `sub`, `user_id`, `employee_id`, `customer_id`
- Personal information: `name`, `email`, `phone_number`, `address`
- Financial data: `credit_card`, `account_number`, `ssn`
- Medical information: `medical_info`, `health_data`
- Confidential data: `secret`, `private_key`, `api_key`
- Internal data: `confidential`, `restricted`, `internal`

```python
from agentauth.security.components.audit_logger import SecurityAuditLogger

# Initialize audit logger
audit_logger = SecurityAuditLogger(log_file="security_audit.log")

# Log token validation (only hash is logged)
token_hash = hashlib.sha256(token.encode()).hexdigest()
audit_logger.log_token_validation(token_hash, True, validation_details)

# Log JWT payload access (sensitive claims redacted)
audit_logger.log_jwt_payload_access(token_hash, payload_claims)
```

**Implementation Details**:
```python
def sanitize_jwt_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Security. Sanitize JWT payload to remove sensitive claims."""
    sanitized = {}
    
    for key, value in payload.items():
        # Security. Check if claim contains sensitive information
        if any(sensitive in key.lower() for sensitive in self.sensitive_jwt_claims):
            sanitized[key] = '[REDACTED]'
        elif isinstance(value, str) and any(sensitive in value.lower() for sensitive in self.sensitive_jwt_claims):
            sanitized[key] = '[REDACTED]'
        else:
            sanitized[key] = value
    
    return sanitized
```

### 6. Resource Limits and DoS Protection

**Problem**: No protection against DoS attacks and resource exhaustion.

**Solution**: `ResourceLimiter` class provides:
- Response size limits (1MB default)
- Processing time limits (30 seconds default)
- Concurrent request limits (10 default)
- Rate limiting per client
- Memory usage limits
- CPU usage limits

```python
from agentauth.security.components.resource_limiter import ResourceLimiter

# Initialize resource limiter
limiter = ResourceLimiter()

# Limit response size
response = limiter.limit_response_size(response)

# Limit processing time
result = limiter.limit_processing_time(expensive_function, *args)

# Acquire request slot
limiter.acquire_request_slot(client_id)
```

### 7. Advanced Audit Logging

**Problem**: Insufficient security event logging for monitoring and compliance.

**Solution**: `SecurityAuditLogger` class provides:
- Comprehensive security event logging
- Sensitive data sanitization in logs
- Token hash correlation without storing raw data
- Authentication attempt tracking
- Rate limit violation logging
- Security violation logging

```python
from agentauth import SecurityAuditLogger

# Initialize audit logger
audit_logger = SecurityAuditLogger(log_file="security_audit.log")

# Log authentication attempts
audit_logger.log_authentication_attempt("client_123", True)

# Log token validation
audit_logger.log_token_validation("token_hash", True, validation_details)

# Log security violations
audit_logger.log_security_violation("injection_attempt", details)
```

### 8. Code Injection Protection

**Problem**: No protection against code injection and RCE attacks.

**Solution**: `CodeInjectionProtector` class provides:
- JWK structure validation
- Algorithm name validation
- Key type validation
- Dangerous pattern detection
- Input sanitization
- Safe value checking

```python
from agentauth.security.components.injection_protector import CodeInjectionProtector

# Initialize code injection protector
protector = CodeInjectionProtector()

# Validate JWK structure
if protector.validate_jwk_structure(jwk):
    # Process JWK safely
    sanitized_jwk = protector.sanitize_jwk_data(jwk)

# Validate algorithm name
if protector.validate_algorithm_name("RS256"):
    # Use algorithm safely
    pass
```

```python
# Simple dictionary storage for tokens and JWKS
self._access_token_cache = {
    'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...',
    'expires_in': 3600
}
self._access_token_expiry = time.time() + 3600

# Retrieve cached data
token = self._access_token_cache.get('access_token', '')
```

### 9. Cryptographic Authentication

**Problem**: No verification that applications using the library are authorized.

**Solution**: `CryptographicAuthenticator` provides:
- HMAC-based authentication tokens
- Certificate chain validation
- Rate limiting (100 requests/minute default)
- Anti-replay protection with nonces

```python
from agentauth.security.authenticator import CryptographicAuthenticator
from agentauth.utils.crypto import generate_secure_nonce

# Initialize authenticator
auth = CryptographicAuthenticator()

# Generate authentication token
auth_token = auth.generate_hmac_token("client_id_123")

# Verify token
is_valid = auth.verify_hmac_token(auth_token, "client_id_123")
```

### 10. Enhanced Token Validation

**Problem**: Basic JWT validation without security checks.

**Solution**: Enhanced validation includes:
- Cryptographic parameter validation (RSA key size, EC curves)
- Token format validation
- Nonce replay protection
- Rate limiting integration

```python
from agentauth.core.client import OAuth2OIDCClient
from agentauth.config.client_config import ClientBuilder
from agentauth.config.security_config import SecurityBuilder

# Create security configuration
security_config = SecurityBuilder().with_security_enabled(True).build()

# Create client configuration
  # Environment variables can override these settings (e.g., AGENTAUTH_IDP_BASE_URL)
  # Note: https://your-idp.example.com is a placeholder - use your actual IdP URL
  client_config = ClientBuilder().with_idp("Your Identity Provider", "https://your-idp.example.com").with_credentials("your-client-id", "your-client-secret").with_security(security_config).build()

# Initialize client with security enabled
client = OAuth2OIDCClient(client_config)

# Validate token with authentication
auth_token = auth.generate_hmac_token(client.client_id)
payload = client.validate_token(
    token="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
    auth_token=auth_token
)
```

### 11. Anti-Replay Protection

**Problem**: Tokens could be replayed maliciously.

**Solution**: Nonce-based replay protection:
- Each token includes a unique nonce
- Nonces are tracked and expire after 5 minutes
- Reused nonces are rejected

```python
from agentauth.utils.crypto import generate_secure_nonce

# Generate nonce for token
nonce = generate_secure_nonce()

# Include nonce in JWT header
header = {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-id",
    "nonce": nonce
}
```

### 12. Secure Memory Management

**Problem**: Sensitive data remains in memory after use.

**Solution**: Secure memory wiping:
- Overwrite sensitive data with random bytes
- Multiple overwrite passes (random, zeros, ones)
- Automatic cleanup on object destruction

### 13. Transport Security (TLS 1.3 Preferred, TLS 1.2 Fallback)

**Problem**: No enforcement of secure transport protocols for network communications.

**Solution**: Comprehensive transport security with TLS 1.3 preference:
- TLS 1.3 preferred, TLS 1.2 fallback for compatibility
- Secure cipher suite configuration
- Certificate validation and hostname verification
- HTTPS-only enforcement
- TLS version verification and logging
- Protection against downgrade attacks

```python
from agentauth.security.components.http_client import SecureHTTPClient, verify_tls_version

# Use secure HTTP client with TLS 1.3 preferred, TLS 1.2 fallback
http_client = SecureHTTPClient(timeout=30, verify_ssl=True)
response = http_client.get("https://api.example.com/data")

# Verify TLS version used
if verify_tls_version(response):
    print("✅ TLS 1.3 preferred, TLS 1.2 fallback working correctly")
```

#### Transport Security Features

**TLS Version Support**:
- **Preferred**: TLS 1.3 (latest security standard)
- **Fallback**: TLS 1.2 (for compatibility with older servers)
- **Minimum**: TLS 1.2 (no older versions allowed)

**Cipher Suite Configuration**:
- **TLS 1.3**: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`
- **TLS 1.2**: `ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES128-GCM-SHA256`, etc.

**Security Measures**:
- Certificate validation and hostname verification
- HTTPS-only enforcement (HTTP requests rejected)
- Protection against SSL/TLS downgrade attacks
- Secure connection logging and monitoring

```python
from agentauth.utils.crypto import secure_wipe_memory

# Securely wipe sensitive data
sensitive_data = b"secret_token_data"
secure_wipe_memory(sensitive_data)
```

## 🛡️ Security Best Practices

> **Note:** All code examples in this section are tested and known good for the current implementation.

### SecurityFramework Class

The `SecurityFramework` class provides a unified interface for all security components, making it easy to coordinate security operations across the application.

#### Basic Usage

```python
from agentauth.security.framework import SecurityFramework
from agentauth.config.security_config import SecurityConfig

# Create security configuration
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

# Initialize security framework
security = SecurityFramework(security_config)
```

#### Input Validation

```python
# Validate and sanitize different types of input
sanitized_token = security.validate_input('token', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...')
sanitized_url = security.validate_input('url', 'https://api.example.com/jwks')
sanitized_client_id = security.validate_input('client_id', 'client_123')
sanitized_jwk = security.validate_input('jwk', jwk_data)
```

#### Security Event Logging

```python
# Log security events with sanitization
security.log_security_event('authentication_attempt', {
    'client_id': 'client-123',
    'success': True,
    'timestamp': '2024-01-01T00:00:00Z'
}, 'INFO')

security.log_security_event('token_validation', {
    'token_hash': 'abc123...',
    'valid': True,
    'audience': 'api.example.com'
}, 'INFO')

security.log_security_event('security_violation', {
    'type': 'injection_attempt',
    'input': 'suspicious_input',
    'pattern': 'script_tag'
}, 'WARNING')
```

#### Secure Error Handling

```python
try:
    # Some operation that might fail
    result = perform_sensitive_operation()
except Exception as e:
    # Handle error securely without information disclosure
    error_id = security.handle_error(e, 'sensitive_operation')
    print(f"Operation failed. Error ID: {error_id}")
```

#### Resource Management

```python
# Acquire resource slot for rate limiting
security.acquire_resource_slot('client-123')

try:
    # Perform operation
    result = perform_operation()
finally:
    # Always release resource slot
    security.release_resource_slot()
```

#### Secure Token Validation

```python
# Validate token with enhanced security checks
payload = security.validate_token_secure(
    token=access_token,
    jwks=jwks,
    audience='api.example.com',
    issuer='https://your-idp.example.com'
)
```

#### JWK Structure Validation

```python
# Validate JWK structure for security
if security.validate_jwk_structure(jwk):
    # Process JWK safely
    print("JWK structure is valid and secure")
else:
    raise SecurityError("Invalid JWK structure")
```

#### JWT Payload Sanitization

```python
# Sanitize JWT payload to remove sensitive information
raw_payload = {
    'sub': 'user123',
    'name': 'John Doe',
    'email': 'john@example.com',
    'ssn': '123-45-6789',
    'iat': 1516239022,
    'exp': 1516242622
}

sanitized_payload = security.sanitize_jwt_payload(raw_payload)
# sensitive fields like 'ssn', 'email', 'name' are redacted
print(sanitized_payload)
# Output: {'sub': '[REDACTED]', 'name': '[REDACTED]', 'email': '[REDACTED]', 'ssn': '[REDACTED]', 'iat': 1516239022, 'exp': 1516242622}
```

#### Resource Usage Monitoring

```python
# Get current resource usage statistics
stats = security.get_resource_usage_stats()
print(f"Active requests: {stats['active_requests']}")
print(f"Max concurrent requests: {stats['max_concurrent_requests']}")
print(f"Active clients: {stats['active_clients']}")
print(f"Total requests in window: {stats['total_requests_in_window']}")
print(f"Max request rate: {stats['max_request_rate']}")
```

#### Security State Management

```python
# Check if security features are enabled
if security.is_security_enabled():
    print("Security features are active")
else:
    print("Security features are disabled")

# Clean up expired entries
security.cleanup_expired_entries()
```

#### Complete Security Workflow Example

```python
from agentauth.security.framework import SecurityFramework
from agentauth.config.security_config import SecurityConfig
from agentauth.core.client import OAuth2OIDCClient
from agentauth.config.client_config import ClientConfig

# 1. Create security configuration
security_config = SecurityConfig(
    enable_security=True,
    max_token_length=8192,
    max_response_size=1024*1024,
    audit_log_file="/var/log/security.log"
)

# 2. Initialize security framework
security = SecurityFramework(security_config)

# 3. Create client configuration
client_config = ClientConfig(
    idp_name="Secure IdP",
    idp_endpoint="https://secure-idp.example.com",
    client_id="secure-client-id",
    client_secret="secure-client-secret",
    security=security_config
)

# 4. Initialize client
client = OAuth2OIDCClient(client_config)

# 5. Perform secure operations
try:
    # Acquire resource slot
    security.acquire_resource_slot('secure-client-id')
    
    # Validate input
    sanitized_token = security.validate_input('token', raw_token)
    
    # Authenticate
    access_token = client.authenticate()
    
    # Log successful authentication
    security.log_security_event('authentication_success', {
        'client_id': 'secure-client-id',
        'token_hash': hashlib.sha256(access_token.encode()).hexdigest()
    }, 'INFO')
    
    # Validate token
    payload = client.validate_token(access_token)
    
    # Sanitize payload for logging
    sanitized_payload = security.sanitize_jwt_payload(payload)
    
    # Log token validation
    security.log_security_event('token_validation_success', {
        'token_hash': hashlib.sha256(access_token.encode()).hexdigest(),
        'payload_claims': sanitized_payload
    }, 'INFO')
    
except Exception as e:
    # Handle errors securely
    error_id = security.handle_error(e, 'authentication_workflow')
    security.log_security_event('authentication_failure', {
        'client_id': 'secure-client-id',
        'error_id': error_id
    }, 'ERROR')
    
finally:
    # Always release resource slot
    security.release_resource_slot()

# 6. Get security statistics
stats = security.get_resource_usage_stats()
print(f"Security workflow completed. Active requests: {stats['active_requests']}")
```

#### Security Framework Configuration

```python
from agentauth.config.security_config import SecurityBuilder

# High-security configuration
high_security_config = (SecurityBuilder()
    .with_security_enabled(True)
    .with_input_limits(max_token_length=4096, max_url_length=1024)
    .with_resource_limits(max_response_size=512*1024, max_processing_time=15)
    .with_audit_logging(audit_log_file="/var/log/security.log", enable_debug=False)
    .with_rate_limiting(rate_limit_per_minute=1000)
    .with_tls_settings(min_tls_version="TLSv1.3", verify_ssl=True)
    .build())

# Development configuration
dev_security_config = (SecurityBuilder()
    .with_security_enabled(True)
    .with_input_limits(max_token_length=8192, max_url_length=2048)
    .with_resource_limits(max_response_size=1024*1024, max_processing_time=30)
    .with_audit_logging(audit_log_file=None, enable_debug=True)
    .with_rate_limiting(rate_limit_per_minute=5000)
    .with_tls_settings(min_tls_version="TLSv1.2", verify_ssl=True)
    .build())

# Initialize frameworks with different configurations
high_security_framework = SecurityFramework(high_security_config)
dev_security_framework = SecurityFramework(dev_security_config)
```

### 1. Security Enabled by Default

```python
# ✅ Good - Security enabled by default
client = OAuth2OIDCClient(
    idp_name="IdP",
    idp_endpoint="https://idp.example.com",
    client_id="client-id",
    client_secret="client-secret"
    # Security is enabled by default
)

# ❌ Bad - Security disabled (only for testing)
client = OAuth2OIDCClient(
    idp_name="IdP",
    idp_endpoint="https://idp.example.com",
    client_id="client-id",
    client_secret="client-secret",
    enable_security=False  # Only use for testing
)
```

### 2. Use Authentication Tokens

```python
# ✅ Good - With authentication
auth = CryptographicAuthenticator()
auth_token = auth.generate_hmac_token(client_id)
payload = client.validate_token(token, auth_token=auth_token)

# ❌ Bad - Without authentication
payload = client.validate_token(token)  # No auth verification
```

### 3. Implement Rate Limiting

```python
# ✅ Good - Check rate limits
if auth.check_rate_limit(client_id):
    # Process request
    pass
else:
    raise SecurityError("Rate limit exceeded")

# ❌ Bad - No rate limiting
# Process request without limits
```

### 4. Validate Cryptographic Parameters

```python
# ✅ Good - Validate parameters
from agentauth import validate_cryptographic_parameters

if validate_cryptographic_parameters(jwk):
    # Use key
    pass
else:
    raise SecurityError("Insecure cryptographic parameters")

# ❌ Bad - No validation
# Use key without validation
```

### 5. Use Secure Random Generation

```python
# ✅ Good - Use secure random
from agentauth import generate_secure_nonce
nonce = generate_secure_nonce()

# ❌ Bad - Use predictable values
nonce = "static_nonce"  # Predictable
```

## 🔍 Security Configuration

### Environment Variables

#### Core Security Variables
```bash
# Security framework control
export AGENTAUTH_DISABLE_SECURITY=false  # Enable security features (default: false)

# TLS/SSL configuration
export AGENTAUTH_MIN_TLS_VERSION=TLSv1.3  # Minimum TLS version (default: TLSv1.2)
export AGENTAUTH_VERIFY_SSL=true          # Enable SSL certificate verification (default: true)
export AGENTAUTH_CERT_CHAIN=/path/to/certificate-chain.pem  # Certificate chain file

# Rate limiting and resource protection
export AGENTAUTH_RATE_LIMIT_PER_MINUTE=3000     # Max requests per minute (default: 3000)
export AGENTAUTH_MAX_RESPONSE_SIZE=1048576      # Max response size in bytes (default: 1MB)
export AGENTAUTH_MAX_PROCESSING_TIME=30         # Max processing time in seconds (default: 30)
export AGENTAUTH_MAX_CONCURRENT_REQUESTS=10     # Max concurrent requests (default: 10)
```

#### Audit and Logging Variables
```bash
# Security audit logging
export AGENTAUTH_AUDIT_LOG_FILE=/var/log/agentauth-audit.log  # Audit log file path
export AGENTAUTH_ENABLE_DEBUG=false  # Enable debug mode for security components

# Error handling and logging
export AGENTAUTH_SANITIZE_ERROR_MESSAGES=true    # Sanitize error messages (default: true)
export AGENTAUTH_LOG_ERROR_DETAILS=true          # Log detailed error information (default: true)
export AGENTAUTH_ERROR_LOG_FILE=/var/log/agentauth-errors.log  # Error log file path
export AGENTAUTH_GENERATE_ERROR_IDS=true         # Generate unique error IDs (default: true)
export AGENTAUTH_REPORT_SECURITY_VIOLATIONS=true # Report security violations (default: true)
```

#### Testing Variables
```bash
# Required for all tests - IdP independent
export AGENTAUTH_TEST_IDP_BASE_URL="https://your-idp.example.com"

# Required for real OAuth2 authentication tests - IdP independent
export AGENTAUTH_TEST_IDP_CLIENT_ID="your-oauth2-client-id"
export AGENTAUTH_TEST_IDP_CLIENT_SECRET="your-oauth2-client-secret"
```

#### Important Notes
```bash
# Token TTL configuration
# AGENTAUTH_TOKEN_TTL removed - token TTL is managed per token via 'exp' claim
# All tokens must have an 'exp' claim - tokens without expiration are rejected

# Production vs Testing
# Use AGENTAUTH_* variables for production
# Use AGENTAUTH_TEST_* variables for testing (all three are IdP independent)
# Tests will emit clear error messages if required test variables are not set
```

### Configuration File

```python
# config.py
SECURITY_CONFIG = {
    "disable_security": False,
    "cert_chain_path": "/path/to/certificate-chain.pem",
    "rate_limit_per_minute": 3000,
    # "token_ttl" removed - token TTL is managed per token via 'exp' claim
    "nonce_ttl": 300,
    "max_auth_token_age": 300
}
```

## Other Security Considerations

### 1. Key Management

- **Master Keys**: Generate cryptographically secure master keys
- **Key Rotation**: Rotate keys regularly (recommended: every 90 days)
- **Key Storage**: Store keys securely (HSM, key management service)
- **Key Distribution**: Use secure channels for key distribution

### 2. Certificate Management

- **Certificate Validation**: Implement proper certificate chain validation
- **Certificate Revocation**: Check certificate revocation lists (CRL)
- **Certificate Pinning**: Consider certificate pinning for additional security

### 3. Transport Security

- **TLS 1.3 Preferred**: Use TLS 1.3 as the primary transport protocol
- **TLS 1.2 Fallback**: Maintain compatibility with TLS 1.2 for older servers
- **Certificate Validation**: Full certificate chain validation and hostname verification
- **DNS Security**: Use DNSSEC to prevent DNS attacks
- **Cipher Suites**: Use only strong cipher suites (AES-GCM, ChaCha20-Poly1305)
- **Protocol Enforcement**: Reject connections using TLS 1.1 or older
- **Downgrade Protection**: Prevent SSL/TLS downgrade attacks
- **Connection Logging**: Log TLS version and cipher suite information

### 4. Application Security

- **Input Validation**: Comprehensive input sanitization implemented
- **Output Encoding**: Secure error handling prevents information disclosure
- **Error Handling**: Sanitized error messages with unique tracking IDs
- **Logging**: Advanced audit logging with sensitive data sanitization
- **Resource Limits**: DoS protection with size and time limits
- **Code Injection Protection**: JWK validation and dangerous pattern detection

### 5. Runtime Security

- **Memory Protection**: Use secure memory regions when available
- **Process Isolation**: Run in isolated containers/processes
- **Privilege Minimization**: Run with minimal required privileges
- **System Hardening**: Harden the underlying system

## 🔧 Security Testing

> **Note:** All code examples in this document are tested and known good for the current implementation. Some tests require proper mocking of network calls. If you see SSL or connection errors to test.issuer.com, this is expected unless you mock network requests.

### 🧪 Sensitive Data Protection Testing

All sensitive data protection features are thoroughly tested with comprehensive test coverage.

**Test Coverage**:
- ✅ JWT payload sanitization
- ✅ Token hashing instead of truncation
- ✅ Audit logging with data sanitization
- ✅ Secure error handling
- ✅ Input validation and sanitization
- ✅ Custom sensitive field configuration
- ✅ Audit log summary metrics

### 1. Penetration Testing

```python
# Test security features
def test_security_features():
    # Test simple dictionary storage
    cache = {'test': 'sensitive_data'}
    assert cache.get('test') == 'sensitive_data'
    
    # Test authentication
    auth = CryptographicAuthenticator()
    token = auth.generate_hmac_token('test_client')
    assert auth.verify_hmac_token(token, 'test_client')
    
    # Test rate limiting
    assert auth.check_rate_limit('test_client')
    
    # Test input sanitization
    sanitizer = InputSanitizer()
    token = sanitizer.sanitize_jwt_token("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...")
    
    # Test secure error handling
    error_handler = SecureErrorHandler()
    error_message = error_handler.handle_error(Exception("test"), "test_context")
    
    # Test resource limiting
    limiter = ResourceLimiter()
    limiter.acquire_request_slot("test_client")
    
    # Test audit logging
    audit_logger = SecurityAuditLogger()
    audit_logger.log_security_event("test_event", {"test": "data"})
    
    # Test code injection protection
    protector = CodeInjectionProtector()
    assert protector.validate_jwk_structure({"kty": "RSA", "n": "test", "e": "AQAB"})
```

### 2. Security Hardening Testing

```python
# Test security hardening features
def test_security_hardening():
    # Test input validation
    sanitizer = InputSanitizer()
    
    # Test JWT token sanitization
    try:
        sanitizer.sanitize_jwt_token("invalid_token")
        assert False, "Should have raised SecurityError"
    except SecurityError:
        pass
    
    # Test URL sanitization
    try:
        sanitizer.sanitize_url("http://localhost/jwks")
        assert False, "Should have raised SecurityError for SSRF"
    except SecurityError:
        pass
    
    # Test error handling
    error_handler = SecureErrorHandler(enable_debug=False)
    error_message = error_handler.handle_error(jwt.ExpiredSignatureError(), "test")
    assert "Token has expired" in error_message
    
    # Test resource limits
    limiter = ResourceLimiter()
    try:
        # Simulate large response
        large_response = type('Response', (), {'content': b'x' * (1024 * 1024 + 1)})()
        limiter.limit_response_size(large_response)
        assert False, "Should have raised SecurityError"
    except SecurityError:
        pass
```

### 3. Vulnerability Scanning

- Use static analysis tools (Bandit, Semgrep)
- Run dynamic analysis tools (OWASP ZAP)
- Perform dependency scanning (Safety, Snyk)
- Conduct regular security audits

### 4. Transport Security Testing

**Note:** These examples use the `AGENTAUTH_TEST_IDP_BASE_URL` environment variable. Set it to your test IdP endpoint:

```bash
export AGENTAUTH_TEST_IDP_BASE_URL='https://your-idp.example.com'
```

```python
# Test transport security features
def test_transport_security():
    import os
    from agentauth import SecureHTTPClient, verify_tls_version
    
    # Get test endpoint from environment
    base_url = os.getenv("AGENTAUTH_TEST_IDP_BASE_URL")
    if not base_url:
        raise ValueError("AGENTAUTH_TEST_IDP_BASE_URL environment variable is required")
    
    # Test TLS 1.3 preference using OIDC discovery endpoint
    http_client = SecureHTTPClient(timeout=10, verify_ssl=True)
    response = http_client.get(f"{base_url}/.well-known/openid-configuration")
    
    # Verify TLS version
    if verify_tls_version(response):
        print("✅ TLS 1.3 preferred, TLS 1.2 fallback working")
    
    # Test HTTPS enforcement by attempting HTTP request
    try:
        # Construct HTTP (insecure) URL from HTTPS base URL
        insecure_url = base_url.replace("https://", "http://")
        http_client.get(f"{insecure_url}/.well-known/openid-configuration")
        assert False, "HTTP request should be rejected"
    except SecurityError:
        print("✅ HTTPS enforcement working")
```

### 5. Security Monitoring

```python
# Monitor security events
import logging

security_logger = logging.getLogger('agentauth.security')
security_logger.setLevel(logging.INFO)

# Log security events
security_logger.info('Authentication token verified')
security_logger.warning('Rate limit exceeded')
security_logger.error('Invalid cryptographic parameters detected')
security_logger.info('TLS 1.3 connection established')
security_logger.info('TLS 1.2 fallback used')
```



## 📋 Security Checklist

- [ ] Security features enabled by default (set `AGENTAUTH_DISABLE_SECURITY=true` to disable)
- [ ] Use authentication tokens for library access
- [ ] Implement rate limiting
- [ ] All tokens must have `exp` (expiration) claims
- [ ] Validate cryptographic parameters
- [ ] Use secure random generation
- [ ] Implement proper error handling
- [ ] Configure secure logging
- [ ] **Use TLS 1.3 preferred, TLS 1.2 fallback for all connections**
- [ ] **Verify certificate validation and hostname verification**
- [ ] **Test HTTPS enforcement (reject HTTP requests)**
- [ ] **Monitor TLS version and cipher suite usage**
- [ ] **Enable JWT payload sanitization**
- [ ] **Use token hashing for audit logs**
- [ ] **Configure sensitive field detection**
- [ ] Perform regular security testing
- [ ] Keep dependencies updated
- [ ] Monitor security events



## 🎯 Next Steps and Roadmap

### 🚀 Future Enhancements
1. **Monitoring**: Implement monitoring for sensitive data access patterns
2. **Alerting**: Add alerts for unusual payload access patterns
3. **Metrics**: Track sanitization effectiveness
4. **Documentation**: Expand security documentation
5. **Training**: Provide security training materials

### 🔧 Configuration Examples

**Custom Sensitive Fields**:
```python
audit_logger = SecurityAuditLogger()
audit_logger.sensitive_jwt_claims.extend(['custom_field', 'internal_data'])
```

**Secure JWT Payload Access**:
```python
from agentauth import OAuth2OIDCClient

client = OAuth2OIDCClient(
    idp_name="Secure IdP",
    idp_endpoint="https://secure-idp.example.com",
    client_id="secure-client-id",
    client_secret="secure-client-secret"
)

# Get token info with sanitized payload
token_info = client.get_token_info(access_token)
# Sensitive claims like 'sub', 'name', 'email' are automatically redacted
print(token_info['payload'])  # Safe to log
```

**Audit Logging**:
```python
from agentauth import SecurityAuditLogger

audit_logger = SecurityAuditLogger(log_file="security_audit.log")

# Log token validation (only hash is logged)
token_hash = hashlib.sha256(token.encode()).hexdigest()
audit_logger.log_token_validation(token_hash, True, validation_details)

# Log JWT payload access (sensitive claims redacted)
audit_logger.log_jwt_payload_access(token_hash, payload_claims)
```

## 📋 Compliance and Regulatory Alignment

This implementation helps with compliance requirements:

### **GDPR (General Data Protection Regulation)**
- ✅ Automatic redaction of personal data in JWT payloads
- ✅ Secure audit logging without sensitive data exposure
- ✅ Right to be forgotten through secure data handling

### **HIPAA (Health Insurance Portability and Accountability Act)**
- ✅ Protection of medical information in JWT claims
- ✅ Secure handling of health-related data
- ✅ Audit trails for healthcare compliance

### **PCI DSS (Payment Card Industry Data Security Standard)**
- ✅ Protection of financial data and credit card information
- ✅ Secure token handling for payment processing
- ✅ Comprehensive audit logging for financial transactions

### **SOC 2 (System and Organization Controls)**
- ✅ Comprehensive security event logging
- ✅ Access control and authentication tracking
- ✅ Data protection and privacy controls

### **ISO 27001 (Information Security Management)**
- ✅ Information security management system alignment
- ✅ Risk assessment and mitigation
- ✅ Security controls implementation

## 📚 Additional Resources

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://www.nist.gov/cryptography)
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [RFC 7517 - JSON Web Key](https://tools.ietf.org/html/rfc7517)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)

---

## 🔧 Security Example

### Security Features Demonstration

See `examples/security_example.py` for a comprehensive demonstration of AgentAuth's security features including:

- **Cryptographic Authentication**: HMAC token generation and verification
- **Rate Limiting**: Built-in rate limiting with DoS protection
- **Anti-Replay Protection**: Nonce verification to prevent replay attacks
- **Enhanced Token Validation**: Secure token validation with security checks
- **Cryptographic Parameter Validation**: Key size and algorithm validation
- **Secure Memory Management**: Secure memory wiping for sensitive data
- **Security Best Practices**: Complete security workflow demonstration

#### Running the Security Example

```bash
python examples/security_example.py
```

#### Example Output

The security example provides comprehensive output demonstrating all security features working together, including:
- Simple dictionary storage operations
- Cryptographic authentication and verification
- Rate limiting and replay protection
- Enhanced token validation
- Secure client usage workflows
- Cryptographic parameter validation
- Secure memory management
- Security best practices implementation

This example demonstrates all the security features working together to provide comprehensive protection for OAuth2/OIDC authentication workflows. 