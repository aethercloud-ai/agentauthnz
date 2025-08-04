"""
AgentAuth - OAuth2/OIDC Authentication and JWT Token Validation Library

A comprehensive Python library for OAuth2 and OpenID Connect (OIDC) authentication
with JWT token validation. This library supports machine-to-machine (M2M) 
authentication and works with any Identity Provider (IdP) that implements 
OAuth2/OIDC standards.

Features:
- OAuth2/OIDC client credentials flow for M2M authentication
- JWT token validation with JWKS (JSON Web Key Set) support
- Automatic JWKS discovery and caching
- Support for any IdP that implements OAuth2/OIDC standards
- Comprehensive error handling and logging
- Enhanced security framework with multiple protection layers

Author: AI Assistant
License: Apache 2.0
Version: 1.0.0
"""

# Core functionality
from .core import (
    OAuth2OIDCClient,
    discover_oidc_config,
    retrieve_jwks,
    validate_token_signature,
    validate_multiple_token_signatures,
    _convert_jwk_to_pem_standalone
)

# Configuration classes
from .config import (
    ClientConfig,
    SecurityConfig,
    ErrorConfig,
    ClientBuilder,
    SecurityBuilder,
    ErrorConfigBuilder
)

# Security framework
from .security import (
    SecurityFramework,
    CryptographicAuthenticator,
    SecureTokenValidator,
    InputSanitizer,
    SecurityAuditLogger,
    ResourceLimiter,
    CodeInjectionProtector,
    SecureErrorHandler,
    SecureHTTPClient,
    SecureHTTPAdapter,
    create_secure_session,
    verify_tls_version
)

# Utilities
from .utils import (
    SecurityError,
    OAuth2OIDCError,
    generate_secure_nonce,
    secure_wipe_memory,
    validate_cryptographic_parameters
)

__version__ = "1.0.0"
__author__ = "AI Assistant"
__license__ = "Apache 2.0"

__all__ = [
    # Core functionality
    "OAuth2OIDCClient",
    "discover_oidc_config",
    "retrieve_jwks",
    "validate_token_signature",
    "validate_multiple_token_signatures",
    "_convert_jwk_to_pem_standalone",
    
    # Configuration
    "ClientConfig",
    "SecurityConfig", 
    "ErrorConfig",
    "ClientBuilder",
    "SecurityBuilder",
    "ErrorConfigBuilder",
    
    # Security framework
    "SecurityFramework",
    "CryptographicAuthenticator",
    "SecureTokenValidator",
    "SecurityError",
    "InputSanitizer",
    "SecurityAuditLogger",
    "ResourceLimiter",
    "CodeInjectionProtector",
    "SecureErrorHandler",
    "SecureHTTPClient",
    "SecureHTTPAdapter",
    "create_secure_session",
    "verify_tls_version",
    
    # Utilities
    "OAuth2OIDCError",
    "generate_secure_nonce",
    "secure_wipe_memory",
    "validate_cryptographic_parameters"
] 