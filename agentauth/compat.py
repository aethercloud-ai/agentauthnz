"""
Backward compatibility module for AgentAuth.

This module provides backward compatibility with the old API structure.
"""

import warnings
from typing import Optional, Dict, List

# Import new structure
from .core import OAuth2OIDCClient
from .config import ClientConfig, SecurityConfig
from .utils.exceptions import SecurityError, OAuth2OIDCError
from .security import (
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
from .utils import (
    generate_secure_nonce,
    secure_wipe_memory,
    validate_cryptographic_parameters
)


def create_client(
    idp_name: str,
    idp_endpoint: str,
    client_id: str,
    client_secret: str,
    scope: Optional[str] = None,
    timeout: int = 30,
    jwks_cache_ttl: int = 3600,
    enable_security: Optional[bool] = None,
    cert_chain: Optional[str] = None
) -> OAuth2OIDCClient:
    """
    Create an OAuth2OIDCClient instance with backward compatibility.
    
    This function maintains backward compatibility with the old API
    while using the new modular structure internally.
    
    Args:
        idp_name: Name of the Identity Provider
        idp_endpoint: Base URL of the IdP
        client_id: OAuth2 client ID
        client_secret: OAuth2 client secret
        scope: OAuth2 scope(s) (optional)
        timeout: HTTP request timeout in seconds
        jwks_cache_ttl: JWKS cache TTL in seconds
        enable_security: Enable enhanced security features
        cert_chain: Path to certificate chain for authentication
        
    Returns:
        OAuth2OIDCClient instance
        
    Deprecated:
        This function is deprecated. Use the new builder pattern instead:
        
        ```python
        from agentauth import ClientBuilder, SecurityBuilder
        
        config = (ClientBuilder()
                 .with_idp("Google Cloud IAM", "https://accounts.google.com")
                 .with_credentials("client_id", "client_secret")
                 .with_security(SecurityBuilder().build())
                 .build())
        
        client = OAuth2OIDCClient(config)
        ```
    """
    warnings.warn(
        "create_client() is deprecated. Use the new builder pattern instead.",
        DeprecationWarning,
        stacklevel=2
    )
    
    # Create security config
    security_config = SecurityConfig()
    if enable_security is not None:
        security_config.enable_security = enable_security
    
    # Create client config
    config = ClientConfig(
        idp_name=idp_name,
        idp_endpoint=idp_endpoint,
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
        timeout=timeout,
        jwks_cache_ttl=jwks_cache_ttl,
        cert_chain=cert_chain,
        security=security_config
    )
    
    return OAuth2OIDCClient(config)


# Legacy imports for backward compatibility
__all__ = [
    "OAuth2OIDCClient",
    "create_client",
    "SecurityError",
    "OAuth2OIDCError",
    "CryptographicAuthenticator",
    "SecureTokenValidator",
    "InputSanitizer",
    "SecurityAuditLogger",
    "ResourceLimiter",
    "CodeInjectionProtector",
    "SecureErrorHandler",
    "SecureHTTPClient",
    "SecureHTTPAdapter",
    "create_secure_session",
    "verify_tls_version",
    "generate_secure_nonce",
    "secure_wipe_memory",
    "validate_cryptographic_parameters"
] 