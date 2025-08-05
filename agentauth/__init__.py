"""
AgentAuth - OAuth2/OIDC Authentication and JWT Token Validation Library

A comprehensive Python library for OAuth2 and OpenID Connect (OIDC) authentication 
with JWT token validation. This library supports machine-to-machine (M2M) 
authentication and works with any Identity Provider (IdP) that implements 
OAuth2/OIDC standards.
"""

from .core import OAuth2OIDCClient, discover_oidc_config, retrieve_jwks, validate_token_signature, validate_multiple_token_signatures
from .config import ClientConfig, ClientBuilder, SecurityConfig, SecurityBuilder, ErrorConfig, ErrorConfigBuilder
from .security import CryptographicAuthenticator, SecureTokenValidator, SecurityFramework
from .utils import SecurityError, OAuth2OIDCError, generate_secure_nonce, secure_wipe_memory, validate_cryptographic_parameters

__version__ = "0.0.1"
__author__ = "Ron Herardian"
__email__ = "agentauth@aethercloud.net"

__all__ = [
    # Core classes
    'OAuth2OIDCClient',
    'discover_oidc_config',
    'retrieve_jwks',
    'validate_token_signature',
    'validate_multiple_token_signatures',
    
    # Configuration classes
    'ClientConfig',
    'ClientBuilder',
    'SecurityConfig',
    'SecurityBuilder',
    'ErrorConfig',
    'ErrorConfigBuilder',
    
    # Security classes
    'CryptographicAuthenticator',
    'SecureTokenValidator',
    'SecurityFramework',
    
    # Utility functions and exceptions
    'SecurityError',
    'OAuth2OIDCError',
    'generate_secure_nonce',
    'secure_wipe_memory',
    'validate_cryptographic_parameters'
]
