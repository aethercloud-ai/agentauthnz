"""
Core module for AgentAuth.

This module provides the main OAuth2/OIDC client and utility functions.
"""

from .client import OAuth2OIDCClient
from .discovery import discover_oidc_config, retrieve_jwks
from .validation import validate_token_signature, validate_multiple_token_signatures, _convert_jwk_to_pem_standalone

__all__ = [
    'OAuth2OIDCClient',
    'discover_oidc_config',
    'retrieve_jwks',
    'validate_token_signature',
    'validate_multiple_token_signatures',
    '_convert_jwk_to_pem_standalone'
]
