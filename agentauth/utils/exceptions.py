"""
Security exceptions for AgentAuth.

This module contains security-related exceptions to avoid circular imports.
"""


class SecurityError(Exception):
    """Security-related exception."""
    pass


class OAuth2OIDCError(Exception):
    """OAuth2/OIDC related exception."""
    pass 