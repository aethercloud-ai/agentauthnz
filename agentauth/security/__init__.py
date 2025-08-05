"""
Security module for AgentAuth.

This module provides security components and framework for authentication and validation.
"""

import os

from .authenticator import CryptographicAuthenticator, SecureTokenValidator
from .framework import SecurityFramework

# Environment variable for disabling security features
AGENTAUTH_DISABLE_SECURITY = os.getenv("AGENTAUTH_DISABLE_SECURITY", "false").lower() == "true"

__all__ = [
    'CryptographicAuthenticator',
    'SecureTokenValidator',
    'SecurityFramework',
    'AGENTAUTH_DISABLE_SECURITY'
]
