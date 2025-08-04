"""
Security framework for AgentAuth.

This module provides the unified security framework and all security components.
"""

from .framework import SecurityFramework
from .authenticator import CryptographicAuthenticator, SecureTokenValidator
from .components.input_sanitizer import InputSanitizer
from .components.audit_logger import SecurityAuditLogger
from .components.resource_limiter import ResourceLimiter
from .components.injection_protector import CodeInjectionProtector
from .components.error_handler import SecureErrorHandler
from .components.http_client import SecureHTTPClient, SecureHTTPAdapter, create_secure_session, verify_tls_version
from ..utils.crypto import generate_secure_nonce, secure_wipe_memory, validate_cryptographic_parameters

# Environment variable for backward compatibility
import os
AGENTAUTH_DISABLE_SECURITY = os.getenv("AGENTAUTH_DISABLE_SECURITY", "false").lower() == "true"

__all__ = [
    "SecurityFramework",
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
    "validate_cryptographic_parameters",
    "AGENTAUTH_DISABLE_SECURITY"
] 