"""
Cryptographic utilities for AgentAuth.

This module provides cryptographic utility functions for secure operations.
"""

import secrets
import hashlib
import hmac
import time
import logging
from typing import Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import jwt

logger = logging.getLogger(__name__)


def generate_secure_nonce() -> str:
    """
    Generate a secure nonce for anti-replay protection.
    
    Returns:
        Secure random nonce string
    """
    return secrets.token_urlsafe(32)


def secure_wipe_memory(data: bytes) -> None:
    """
    Securely wipe sensitive data from memory.
    
    Args:
        data: Data to wipe from memory
    """
    try:
        # Overwrite with random data
        for i in range(len(data)):
            data[i] = secrets.token_bytes(1)[0]
        
        # Overwrite with zeros
        for i in range(len(data)):
            data[i] = 0
            
    except Exception as e:
        logger.warning(f"Failed to wipe memory: {e}")


def validate_cryptographic_parameters(jwk: Dict) -> bool:
    """
    Validate cryptographic parameters in JWK.
    
    Args:
        jwk: JWK dictionary to validate
        
    Returns:
        True if parameters are valid and secure
    """
    try:
        # Check for required fields
        required_fields = ['kty']
        for field in required_fields:
            if field not in jwk:
                logger.warning(f"Missing required JWK field: {field}")
                return False
        
        # Validate key type
        kty = jwk.get('kty')
        allowed_key_types = {'RSA', 'EC', 'Dilithium', 'Falcon', 'SPHINCS+'}
        if kty not in allowed_key_types:
            logger.warning(f"Unsupported key type: {kty}")
            return False
        
        # Validate algorithm if present
        alg = jwk.get('alg')
        if alg:
            allowed_algorithms = {
                'RS256', 'ES256', 'ES384', 'ES512',
                'Dilithium2', 'Dilithium3', 'Dilithium5',
                'Falcon512', 'Falcon1024',
                'SPHINCS+-SHA256-128f-robust'
            }
            if alg not in allowed_algorithms:
                logger.warning(f"Unsupported algorithm: {alg}")
                return False
        
        # Validate field types and content
        for key, value in jwk.items():
            if not _is_safe_crypto_value(value):
                logger.warning(f"Dangerous value in JWK field: {key}")
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error validating cryptographic parameters: {e}")
        return False


def _is_safe_crypto_value(value: Any) -> bool:
    """
    Check if a value is safe for cryptographic operations.
    
    Args:
        value: Value to check
        
    Returns:
        True if value is safe
    """
    if isinstance(value, str):
        # Check for dangerous patterns
        dangerous_patterns = [
            r'<script', r'javascript:', r'data:', r'vbscript:',
            r'<iframe', r'<object', r'<embed', r'<form',
            r'../', r'..\\', r'%00', r'%0d', r'%0a',
            r'eval\(', r'exec\(', r'compile\(', r'__import__',
            r'os\.', r'sys\.', r'subprocess\.', r'import\s+',
            r'from\s+.*\s+import', r'globals\(\)', r'locals\('
        ]
        
        import re
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return False
        
        return True
    
    elif isinstance(value, (int, float, bool)):
        return True
    
    elif isinstance(value, dict):
        return all(_is_safe_crypto_value(v) for v in value.values())
    
    elif isinstance(value, list):
        return all(_is_safe_crypto_value(v) for v in value)
    
    else:
        return False 