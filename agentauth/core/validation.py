"""
Token validation functions for AgentAuth.

This module provides functions for validating JWT tokens and converting JWK to PEM format.
"""

import time
import base64
import logging
from typing import Dict, List, Optional
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from ..utils.exceptions import OAuth2OIDCError

logger = logging.getLogger(__name__)


def _convert_jwk_to_pem_standalone(jwk: Dict) -> str:
    """
    Convert JWK (JSON Web Key) to PEM format - standalone version.
    
    Args:
        jwk: JWK dictionary
        
    Returns:
        PEM-formatted public key string
        
    Raises:
        OAuth2OIDCError: If key type is unsupported
    """
    kty = jwk.get('kty')
    
    if kty == 'RSA':
        # Handle RSA keys
        n = int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + '=='), 'big')
        e = int.from_bytes(base64.urlsafe_b64decode(jwk['e'] + '=='), 'big')
        
        numbers = RSAPublicNumbers(e, n)
        public_key = numbers.public_key(backend=default_backend())
        
    elif kty == 'EC':
        # Handle EC keys
        x = int.from_bytes(base64.urlsafe_b64decode(jwk['x'] + '=='), 'big')
        y = int.from_bytes(base64.urlsafe_b64decode(jwk['y'] + '=='), 'big')
        
        # Determine curve
        crv = jwk.get('crv', 'P-256')
        if crv == 'P-256':
            from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
            curve = SECP256R1()
        elif crv == 'P-384':
            from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1
            curve = SECP384R1()
        elif crv == 'P-521':
            from cryptography.hazmat.primitives.asymmetric.ec import SECP521R1
            curve = SECP521R1()
        else:
            raise OAuth2OIDCError(f"Unsupported EC curve: {crv}")
        
        numbers = EllipticCurvePublicNumbers(x, y, curve)
        public_key = numbers.public_key(backend=default_backend())
        
    else:
        raise OAuth2OIDCError(f"Unsupported key type: {kty}")
    
    # Convert to PEM format
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem.decode('utf-8')


def validate_token_signature(
    token: str,
    jwks: Dict,
    audience: Optional[str] = None,
    issuer: Optional[str] = None
) -> Dict:
    """
    Validate JWT token signature using provided JWKS.
    
    Args:
        token: JWT token string
        jwks: JWKS dictionary
        audience: Expected audience (aud) claim
        issuer: Expected issuer (iss) claim
        
    Returns:
        Token payload as dictionary
        
    Raises:
        OAuth2OIDCError: If validation fails
    """
    try:
        # Decode token header to get key ID
        unverified_header = jwt.get_unverified_header(token)
        key_id = unverified_header.get('kid')
        
        if not key_id:
            raise OAuth2OIDCError("No key ID (kid) found in token header")
        
        # Find the key in JWKS
        keys = jwks.get('keys', [])
        matching_key = None
        
        for key in keys:
            if key.get('kid') == key_id:
                matching_key = key
                break
        
        if not matching_key:
            raise OAuth2OIDCError(f"No public key found for key ID: {key_id}")
        
        # Convert JWK to PEM using standalone function
        public_key = _convert_jwk_to_pem_standalone(matching_key)
        
        # Validate token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256', 'ES256', 'ES384', 'ES512'],
            audience=audience,
            issuer=issuer,
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_iat': True,
                'require_exp': True,
                'require_iat': True
            }
        )
        
        # Security. Explicitly check for exp claim - tokens without expiration are not allowed
        if 'exp' not in payload:
            raise OAuth2OIDCError("Token missing required 'exp' (expiration) claim")
        
        # Security. Check if token is already expired
        current_time = int(time.time())
        if payload['exp'] < current_time:
            raise OAuth2OIDCError("Token has expired")
        
        return payload
        
    except jwt.ExpiredSignatureError:
        raise OAuth2OIDCError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise OAuth2OIDCError(f"Invalid token: {e}")
    except Exception as e:
        raise OAuth2OIDCError(f"Token validation failed: {e}")


def validate_multiple_token_signatures(
    tokens: List[Dict],
    jwks: Dict,
    audience: Optional[str] = None,
    issuer: Optional[str] = None
) -> List[Dict]:
    """
    Validate multiple JWT token signatures using provided JWKS.
    
    Args:
        tokens: List of token dictionaries with 'token' and 'type' keys
        jwks: JWKS dictionary
        audience: Expected audience (aud) claim
        issuer: Expected issuer (iss) claim
        
    Returns:
        List of validation results
    """
    results = []
    
    for token_info in tokens:
        result = {
            'token': token_info['token'],
            'type': token_info.get('type', 'access_token'),
            'valid': False,
            'payload': None,
            'error': None
        }
        
        try:
            payload = validate_token_signature(
                token_info['token'],
                jwks,
                audience,
                issuer
            )
            result['valid'] = True
            result['payload'] = payload
            
        except OAuth2OIDCError as e:
            result['error'] = str(e)
        
        results.append(result)
    
    return results 