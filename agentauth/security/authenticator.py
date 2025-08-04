"""
Cryptographic authentication and secure token validation for AgentAuth.

This module provides cryptographic authentication and enhanced token validation.
"""

import os
import time
import hashlib
import hmac
import secrets
import base64
import logging
from typing import Dict, Optional, Any, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import jwt

from ..utils.exceptions import SecurityError
from ..utils.crypto import validate_cryptographic_parameters

logger = logging.getLogger(__name__)


class CryptographicAuthenticator:
    """
    Cryptographic authentication for library access.
    
    This class provides:
    - Certificate-based authentication
    - Token-based authentication with HMAC
    - Rate limiting
    - Anti-replay protection
    """
    
    def __init__(self, cert_chain: Optional[str] = None, secret_key: Optional[bytes] = None):
        """
        Initialize cryptographic authenticator.
        
        Args:
            cert_chain: Path to certificate chain file
            secret_key: Secret key for HMAC authentication
        """
        self._cert_chain = cert_chain
        self._secret_key = secret_key or secrets.token_bytes(32)
        self._nonce_store = {}
        self._rate_limit_store = {}
        self._max_requests_per_minute = int(os.getenv("AGENTAUTH_RATE_LIMIT_PER_MINUTE", "3000"))
        
    def verify_certificate_chain(self, cert_data: bytes) -> bool:
        """
        Verify certificate chain authenticity.
        
        Args:
            cert_data: Certificate data to verify
            
        Returns:
            True if certificate chain is valid
        """
        try:
            # Load certificate
            cert = serialization.load_pem_x509_certificate(cert_data)
            
            # Verify certificate chain if provided
            if self._cert_chain:
                with open(self._cert_chain, 'rb') as f:
                    chain_data = f.read()
                
                # Basic chain verification (in production, use proper CA validation)
                return self._verify_chain(cert, chain_data)
            
            return True
            
        except Exception as e:
            logger.error(f"Certificate verification failed: {e}")
            return False
    
    def _verify_chain(self, cert: Any, chain_data: bytes) -> bool:
        """Verify certificate chain (simplified implementation)."""
        # In production, implement proper certificate chain validation
        # This is a simplified version for demonstration
        return True
    
    def generate_hmac_token(self, data: str, timestamp: Optional[int] = None) -> str:
        """
        Generate HMAC token for authentication.
        
        Args:
            data: Data to sign
            timestamp: Optional timestamp (defaults to current time)
            
        Returns:
            HMAC token string
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # Create message with timestamp
        message = f"{data}:{timestamp}"
        
        # Generate HMAC
        h = hmac.new(self._secret_key, message.encode(), hashlib.sha256)
        signature = base64.urlsafe_b64encode(h.digest()).decode()
        
        return f"{signature}:{timestamp}"
    
    def verify_hmac_token(self, token: str, data: str, max_age: int = 300) -> bool:
        """
        Verify HMAC token.
        
        Args:
            token: HMAC token to verify
            data: Original data
            max_age: Maximum age in seconds
            
        Returns:
            True if token is valid
        """
        try:
            # Parse token
            parts = token.split(':')
            if len(parts) != 2:
                return False
            
            signature, timestamp_str = parts
            timestamp = int(timestamp_str)
            
            # Check age
            if time.time() - timestamp > max_age:
                return False
            
            # Verify signature
            message = f"{data}:{timestamp}"
            h = hmac.new(self._secret_key, message.encode(), hashlib.sha256)
            expected_signature = base64.urlsafe_b64encode(h.digest()).decode()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception as e:
            logger.error(f"HMAC verification failed: {e}")
            return False
    
    def check_rate_limit(self, identifier: str) -> bool:
        """
        Check rate limit for identifier.
        
        Args:
            identifier: Client identifier
            
        Returns:
            True if within rate limit
        """
        current_time = time.time()
        
        # Clean up old entries
        self._rate_limit_store = {
            k: v for k, v in self._rate_limit_store.items()
            if v and current_time - max(v) < 60
        }
        
        # Count requests in last minute
        if identifier in self._rate_limit_store:
            count = len(self._rate_limit_store[identifier])
            if count >= self._max_requests_per_minute:
                return False
        
        # Add current request
        if identifier not in self._rate_limit_store:
            self._rate_limit_store[identifier] = []
        
        self._rate_limit_store[identifier].append(current_time)
        return True
    
    def verify_nonce(self, nonce: str, max_age: int = 300) -> bool:
        """
        Verify nonce for anti-replay protection.
        
        Args:
            nonce: Nonce to verify
            max_age: Maximum age in seconds
            
        Returns:
            True if nonce is valid
        """
        current_time = time.time()
        
        # Clean up old nonces
        self._nonce_store = {
            k: v for k, v in self._nonce_store.items()
            if current_time - v < max_age
        }
        
        # Check if nonce exists
        if nonce in self._nonce_store:
            return False
        
        # Store nonce
        self._nonce_store[nonce] = current_time
        return True


class SecureTokenValidator:
    """
    Enhanced token validation with security features.
    
    This class provides secure token validation with additional
    security checks and validation.
    """
    
    def __init__(self):
        """Initialize secure token validator."""
        pass
    
    def validate_token_secure(
        self,
        token: str,
        jwks: Dict,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
        auth_token: Optional[str] = None,
        client_id: Optional[str] = None
    ) -> Dict:
        """
        Validate token with enhanced security checks.
        
        Args:
            token: JWT token to validate
            jwks: JWKS dictionary
            audience: Expected audience
            issuer: Expected issuer
            auth_token: Optional authentication token
            client_id: Optional client ID
            
        Returns:
            Token payload
            
        Raises:
            SecurityError: If security validation fails
        """
        try:
            # Validate token format
            if not self._validate_token_format(token):
                raise SecurityError("Invalid token format")
            
            # Decode token header to get key ID
            try:
                header = jwt.get_unverified_header(token)
            except jwt.InvalidTokenError as e:
                raise SecurityError(f"Invalid token header: {e}")
            
            key_id = header.get('kid')
            if not key_id:
                raise SecurityError("Token header missing key ID")
            
            # Find the key in JWKS
            keys = jwks.get('keys', [])
            matching_key = None
            
            for key in keys:
                if key.get('kid') == key_id:
                    # Validate JWK structure
                    if not validate_cryptographic_parameters(key):
                        raise SecurityError("Invalid JWK structure")
                    matching_key = key
                    break
            
            if not matching_key:
                raise SecurityError(f"No public key found for key ID: {key_id}")
            
            # Convert JWK to PEM
            from ..core.validation import _convert_jwk_to_pem_standalone
            public_key = _convert_jwk_to_pem_standalone(matching_key)
            
            # Validate token with enhanced options
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
            
            # Additional security checks
            self._validate_token_security(payload, auth_token, client_id)
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise SecurityError("Token has expired")
        except jwt.InvalidAudienceError:
            raise SecurityError("Invalid token audience")
        except jwt.InvalidIssuerError:
            raise SecurityError("Invalid token issuer")
        except jwt.InvalidSignatureError:
            raise SecurityError("Invalid token signature")
        except jwt.InvalidTokenError as e:
            raise SecurityError(f"Invalid token: {e}")
        except Exception as e:
            raise SecurityError(f"Token validation failed: {e}")
    
    def _validate_token_format(self, token: str) -> bool:
        """
        Validate basic JWT token format.
        
        Args:
            token: Token to validate
            
        Returns:
            True if token format is valid
        """
        if not token or not isinstance(token, str):
            return False
        
        # Check for JWT format (three parts separated by dots)
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Check that all parts are base64url encoded
        import re
        base64url_pattern = re.compile(r'^[A-Za-z0-9_-]+$')
        
        for part in parts:
            if not base64url_pattern.match(part):
                return False
        
        return True
    
    def _validate_token_security(self, payload: Dict, auth_token: Optional[str] = None, client_id: Optional[str] = None):
        """
        Perform additional security validations on token payload.
        
        Args:
            payload: Token payload
            auth_token: Optional authentication token
            client_id: Optional client ID
            
        Raises:
            SecurityError: If security validation fails
        """
        # Check for required claims
        required_claims = ['exp', 'iat']
        for claim in required_claims:
            if claim not in payload:
                raise SecurityError(f"Token missing required claim: {claim}")
        
        # Check expiration
        import time
        current_time = int(time.time())
        if payload['exp'] < current_time:
            raise SecurityError("Token has expired")
        
        # Check issued at time
        if payload['iat'] > current_time:
            raise SecurityError("Token issued in the future")
        
        # Additional checks if auth_token provided
        if auth_token:
            # Validate auth_token format
            if not self._validate_token_format(auth_token):
                raise SecurityError("Invalid authentication token format")
        
        # Additional checks if client_id provided
        if client_id and 'aud' in payload:
            if payload['aud'] != client_id:
                raise SecurityError("Token audience does not match client ID") 