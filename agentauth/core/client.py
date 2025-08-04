"""
OAuth2/OIDC client for AgentAuth.

This module provides the main OAuth2/OIDC client class for authentication and token validation.
"""

import json
import logging
import time
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin

import requests
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

# Import configuration
from ..config import ClientConfig
from ..utils.exceptions import SecurityError, OAuth2OIDCError
from ..security.framework import SecurityFramework
from ..security.components.http_client import SecureHTTPClient
from ..security.components.http_client import verify_tls_version

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OAuth2OIDCClient:
    """
    OAuth2/OIDC client for machine-to-machine authentication and JWT token validation.
    
    This class provides functionality to:
    - Authenticate using OAuth2 client credentials flow
    - Retrieve and cache JWKS (JSON Web Key Set) from IdP
    - Validate JWT tokens (access tokens, ID tokens)
    - Handle token refresh and expiration
    """
    
    def __init__(self, config: ClientConfig):
        """
        Initialize the OAuth2/OIDC client with configuration.
        
        Args:
            config: Client configuration object
        """
        self.config = config
        self.idp_name = config.idp_name
        self.idp_endpoint = config.idp_endpoint.rstrip('/')
        self.client_id = config.client_id
        self.client_secret = config.client_secret
        self.scope = config.scope
        self.timeout = config.timeout
        self.jwks_cache_ttl = config.jwks_cache_ttl
        self.enable_security = config.security.enable_security
        
        # Initialize simple dictionary-based storage
        self._jwks_cache = {}
        self._jwks_cache_time = 0
        self._access_token_cache = {}
        self._access_token_expiry = 0
        
        # Initialize security framework
        self.security = SecurityFramework(config.security)
        
        # Initialize secure HTTP client
        self._http_client = SecureHTTPClient(timeout=self.timeout, verify_ssl=config.security.verify_ssl)
        
        # Discover OIDC configuration
        self._discover_oidc_config()
    
    def _discover_oidc_config(self) -> None:
        """
        Discover OIDC configuration from the IdP's well-known endpoint.
        
        This method retrieves the OIDC discovery document which contains
        endpoints for token, authorization, JWKS, etc. All communications
        are secured with TLS 1.3 preferred, TLS 1.2 fallback.
        """
        try:
            well_known_url = f"{self.idp_endpoint}/.well-known/openid_configuration"
            logger.info(f"Discovering OIDC configuration from {well_known_url}")
            
            # Use secure HTTP client with TLS 1.3 preferred, TLS 1.2 fallback
            response = self._http_client.get(well_known_url)
            
            # Verify TLS version used (TLS 1.3 preferred, TLS 1.2 fallback)
            if not verify_tls_version(response):
                raise SecurityError("Insecure TLS version detected - TLS 1.2+ required")
            
            self.oidc_config = response.json()
            logger.info(f"Successfully discovered OIDC configuration for {self.idp_name}")
            
        except SecurityError as e:
            logger.error(f"Security error during OIDC discovery: {e}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to discover OIDC configuration: {e}")
            raise OAuth2OIDCError(f"OIDC discovery failed: {e}")
    
    def authenticate(self, force_refresh: bool = False, auth_token: Optional[str] = None) -> str:
        """
        Authenticate using OAuth2 client credentials flow.
        
        Args:
            force_refresh: Force token refresh even if current token is valid
            auth_token: Optional authentication token for additional security
            
        Returns:
            Access token string
            
        Raises:
            OAuth2OIDCError: If authentication fails
            SecurityError: If security validation fails
        """
        try:
            # Security. Validate input parameters
            if self.enable_security:
                self.security.sanitizer.sanitize_client_id(self.client_id)
                if auth_token:
                    self.security.sanitizer.sanitize_jwt_token(auth_token)
            
            # Check if we have a valid cached token
            if not force_refresh and self._is_token_valid():
                logger.info("Using cached access token")
                return self._access_token_cache.get('access_token', '')
            
            # Security. Acquire request slot for rate limiting
            if self.enable_security:
                self.security.resource_limiter.acquire_request_slot(self.client_id)
            
            # Prepare authentication request
            token_endpoint = self.oidc_config.get('token_endpoint')
            if not token_endpoint:
                raise OAuth2OIDCError("Token endpoint not found in OIDC configuration")
            
            # Security. Sanitize token endpoint URL
            if self.enable_security:
                token_endpoint = self.security.sanitizer.sanitize_url(token_endpoint)
            
            auth_data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
            
            if self.scope:
                auth_data['scope'] = self.scope
            
            # Security. Add authentication token if provided
            if auth_token:
                auth_data['auth_token'] = auth_token
            
            # Make authentication request
            logger.info(f"Authenticating with {self.idp_name}")
            response = self._http_client.post(token_endpoint, data=auth_data)
            
            # Security. Limit response size
            if self.enable_security:
                response = self.security.resource_limiter.limit_response_size(response)
            
            if response.status_code != 200:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                raise OAuth2OIDCError(f"Authentication failed: {response.status_code}")
            
            token_data = response.json()
            access_token = token_data.get('access_token')
            
            if not access_token:
                raise OAuth2OIDCError("No access token received")
            
            # Security. Validate token format
            if self.enable_security:
                self.security.sanitizer.sanitize_jwt_token(access_token)
            
            # Cache token with expiration
            expires_in = token_data.get('expires_in', 3600)
            self._access_token_cache = token_data
            self._access_token_expiry = time.time() + expires_in
            
            # Security. Log successful authentication
            if self.enable_security:
                self.security.audit_logger.log_authentication_attempt(
                    self.client_id, True, {'expires_in': expires_in}
                )
            
            logger.info(f"Successfully authenticated with {self.idp_name}")
            return access_token
            
        except (SecurityError, OAuth2OIDCError):
            # Security. Log failed authentication
            if self.enable_security:
                self.security.audit_logger.log_authentication_attempt(
                    self.client_id, False, {'error': 'authentication_failed'}
                )
            raise
        finally:
            # Security. Release request slot
            if self.enable_security:
                self.security.resource_limiter.release_request_slot()
    
    def _is_token_valid(self) -> bool:
        """
        Check if the cached access token is still valid.
        
        Returns:
            True if token is valid and not expired
        """
        if not self._access_token_cache:
            return False
        
        # Check if token is expired (with 5-minute buffer)
        if time.time() >= self._access_token_expiry - 300:
            return False
        
        return True
    
    def get_jwks(self, force_refresh: bool = False) -> Dict:
        """
        Get JWKS (JSON Web Key Set) from the IdP.
        
        Args:
            force_refresh: Force refresh of JWKS cache
            
        Returns:
            JWKS dictionary
            
        Raises:
            OAuth2OIDCError: If JWKS retrieval fails
            SecurityError: If security validation fails
        """
        try:
            # Check if we have valid cached JWKS
            if not force_refresh and self._is_jwks_valid():
                logger.info("Using cached JWKS")
                return self._jwks_cache
            
            # Security. Acquire request slot for rate limiting
            if self.enable_security:
                self.security.resource_limiter.acquire_request_slot(self.client_id)
            
            jwks_uri = self.oidc_config.get('jwks_uri')
            if not jwks_uri:
                raise OAuth2OIDCError("JWKS URI not found in OIDC configuration")
            
            # Security. Sanitize JWKS URI
            if self.enable_security:
                jwks_uri = self.security.sanitizer.sanitize_url(jwks_uri)
            
            logger.info(f"Retrieving JWKS from {jwks_uri}")
            response = self._http_client.get(jwks_uri)
            
            # Security. Limit response size
            if self.enable_security:
                response = self.security.resource_limiter.limit_response_size(response)
            
            if response.status_code != 200:
                logger.error(f"JWKS retrieval failed: {response.status_code} - {response.text}")
                raise OAuth2OIDCError(f"JWKS retrieval failed: {response.status_code}")
            
            jwks_data = response.json()
            
            # Security. Validate JWKS structure
            if self.enable_security:
                if not self.security.injection_protector.validate_jwk_structure(jwks_data):
                    raise SecurityError("Invalid JWKS structure")
            
            # Cache JWKS with TTL
            self._jwks_cache = jwks_data
            self._jwks_cache_time = time.time()
            
            logger.info(f"Successfully retrieved JWKS from {self.idp_name}")
            return jwks_data
            
        except (SecurityError, OAuth2OIDCError):
            # Security. Log JWKS retrieval failure
            if self.enable_security:
                self.security.audit_logger.log_security_violation(
                    "jwks_retrieval_failed", {'error': 'jwks_retrieval_failed'}
                )
            raise
        finally:
            # Security. Release request slot
            if self.enable_security:
                self.security.resource_limiter.release_request_slot()
    
    def _is_jwks_valid(self) -> bool:
        """
        Check if the cached JWKS is still valid.
        
        Returns:
            True if JWKS is valid and not expired
        """
        if not self._jwks_cache:
            return False
        
        # Check if JWKS cache is expired
        if time.time() >= self._jwks_cache_time + self.jwks_cache_ttl:
            return False
        
        return True
    
    def _get_public_key(self, key_id: str) -> Optional[str]:
        """
        Get public key from JWKS by key ID.
        
        Args:
            key_id: Key ID to look up
            
        Returns:
            PEM-encoded public key or None if not found
        """
        jwks = self.get_jwks()
        keys = jwks.get('keys', [])
        
        for key in keys:
            if key.get('kid') == key_id:
                return self._convert_jwk_to_pem(key)
        
        return None
    
    def _convert_jwk_to_pem(self, jwk: Dict) -> str:
        """
        Convert JWK to PEM format.
        
        Args:
            jwk: JWK dictionary
            
        Returns:
            PEM-encoded public key
        """
        kty = jwk.get('kty')
        
        if kty == 'RSA':
            # Convert RSA JWK to PEM
            n = int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + '=='), 'big')
            e = int.from_bytes(base64.urlsafe_b64decode(jwk['e'] + '=='), 'big')
            
            public_numbers = RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key(backend=default_backend())
            
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return pem.decode('utf-8')
        
        elif kty == 'EC':
            # Convert EC JWK to PEM
            x = int.from_bytes(base64.urlsafe_b64decode(jwk['x'] + '=='), 'big')
            y = int.from_bytes(base64.urlsafe_b64decode(jwk['y'] + '=='), 'big')
            
            curve_name = jwk.get('crv', 'P-256')
            if curve_name == 'P-256':
                from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
                curve = SECP256R1()
            elif curve_name == 'P-384':
                from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1
                curve = SECP384R1()
            elif curve_name == 'P-521':
                from cryptography.hazmat.primitives.asymmetric.ec import SECP521R1
                curve = SECP521R1()
            else:
                raise OAuth2OIDCError(f"Unsupported EC curve: {curve_name}")
            
            public_numbers = EllipticCurvePublicNumbers(x, y, curve)
            public_key = public_numbers.public_key(backend=default_backend())
            
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return pem.decode('utf-8')
        
        else:
            raise OAuth2OIDCError(f"Unsupported key type: {kty}")
    
    def validate_token(
        self,
        token: str,
        token_type: str = 'access_token',
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
        auth_token: Optional[str] = None
    ) -> Dict:
        """
        Validate JWT token signature and claims.
        
        Args:
            token: JWT token to validate
            token_type: Type of token ('access_token', 'id_token', etc.)
            audience: Expected audience (optional)
            issuer: Expected issuer (optional)
            auth_token: Optional authentication token for additional security
            
        Returns:
            Decoded token payload
            
        Raises:
            OAuth2OIDCError: If token validation fails
            SecurityError: If security validation fails
        """
        try:
            # Security. Validate input parameters
            if self.enable_security:
                self.security.sanitizer.sanitize_jwt_token(token)
                if auth_token:
                    self.security.sanitizer.sanitize_jwt_token(auth_token)
            
            # Security. Validate token content
            if self.enable_security:
                if not self.security.injection_protector.validate_token_content(token):
                    raise SecurityError("Token contains suspicious content")
            
            # Get JWKS for signature validation
            jwks = self.get_jwks()
            
            # Decode token header to get key ID
            try:
                header = jwt.get_unverified_header(token)
            except jwt.InvalidTokenError as e:
                raise OAuth2OIDCError(f"Invalid token format: {e}")
            
            key_id = header.get('kid')
            if not key_id:
                raise OAuth2OIDCError("Token header missing key ID")
            
            # Get public key for signature validation
            public_key_pem = self._get_public_key(key_id)
            if not public_key_pem:
                raise OAuth2OIDCError(f"Public key not found for key ID: {key_id}")
            
            # Validate token signature and claims
            try:
                # Security. Use secure token validator
                if self.enable_security:
                    payload = self.security.validator.validate_token_secure(
                        token, jwks, audience, issuer, auth_token, self.client_id
                    )
                else:
                    # Fallback to basic validation
                    payload = jwt.decode(
                        token,
                        public_key_pem,
                        algorithms=['RS256', 'ES256', 'ES384', 'ES512'],
                        audience=audience,
                        issuer=issuer,
                        options={'verify_signature': True}
                    )
                
                # Security. Log token validation success
                if self.enable_security:
                    token_hash = self.security.audit_logger._hash_sensitive_data(token)
                    self.security.audit_logger.log_token_validation(
                        token_hash, True, {'token_type': token_type}
                    )
                
                logger.info(f"Successfully validated {token_type}")
                return payload
                
            except jwt.ExpiredSignatureError:
                logger.warning(f"{token_type} has expired")
                raise OAuth2OIDCError(f"{token_type} has expired")
            except jwt.InvalidAudienceError:
                logger.warning(f"Invalid {token_type} audience")
                raise OAuth2OIDCError(f"Invalid {token_type} audience")
            except jwt.InvalidIssuerError:
                logger.warning(f"Invalid {token_type} issuer")
                raise OAuth2OIDCError(f"Invalid {token_type} issuer")
            except jwt.InvalidSignatureError:
                logger.warning(f"Invalid {token_type} signature")
                raise OAuth2OIDCError(f"Invalid {token_type} signature")
            except jwt.InvalidTokenError as e:
                logger.warning(f"Invalid {token_type}: {e}")
                raise OAuth2OIDCError(f"Invalid {token_type}: {e}")
                
        except (SecurityError, OAuth2OIDCError):
            # Security. Log token validation failure
            if self.enable_security:
                token_hash = self.security.audit_logger._hash_sensitive_data(token)
                self.security.audit_logger.log_token_validation(
                    token_hash, False, {'error': 'validation_failed'}
                )
            raise
    
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
    
    def validate_multiple_tokens(
        self,
        tokens: List[Dict],
        audience: Optional[str] = None,
        issuer: Optional[str] = None
    ) -> List[Dict]:
        """
        Validate multiple JWT tokens.
        
        Args:
            tokens: List of token dictionaries with 'token' and 'type' keys
            audience: Expected audience (optional)
            issuer: Expected issuer (optional)
            
        Returns:
            List of validation results
        """
        results = []
        
        for token_info in tokens:
            try:
                token = token_info.get('token')
                token_type = token_info.get('type', 'access_token')
                
                if not token:
                    results.append({
                        'valid': False,
                        'error': 'Missing token',
                        'token_type': token_type
                    })
                    continue
                
                payload = self.validate_token(token, token_type, audience, issuer)
                results.append({
                    'valid': True,
                    'payload': payload,
                    'token_type': token_type
                })
                
            except Exception as e:
                results.append({
                    'valid': False,
                    'error': str(e),
                    'token_type': token_info.get('type', 'access_token')
                })
        
        return results
    
    def get_token_info(self, token: str) -> Dict:
        """
        Get information about a JWT token without validating signature.
        
        Args:
            token: JWT token to analyze
            
        Returns:
            Token information dictionary
        """
        try:
            # Security. Validate token format
            if self.enable_security:
                self.security.sanitizer.sanitize_jwt_token(token)
            
            # Decode token without signature verification
            payload = jwt.decode(token, options={'verify_signature': False})
            
            # Security. Sanitize sensitive claims
            if self.enable_security:
                payload = self.security.audit_logger.sanitize_jwt_payload(payload)
            
            return {
                'header': jwt.get_unverified_header(token),
                'payload': payload,
                'format_valid': self._validate_token_format(token)
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'format_valid': self._validate_token_format(token)
            } 