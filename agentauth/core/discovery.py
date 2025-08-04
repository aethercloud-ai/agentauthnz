"""
OIDC discovery and JWKS retrieval for AgentAuth.

This module provides functions for discovering OIDC configuration and retrieving JWKS.
"""

import logging
import requests
from typing import Dict
from ..utils.exceptions import OAuth2OIDCError, SecurityError
from ..security.components.http_client import SecureHTTPClient, verify_tls_version

logger = logging.getLogger(__name__)


def discover_oidc_config(idp_endpoint: str, timeout: int = 30) -> Dict:
    """
    Discover OIDC configuration from the IdP's well-known endpoint.
    
    Args:
        idp_endpoint: Base URL of the Identity Provider
        timeout: HTTP request timeout in seconds
        
    Returns:
        OIDC configuration dictionary
        
    Raises:
        OAuth2OIDCError: If OIDC discovery fails
        SecurityError: If security validation fails
    """
    try:
        well_known_url = f"{idp_endpoint.rstrip('/')}/.well-known/openid_configuration"
        logger.info(f"Discovering OIDC configuration from {well_known_url}")
        
        # Use secure HTTP client
        http_client = SecureHTTPClient(timeout=timeout, verify_ssl=True)
        response = http_client.get(well_known_url)
        
        # Verify TLS version used
        if not verify_tls_version(response):
            raise SecurityError("Insecure TLS version detected - TLS 1.2+ required")
        
        if response.status_code != 200:
            logger.error(f"OIDC discovery failed: {response.status_code} - {response.text}")
            raise OAuth2OIDCError(f"OIDC discovery failed: {response.status_code}")
        
        oidc_config = response.json()
        
        # Validate required endpoints
        required_endpoints = ['token_endpoint', 'jwks_uri']
        for endpoint in required_endpoints:
            if endpoint not in oidc_config:
                raise OAuth2OIDCError(f"Missing required endpoint: {endpoint}")
        
        logger.info("Successfully discovered OIDC configuration")
        return oidc_config
        
    except (SecurityError, OAuth2OIDCError):
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to discover OIDC configuration: {e}")
        raise OAuth2OIDCError(f"OIDC discovery failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during OIDC discovery: {e}")
        raise OAuth2OIDCError(f"OIDC discovery failed: {e}")


def retrieve_jwks(jwks_uri: str, timeout: int = 30) -> Dict:
    """
    Retrieve JWKS (JSON Web Key Set) from the specified URI.
    
    Args:
        jwks_uri: URI of the JWKS endpoint
        timeout: HTTP request timeout in seconds
        
    Returns:
        JWKS dictionary
        
    Raises:
        OAuth2OIDCError: If JWKS retrieval fails
        SecurityError: If security validation fails
    """
    try:
        logger.info(f"Retrieving JWKS from {jwks_uri}")
        
        # Use secure HTTP client
        http_client = SecureHTTPClient(timeout=timeout, verify_ssl=True)
        response = http_client.get(jwks_uri)
        
        # Verify TLS version used
        if not verify_tls_version(response):
            raise SecurityError("Insecure TLS version detected - TLS 1.2+ required")
        
        if response.status_code != 200:
            logger.error(f"JWKS retrieval failed: {response.status_code} - {response.text}")
            raise OAuth2OIDCError(f"JWKS retrieval failed: {response.status_code}")
        
        jwks_data = response.json()
        
        # Validate JWKS structure
        if 'keys' not in jwks_data:
            raise OAuth2OIDCError("Invalid JWKS structure: missing 'keys' field")
        
        if not isinstance(jwks_data['keys'], list):
            raise OAuth2OIDCError("Invalid JWKS structure: 'keys' must be an array")
        
        logger.info(f"Successfully retrieved JWKS with {len(jwks_data['keys'])} keys")
        return jwks_data
        
    except (SecurityError, OAuth2OIDCError):
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to retrieve JWKS: {e}")
        raise OAuth2OIDCError(f"JWKS retrieval failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during JWKS retrieval: {e}")
        raise OAuth2OIDCError(f"JWKS retrieval failed: {e}") 