#!/usr/bin/env python3
"""
Test Configuration for OAuth2/OIDC Library Unit Tests

This module provides test data, mock objects, and utilities for unit testing
the OAuth2/OIDC library.
"""

import os
import time
import jwt
from datetime import datetime, timedelta


def get_test_idp_base_url():
    """Get the test IdP base URL for testing (completely independent of environment variables)."""
    return "https://test.issuer.com"


class TestData:
    """Test data constants and utilities."""
    
    # Get base URL for dynamic configuration
    _base_url = get_test_idp_base_url()
    
    # Mock OIDC Configuration
    MOCK_OIDC_CONFIG = {
        "issuer": _base_url,
        "authorization_endpoint": f"{_base_url}/oauth2/authorize",
        "token_endpoint": f"{_base_url}/oauth2/token",
        "userinfo_endpoint": f"{_base_url}/oauth2/userinfo",
        "jwks_uri": f"{_base_url}/.well-known/jwks.json",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "name", "given_name", "family_name", "email"]
    }
    
    # Mock JWKS
    MOCK_JWKS = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-rsa-key-1",
                "alg": "RS256",
                "use": "sig",
                "n": "test-n-value-1",
                "e": "AQAB"
            },
            {
                "kty": "RSA",
                "kid": "test-rsa-key-2",
                "alg": "RS256",
                "use": "sig",
                "n": "test-n-value-2",
                "e": "AQAB"
            },
            {
                "kty": "EC",
                "kid": "test-ec-key-1",
                "alg": "ES256",
                "use": "sig",
                "crv": "P-256",
                "x": "test-x-value",
                "y": "test-y-value"
            }
        ]
    }
    
    # Mock Token Responses
    MOCK_ACCESS_TOKEN_RESPONSE = {
        "access_token": "mock-access-token-12345",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid profile email",
        "refresh_token": "mock-refresh-token-12345"
    }
    
    MOCK_ID_TOKEN_RESPONSE = {
        "id_token": "mock-id-token-12345",
        "access_token": "mock-access-token-12345",
        "token_type": "Bearer",
        "expires_in": 3600
    }
    
    # Test Client Configuration
    TEST_CLIENT_CONFIG = {
        "idp_name": "Test Identity Provider",
        "idp_endpoint": _base_url,
        "client_id": "test-client-id-12345",
        "client_secret": "test-client-secret-12345",
        "scope": "openid profile email",
        "timeout": 30,
        "jwks_cache_ttl": 3600
    }
    
    # Test Token Payloads
    TEST_ACCESS_TOKEN_PAYLOAD = {
        "sub": "test-user-12345",
        "iss": _base_url,
        "aud": "test-client-id-12345",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "scope": "openid profile email",
        "client_id": "test-client-id-12345"
    }
    
    TEST_ID_TOKEN_PAYLOAD = {
        "sub": "test-user-12345",
        "iss": _base_url,
        "aud": "test-client-id-12345",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "email": "test.user@example.com",
        "email_verified": True
    }
    
    # Error Messages
    ERROR_MESSAGES = {
        "network_error": "Network error occurred",
        "invalid_credentials": "Invalid client credentials",
        "token_expired": "Token has expired",
        "invalid_signature": "Invalid token signature",
        "missing_kid": "No key ID (kid) found in token header",
        "key_not_found": "No public key found for key ID",
        "unsupported_key_type": "Unsupported key type",
        "unsupported_curve": "Unsupported EC curve",
        "oidc_discovery_failed": "OIDC discovery failed",
        "jwks_retrieval_failed": "JWKS retrieval failed",
        "authentication_failed": "Authentication failed",
        "token_validation_failed": "Token validation failed"
    }


class MockResponses:
    """Mock HTTP responses for testing."""
    
    @staticmethod
    def create_success_response(data, status_code=200):
        """Create a mock successful HTTP response."""
        response = Mock()
        response.json.return_value = data
        response.status_code = status_code
        response.raise_for_status.return_value = None
        return response
    
    @staticmethod
    def create_error_response(status_code=400, error_message="Bad Request"):
        """Create a mock error HTTP response."""
        response = Mock()
        response.status_code = status_code
        response.raise_for_status.side_effect = Exception(error_message)
        return response
    
    @staticmethod
    def create_network_error():
        """Create a mock network error."""
        return Exception("Network error occurred")


class TokenGenerator:
    """Utility class for generating test tokens."""
    
    @staticmethod
    def create_test_jwt(payload, secret="test-secret", algorithm="HS256", headers=None):
        """Create a test JWT token."""
        if headers is None:
            headers = {}
        
        return jwt.encode(payload, secret, algorithm=algorithm, headers=headers)
    
    @staticmethod
    def create_expired_token():
        """Create an expired JWT token."""
        payload = {
            "sub": "test-user",
            "iss": _base_url,
            "aud": "test-client",
            "iat": int(time.time()) - 7200,  # 2 hours ago
            "exp": int(time.time()) - 3600    # 1 hour ago
        }
        return TokenGenerator.create_test_jwt(payload)
    
    @staticmethod
    def create_valid_token():
        """Create a valid JWT token."""
        payload = {
            "sub": "test-user",
            "iss": _base_url,
            "aud": "test-client",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }
        return TokenGenerator.create_test_jwt(payload)
    
    @staticmethod
    def create_token_with_kid(kid="test-key-id"):
        """Create a JWT token with a specific key ID."""
        payload = {
            "sub": "test-user",
            "iss": _base_url,
            "aud": "test-client",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }
        headers = {"kid": kid}
        return TokenGenerator.create_test_jwt(payload, headers=headers)


class TestUtilities:
    """Utility functions for testing."""
    
    @staticmethod
    def assert_dict_contains_keys(dictionary, required_keys):
        """Assert that a dictionary contains all required keys."""
        for key in required_keys:
            assert key in dictionary, f"Missing required key: {key}"
    
    @staticmethod
    def assert_token_info_structure(token_info):
        """Assert that token info has the correct structure."""
        required_keys = ["header", "payload", "exp", "iat", "aud", "iss", "sub"]
        TestUtilities.assert_dict_contains_keys(token_info, required_keys)
    
    @staticmethod
    def assert_validation_result_structure(result):
        """Assert that validation result has the correct structure."""
        required_keys = ["token", "type", "valid", "payload", "error"]
        TestUtilities.assert_dict_contains_keys(result, required_keys)
    
    @staticmethod
    def create_mock_client():
        """Create a mock OAuth2OIDCClient instance."""
        from agentauth.core.client import OAuth2OIDCClient
        from agentauth.config.client_config import ClientConfig
        
        # We need to patch the OIDC discovery to avoid actual HTTP calls
        with patch('agentauth.core.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = TestData.MOCK_OIDC_CONFIG
            mock_response.raise_for_status.return_value = None
            mock_response.headers = {'content-length': '1000'}
            mock_response.raw.connection.sock.version.return_value = "TLSv1.3"
            mock_response.content = b'{"issuer":"https://test.issuer.com","token_endpoint":"https://test.issuer.com/oauth2/token","jwks_uri":"https://test.issuer.com/.well-known/jwks.json"}'
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            # Create config from test data
            config = ClientConfig(**TestData.TEST_CLIENT_CONFIG)
            client = OAuth2OIDCClient(config)
            return client


# Import Mock for use in this module
from unittest.mock import Mock 