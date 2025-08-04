#!/usr/bin/env python3
"""
Simple test script to run basic tests with proper mocking.
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the library under test
from agentauth.core.client import OAuth2OIDCClient
from agentauth.core.discovery import discover_oidc_config, retrieve_jwks
from agentauth.core.validation import validate_token_signature, validate_multiple_token_signatures, _convert_jwk_to_pem_standalone
from agentauth.utils.exceptions import SecurityError, OAuth2OIDCError
from agentauth.config.client_config import ClientConfig
from agentauth.security.authenticator import CryptographicAuthenticator
from agentauth.security.components.input_sanitizer import InputSanitizer
from agentauth.security.components.resource_limiter import ResourceLimiter
from agentauth.security.components.audit_logger import SecurityAuditLogger
from agentauth.security.components.injection_protector import CodeInjectionProtector
from agentauth.security.components.error_handler import SecureErrorHandler
from agentauth.security.components.http_client import SecureHTTPClient
from agentauth.utils.crypto import generate_secure_nonce, secure_wipe_memory, validate_cryptographic_parameters


def get_test_idp_base_url():
    """Get the test IdP base URL from environment variable or use default."""
    return os.getenv("AGENTAUTH_IDP_BASE_URL", "https://test.issuer.com").rstrip('/')


def create_test_client(**kwargs):
    """Helper function to create a test OAuth2OIDCClient with default config."""
    default_config = {
        "idp_name": "Test IdP",
        "idp_endpoint": get_test_idp_base_url(),
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "scope": "test-scope"
    }
    default_config.update(kwargs)
    
    config = ClientConfig(**default_config)
    return OAuth2OIDCClient(config)


class TestBasicFunctionality(unittest.TestCase):
    """Test basic functionality with proper mocking."""
    
    def setUp(self):
        """Set up test fixtures."""
        base_url = get_test_idp_base_url()
        self.mock_oidc_config = {
            "issuer": base_url,
            "token_endpoint": f"{base_url}/oauth2/token",
            "jwks_uri": f"{base_url}/.well-known/jwks.json",
            "authorization_endpoint": f"{base_url}/oauth2/authorize"
        }
        
        self.mock_jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key-1",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "AQAB",
                    "e": "AQAB"
                }
            ]
        }
    
    def test_client_config_initialization(self):
        """Test client configuration initialization without network calls."""
        # Test that ClientConfig can be created properly
        base_url = get_test_idp_base_url()
        config = ClientConfig(
            idp_name="Test IdP",
            idp_endpoint=base_url,
            client_id="test-client-id",
            client_secret="test-client-secret",
            scope="test-scope"
        )
        
        self.assertEqual(config.idp_name, "Test IdP")
        self.assertEqual(config.idp_endpoint, base_url)
        self.assertEqual(config.client_id, "test-client-id")
        self.assertEqual(config.client_secret, "test-client-secret")
        self.assertEqual(config.scope, "test-scope")
    
    def test_exception_classes(self):
        """Test that exception classes can be created."""
        error_message = "Test error message"
        
        with self.assertRaises(OAuth2OIDCError) as context:
            raise OAuth2OIDCError(error_message)
        
        self.assertEqual(str(context.exception), error_message)
        
        with self.assertRaises(SecurityError) as context:
            raise SecurityError(error_message)
        
        self.assertEqual(str(context.exception), error_message)
    
    def test_cryptographic_authenticator(self):
        """Test cryptographic authenticator basic functionality."""
        auth = CryptographicAuthenticator()
        
        # Test HMAC token generation
        data = "test-client-id"
        token = auth.generate_hmac_token(data)
        
        # Token should be in format "signature:timestamp"
        parts = token.split(':')
        self.assertEqual(len(parts), 2)
        self.assertTrue(len(parts[0]) > 0)   # signature
        self.assertTrue(parts[1].isdigit())  # timestamp
        
        # Test HMAC token verification
        result = auth.verify_hmac_token(token, data)
        self.assertTrue(result)
    
    def test_input_sanitizer(self):
        """Test input sanitizer basic functionality."""
        sanitizer = InputSanitizer()
        
        # Test JWT token sanitization
        valid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = sanitizer.sanitize_jwt_token(valid_token)
        self.assertTrue(result)
        
        # Test invalid token
        invalid_token = "invalid-token"
        with self.assertRaises(SecurityError):
            sanitizer.sanitize_jwt_token(invalid_token)
    
    def test_resource_limiter(self):
        """Test resource limiter basic functionality."""
        limiter = ResourceLimiter()
        
        # Test memory usage limiting
        small_data = b"small response"
        result = limiter.limit_memory_usage(small_data)
        self.assertEqual(result, small_data)
        
        # Test rate limiting
        identifier = "test-client"
        try:
            limiter.acquire_request_slot(identifier)
            # If we get here, the slot was acquired successfully
            limiter.release_request_slot()
            success = True
        except SecurityError:
            success = False
        self.assertTrue(success)
    
    def test_audit_logger(self):
        """Test audit logger basic functionality."""
        logger = SecurityAuditLogger()
        
        # Test logging security event
        event_type = "authentication_attempt"
        details = {"client_id": "test-client", "success": True}
        
        # This should not raise an exception
        logger.log_security_event(event_type, details)
        
        # Test getting audit summary
        summary = logger.get_audit_summary()
        self.assertIsInstance(summary, dict)
    
    def test_code_injection_protector(self):
        """Test code injection protector basic functionality."""
        protector = CodeInjectionProtector()
        
        # Test JWK structure validation
        valid_jwk = {
            "kty": "RSA",
            "kid": "test-key",
            "alg": "RS256",
            "use": "sig",
            "n": "test-n",
            "e": "AQAB"
        }
        
        result = protector.validate_jwk_structure(valid_jwk)
        self.assertTrue(result)
        
        # Test invalid JWK
        invalid_jwk = {"invalid": "structure"}
        result = protector.validate_jwk_structure(invalid_jwk)
        self.assertFalse(result)
    
    def test_error_handler(self):
        """Test error handler basic functionality."""
        handler = SecureErrorHandler(enable_debug=False)
        
        # Test error handling
        error = Exception("Test error")
        result = handler.handle_error(error)
        
        self.assertIsInstance(result, dict)
        self.assertIn('error_id', result)
        self.assertIn('error_message', result)
    
    def test_secure_http_client(self):
        """Test secure HTTP client basic functionality."""
        client = SecureHTTPClient()
        
        # Test that client can be created
        self.assertIsNotNone(client)
        self.assertIsNotNone(client.session)
    
    def test_crypto_utilities(self):
        """Test crypto utility functions."""
        # Test secure nonce generation
        nonce = generate_secure_nonce()
        self.assertIsInstance(nonce, str)
        self.assertTrue(len(nonce) > 0)
        
        # Test secure memory wipe
        data = b"test data"
        secure_wipe_memory(data)
        # This should not raise an exception
        
        # Test cryptographic parameter validation
        valid_rsa_params = {
            "kty": "RSA",
            "n": "AQAB",
            "e": "AQAB"
        }
        result = validate_cryptographic_parameters(valid_rsa_params)
        self.assertTrue(result)


class TestJWKConversion(unittest.TestCase):
    """Test JWK to PEM conversion functionality."""
    
    def test_convert_jwk_to_pem_unsupported_key_type(self):
        """Test JWK conversion with unsupported key type."""
        jwk = {
            "kty": "UNSUPPORTED",
            "kid": "test-key",
            "alg": "UNSUPPORTED"
        }
        
        with self.assertRaises(OAuth2OIDCError):
            _convert_jwk_to_pem_standalone(jwk)
    
    def test_convert_jwk_to_pem_unsupported_ec_curve(self):
        """Test JWK conversion with unsupported EC curve."""
        jwk = {
            "kty": "EC",
            "kid": "test-key",
            "crv": "UNSUPPORTED_CURVE",
            "x": "test-x",
            "y": "test-y"
        }
        
        with self.assertRaises(OAuth2OIDCError):
            _convert_jwk_to_pem_standalone(jwk)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestBasicFunctionality,
        TestJWKConversion
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Test Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback}")
    
    # Exit with appropriate code
    if result.failures or result.errors:
        sys.exit(1)
    else:
        sys.exit(0) 