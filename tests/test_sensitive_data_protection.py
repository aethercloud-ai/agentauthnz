#!/usr/bin/env python3
"""
Tests for sensitive data protection features.

This module tests the security features that prevent sensitive data exposure
in logs and error messages.
"""

import unittest
import hashlib
import json
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from agentauth.security.components.audit_logger import SecurityAuditLogger
from agentauth.security.components.error_handler import SecureErrorHandler
from agentauth.security.components.input_sanitizer import InputSanitizer
from agentauth.utils.exceptions import SecurityError


class TestSensitiveDataProtection(unittest.TestCase):
    """Test sensitive data protection features."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.audit_logger = SecurityAuditLogger()
        self.error_handler = SecureErrorHandler(enable_debug=False)
        self.input_sanitizer = InputSanitizer()
    
    def test_jwt_payload_sanitization(self):
        """Test that sensitive JWT claims are properly redacted."""
        # Test payload with sensitive claims
        sensitive_payload = {
            'sub': 'user123',
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'ssn': '123-45-6789',
            'credit_card': '4111-1111-1111-1111',
            'exp': 1735680000,
            'iat': 1735593600,
            'aud': 'test-audience',
            'iss': 'https://example.com'
        }
        
        # Sanitize payload
        sanitized = self.audit_logger.sanitize_jwt_payload(sensitive_payload)
        
        # Verify sensitive claims are redacted
        self.assertEqual(sanitized['sub'], '[REDACTED]')
        self.assertEqual(sanitized['name'], '[REDACTED]')
        self.assertEqual(sanitized['email'], '[REDACTED]')
        self.assertEqual(sanitized['ssn'], '[REDACTED]')
        self.assertEqual(sanitized['credit_card'], '[REDACTED]')
        
        # Verify non-sensitive claims are preserved
        self.assertEqual(sanitized['exp'], 1735680000)
        self.assertEqual(sanitized['iat'], 1735593600)
        self.assertEqual(sanitized['aud'], 'test-audience')
        self.assertEqual(sanitized['iss'], 'https://example.com')
    
    def test_token_hashing(self):
        """Test that tokens are hashed instead of logged in raw form."""
        test_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        # Calculate expected hash
        expected_hash = hashlib.sha256(test_token.encode()).hexdigest()
        
        # Test token validation logging
        with patch.object(self.audit_logger, '_write_log') as mock_write:
            self.audit_logger.log_token_validation(expected_hash, True, {
                'token_type': 'access_token',
                'audience': 'test-audience'
            })
            
            # Verify the log was written
            mock_write.assert_called_once()
            
            # Get the logged event
            call_args = mock_write.call_args[0][0]
            
            # Verify token hash is logged but not raw token
            self.assertIn('details', call_args)
            details = call_args['details']
            self.assertIn('token_hash', details)
            self.assertEqual(details['token_hash'], expected_hash)
            self.assertNotIn('token', call_args)
    
    def test_jwt_payload_access_logging(self):
        """Test that JWT payload access is logged with sanitization."""
        test_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        token_hash = hashlib.sha256(test_token.encode()).hexdigest()
        
        sensitive_payload = {
            'sub': 'user123',
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'exp': 1735680000,
            'aud': 'test-audience'
        }
        
        with patch.object(self.audit_logger, '_write_log') as mock_write:
            self.audit_logger.log_jwt_payload_access(token_hash, sensitive_payload)
            
            # Verify the log was written
            mock_write.assert_called_once()
            
            # Get the logged event
            call_args = mock_write.call_args[0][0]
            
            # Verify sensitive claims are redacted in logged payload
            logged_payload = call_args['details']['payload_claims']
            self.assertEqual(logged_payload['sub'], '[REDACTED]')
            self.assertEqual(logged_payload['name'], '[REDACTED]')
            self.assertEqual(logged_payload['email'], '[REDACTED]')
            
            # Verify non-sensitive claims are preserved
            self.assertEqual(logged_payload['exp'], 1735680000)
            self.assertEqual(logged_payload['aud'], 'test-audience')
    
    def test_secure_error_handling(self):
        """Test that error messages are sanitized to prevent information disclosure."""
        import jwt
        
        # Test JWT-specific errors
        expired_error = jwt.ExpiredSignatureError("Token has expired")
        sanitized = self.error_handler.handle_error(expired_error, "token_validation")
        self.assertIn("Token has expired", sanitized)
        self.assertNotIn("jwt.ExpiredSignatureError", sanitized)
        
        # Test generic errors
        generic_error = Exception("Internal server error with sensitive data")
        sanitized = self.error_handler.handle_error(generic_error, "token_validation")
        self.assertIn("Token validation failed", sanitized)
        self.assertNotIn("Internal server error", sanitized)
    
    def test_input_sanitization(self):
        """Test that input sanitization prevents malicious input."""
        # Test valid JWT token
        valid_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        sanitized = self.input_sanitizer.sanitize_jwt_token(valid_token)
        self.assertEqual(sanitized, valid_token)
        
        # Test malicious input
        malicious_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.<script>alert('xss')</script>"
        with self.assertRaises(SecurityError):
            self.input_sanitizer.sanitize_jwt_token(malicious_token)
    
    def test_audit_log_summary(self):
        """Test that audit log summary includes sensitive data protection metrics."""
        summary = self.audit_logger.get_audit_summary()
        
        # Verify summary includes sensitive data protection metrics
        self.assertIn('jwt_payload_access', summary)
        self.assertIsInstance(summary['jwt_payload_access'], int)
        
        # Verify other security metrics are present
        self.assertIn('token_validations', summary)
        self.assertIn('security_violations', summary)
        self.assertIn('input_validation_failures', summary)
    
    def test_custom_sensitive_fields(self):
        """Test that custom sensitive fields can be configured."""
        # Create audit logger with custom sensitive fields
        custom_audit_logger = SecurityAuditLogger()
        custom_audit_logger.sensitive_jwt_claims.extend(['custom_field', 'internal_data'])
        
        test_payload = {
            'sub': 'user123',
            'custom_field': 'sensitive_value',
            'internal_data': 'confidential',
            'public_field': 'public_value',
            'exp': 1735680000
        }
        
        sanitized = custom_audit_logger.sanitize_jwt_payload(test_payload)
        
        # Verify custom sensitive fields are redacted
        self.assertEqual(sanitized['custom_field'], '[REDACTED]')
        self.assertEqual(sanitized['internal_data'], '[REDACTED]')
        
        # Verify public fields are preserved
        self.assertEqual(sanitized['public_field'], 'public_value')
        self.assertEqual(sanitized['exp'], 1735680000)


if __name__ == '__main__':
    unittest.main() 