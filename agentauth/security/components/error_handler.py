"""
Secure error handling for AgentAuth.

This module provides secure error handling to prevent information disclosure
while maintaining detailed logging for debugging and security analysis.
"""

import time
import traceback
import secrets
import logging
from typing import Optional, Dict, Any
import jwt
from ...utils.exceptions import SecurityError

logger = logging.getLogger(__name__)


class SecureErrorHandler:
    """Secure error handling to prevent information disclosure."""
    
    def __init__(self, enable_debug: bool = False):
        # Security. Configure error handling mode
        self.enable_debug = enable_debug
        
        # Security. Define sanitized error messages to prevent information disclosure
        self.error_messages = {
            'invalid_token': 'Token validation failed',
            'expired_token': 'Token has expired',
            'invalid_signature': 'Invalid token signature',
            'invalid_audience': 'Invalid token audience',
            'invalid_issuer': 'Invalid token issuer',
            'rate_limit_exceeded': 'Rate limit exceeded',
            'authentication_failed': 'Authentication failed',
            'network_error': 'Network communication error',
            'cryptographic_error': 'Cryptographic operation failed',
            'input_validation_error': 'Invalid input provided',
            'resource_limit_error': 'Resource limit exceeded',
            'security_violation': 'Security policy violation',
            'ssrf_vulnerability': 'URL validation failed',
            'injection_attempt': 'Malicious input detected'
        }
    
    def handle_error(self, error: Exception, context: str = None) -> str:
        """
        Security. Handle errors securely without information disclosure.
        
        Args:
            error: Exception to handle
            context: Additional context for logging
            
        Returns:
            Error ID string for tracking
        """
        # Security. Generate unique error ID for tracking
        error_id = self._generate_error_id()
        
        # Security. Log full error details internally for debugging
        self._log_error_details(error, context, error_id)
        
        # Security. Return only the error ID to prevent information disclosure
        return error_id
    
    def get_error_details(self, error: Exception, context: str = None) -> Dict[str, Any]:
        """
        Security. Get detailed error information for internal use.
        
        Args:
            error: Exception to handle
            context: Additional context for logging
            
        Returns:
            Dictionary containing error information
        """
        # Security. Generate unique error ID for tracking
        error_id = self._generate_error_id()
        
        # Security. Log full error details internally for debugging
        self._log_error_details(error, context, error_id)
        
        # Security. Return sanitized error information to prevent information disclosure
        return {
            'error_id': error_id,
            'error_type': type(error).__name__,
            'error_message': self._get_sanitized_message(error),
            'context': context,
            'timestamp': time.time()
        }
    
    def _generate_error_id(self) -> str:
        """
        Security. Generate unique error ID for tracking and correlation.
        
        Returns:
            Unique error identifier
        """
        return secrets.token_hex(8)
    
    def _log_error_details(self, error: Exception, context: str, error_id: str):
        """
        Security. Log detailed error information for debugging and security analysis.
        
        Args:
            error: Exception that occurred
            context: Additional context
            error_id: Unique error identifier
        """
        error_details = {
            'error_id': error_id,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context,
            'timestamp': time.time(),
            'traceback': traceback.format_exc() if self.enable_debug else None
        }
        
        # Security. Log error details for security monitoring
        logger.error(f"Error ID {error_id}: {error_details}")
    
    def _get_sanitized_message(self, error: Exception) -> str:
        """
        Security. Get sanitized error message to prevent information disclosure.
        
        Args:
            error: Exception to sanitize
            
        Returns:
            Sanitized error message
        """
        # Security. Map specific JWT errors to sanitized messages
        if isinstance(error, jwt.ExpiredSignatureError):
            return self.error_messages['expired_token']
        elif isinstance(error, jwt.InvalidSignatureError):
            return self.error_messages['invalid_signature']
        elif isinstance(error, jwt.InvalidAudienceError):
            return self.error_messages['invalid_audience']
        elif isinstance(error, jwt.InvalidIssuerError):
            return self.error_messages['invalid_issuer']
        elif isinstance(error, jwt.InvalidTokenError):
            return self.error_messages['invalid_token']
        
        # Security. Map SecurityError messages (already sanitized)
        elif isinstance(error, SecurityError):
            return str(error)
        
        # Security. Map other common error types
        elif 'rate limit' in str(error).lower():
            return self.error_messages['rate_limit_exceeded']
        elif 'authentication' in str(error).lower():
            return self.error_messages['authentication_failed']
        elif 'network' in str(error).lower() or 'connection' in str(error).lower():
            return self.error_messages['network_error']
        elif 'cryptographic' in str(error).lower() or 'crypto' in str(error).lower():
            return self.error_messages['cryptographic_error']
        elif 'input' in str(error).lower() or 'validation' in str(error).lower():
            return self.error_messages['input_validation_error']
        elif 'resource' in str(error).lower() or 'limit' in str(error).lower():
            return self.error_messages['resource_limit_error']
        elif 'ssrf' in str(error).lower():
            return self.error_messages['ssrf_vulnerability']
        elif 'injection' in str(error).lower() or 'malicious' in str(error).lower():
            return self.error_messages['injection_attempt']
        
        # Security. Default to generic error message
        else:
            return self.error_messages['invalid_token']
    
    def log_security_violation(self, violation_type: str, details: Dict[str, Any], 
                              severity: str = 'WARNING'):
        """
        Security. Log security violations for monitoring and analysis.
        
        Args:
            violation_type: Type of security violation
            details: Additional details about the violation
            severity: Severity level of the violation
        """
        violation_log = {
            'timestamp': time.time(),
            'violation_type': violation_type,
            'severity': severity,
            'details': details,
            'error_id': self._generate_error_id()
        }
        
        # Security. Log security violations for monitoring
        if severity == 'ERROR':
            logger.error(f"Security violation: {violation_log}")
        elif severity == 'WARNING':
            logger.warning(f"Security violation: {violation_log}")
        else:
            logger.info(f"Security violation: {violation_log}")
    
    def sanitize_exception_for_logging(self, error: Exception) -> Dict[str, Any]:
        """
        Security. Sanitize exception details for safe logging.
        
        Args:
            error: Exception to sanitize
            
        Returns:
            Sanitized exception details
        """
        return {
            'error_type': type(error).__name__,
            'error_message': self._get_sanitized_message(error),
            'timestamp': time.time()
        } 