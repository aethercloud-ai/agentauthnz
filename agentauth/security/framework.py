"""
Unified security framework for AgentAuth.

This module provides a unified security framework that coordinates all security components.
"""

import logging
from typing import Optional
from ..config import SecurityConfig
from .components.input_sanitizer import InputSanitizer
from .components.audit_logger import SecurityAuditLogger
from .components.resource_limiter import ResourceLimiter
from .components.injection_protector import CodeInjectionProtector
from .components.error_handler import SecureErrorHandler
from .authenticator import SecureTokenValidator

logger = logging.getLogger(__name__)


class SecurityFramework:
    """
    Unified security framework that coordinates all security components.
    
    This class provides a single interface for all security operations,
    ensuring consistent security policies across the application.
    """
    
    def __init__(self, config: SecurityConfig):
        """
        Initialize the security framework with configuration.
        
        Args:
            config: Security configuration object
        """
        self.config = config
        
        # Initialize security components
        self.sanitizer = InputSanitizer()
        self.audit_logger = SecurityAuditLogger(config.audit_log_file)
        self.resource_limiter = ResourceLimiter()
        self.injection_protector = CodeInjectionProtector()
        self.error_handler = SecureErrorHandler(config.enable_debug)
        self.validator = SecureTokenValidator()
        
        # Configure components with security settings
        self._configure_components()
        
        logger.info("Security framework initialized")
    
    def _configure_components(self):
        """Configure security components with settings from config."""
        # Configure resource limiter
        self.resource_limiter.max_response_size = self.config.max_response_size
        self.resource_limiter.max_processing_time = self.config.max_processing_time
        self.resource_limiter.max_concurrent_requests = self.config.max_concurrent_requests
        self.resource_limiter.max_request_rate = self.config.max_request_rate
        
        # Configure input sanitizer
        self.sanitizer.max_token_length = self.config.max_token_length
        self.sanitizer.max_url_length = self.config.max_url_length
        self.sanitizer.max_client_id_length = self.config.max_client_id_length
        
        logger.debug("Security components configured")
    
    def validate_input(self, input_type: str, value: str) -> str:
        """
        Validate and sanitize input based on type.
        
        Args:
            input_type: Type of input ('token', 'url', 'client_id', 'jwk')
            value: Input value to validate
            
        Returns:
            Sanitized input value
            
        Raises:
            SecurityError: If input validation fails
        """
        try:
            if input_type == 'token':
                return self.sanitizer.sanitize_jwt_token(value)
            elif input_type == 'url':
                return self.sanitizer.sanitize_url(value)
            elif input_type == 'client_id':
                return self.sanitizer.sanitize_client_id(value)
            elif input_type == 'jwk':
                return self.sanitizer.sanitize_jwk(value)
            else:
                raise ValueError(f"Unknown input type: {input_type}")
                
        except Exception as e:
            self.audit_logger.log_input_validation_failure(input_type, str(e), value)
            raise
    
    def log_security_event(self, event_type: str, details: dict, severity: str = 'INFO'):
        """
        Log a security event.
        
        Args:
            event_type: Type of security event
            details: Event details
            severity: Severity level
        """
        self.audit_logger.log_security_event(event_type, details, severity)
    
    def handle_error(self, error: Exception, context: str = None) -> str:
        """
        Handle errors securely.
        
        Args:
            error: Exception to handle
            context: Additional context
            
        Returns:
            Sanitized error message
        """
        return self.error_handler.handle_error(error, context)
    
    def acquire_resource_slot(self, client_id: str = None):
        """
        Acquire a resource slot for rate limiting.
        
        Args:
            client_id: Client identifier
        """
        self.resource_limiter.acquire_request_slot(client_id)
    
    def release_resource_slot(self):
        """Release a resource slot."""
        self.resource_limiter.release_request_slot()
    
    def validate_token_secure(self, token: str, jwks: dict, **kwargs) -> dict:
        """
        Validate token with enhanced security.
        
        Args:
            token: JWT token to validate
            jwks: JWKS dictionary
            **kwargs: Additional validation parameters
            
        Returns:
            Token payload
        """
        return self.validator.validate_token_secure(token, jwks, **kwargs)
    
    def validate_jwk_structure(self, jwk: dict) -> bool:
        """
        Validate JWK structure for security.
        
        Args:
            jwk: JWK dictionary to validate
            
        Returns:
            True if JWK structure is valid
        """
        return self.injection_protector.validate_jwk_structure(jwk)
    
    def sanitize_jwt_payload(self, payload: dict) -> dict:
        """
        Sanitize JWT payload to remove sensitive information.
        
        Args:
            payload: JWT payload to sanitize
            
        Returns:
            Sanitized payload
        """
        return self.audit_logger.sanitize_jwt_payload(payload)
    
    def get_resource_usage_stats(self) -> dict:
        """
        Get resource usage statistics.
        
        Returns:
            Resource usage statistics
        """
        return self.resource_limiter.get_resource_usage_stats()
    
    def cleanup_expired_entries(self):
        """Clean up expired entries in security components."""
        self.resource_limiter.cleanup_expired_entries()
    
    def is_security_enabled(self) -> bool:
        """
        Check if security features are enabled.
        
        Returns:
            True if security is enabled
        """
        return self.config.enable_security 