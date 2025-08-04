"""
Security configuration for AgentAuth.

This module provides configuration classes for security settings.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class SecurityConfig:
    """Configuration for security features."""
    
    # Security enablement
    enable_security: bool = True
    
    # Input validation limits
    max_token_length: int = 8192
    max_url_length: int = 2048
    max_client_id_length: int = 64
    
    # Resource limits
    max_response_size: int = 1024 * 1024  # 1MB
    max_processing_time: int = 30  # seconds
    max_concurrent_requests: int = 10
    max_request_rate: int = 3000  # requests per minute
    
    # Audit logging
    audit_log_file: Optional[str] = None
    enable_debug: bool = False
    
    # Rate limiting
    rate_limit_per_minute: int = 3000
    
    # TLS settings
    min_tls_version: str = "TLSv1.2"
    verify_ssl: bool = True
    
    def __post_init__(self):
        """Apply environment variable overrides after initialization."""
        # Security enablement
        if os.getenv("AGENTAUTH_DISABLE_SECURITY"):
            self.enable_security = os.getenv("AGENTAUTH_DISABLE_SECURITY").lower() != "true"
        
        # Resource limits
        if os.getenv("AGENTAUTH_MAX_RESPONSE_SIZE"):
            self.max_response_size = int(os.getenv("AGENTAUTH_MAX_RESPONSE_SIZE"))
        
        if os.getenv("AGENTAUTH_MAX_PROCESSING_TIME"):
            self.max_processing_time = int(os.getenv("AGENTAUTH_MAX_PROCESSING_TIME"))
        
        if os.getenv("AGENTAUTH_MAX_CONCURRENT_REQUESTS"):
            self.max_concurrent_requests = int(os.getenv("AGENTAUTH_MAX_CONCURRENT_REQUESTS"))
        
        if os.getenv("AGENTAUTH_RATE_LIMIT_PER_MINUTE"):
            self.rate_limit_per_minute = int(os.getenv("AGENTAUTH_RATE_LIMIT_PER_MINUTE"))
        
        # Audit logging
        if os.getenv("AGENTAUTH_AUDIT_LOG_FILE"):
            self.audit_log_file = os.getenv("AGENTAUTH_AUDIT_LOG_FILE")
        
        if os.getenv("AGENTAUTH_ENABLE_DEBUG"):
            self.enable_debug = os.getenv("AGENTAUTH_ENABLE_DEBUG").lower() == "true"
        
        # TLS settings
        if os.getenv("AGENTAUTH_MIN_TLS_VERSION"):
            self.min_tls_version = os.getenv("AGENTAUTH_MIN_TLS_VERSION")
        
        if os.getenv("AGENTAUTH_VERIFY_SSL"):
            self.verify_ssl = os.getenv("AGENTAUTH_VERIFY_SSL").lower() == "true"


class SecurityBuilder:
    """Builder pattern for creating SecurityConfig instances."""
    
    def __init__(self):
        self.config = SecurityConfig()
    
    def with_security_enabled(self, enabled: bool = True) -> 'SecurityBuilder':
        """Enable or disable security features."""
        self.config.enable_security = enabled
        return self
    
    def with_input_limits(self, max_token_length: int = 8192, 
                         max_url_length: int = 2048, 
                         max_client_id_length: int = 64) -> 'SecurityBuilder':
        """Set input validation limits."""
        self.config.max_token_length = max_token_length
        self.config.max_url_length = max_url_length
        self.config.max_client_id_length = max_client_id_length
        return self
    
    def with_resource_limits(self, max_response_size: int = 1024 * 1024,
                           max_processing_time: int = 30,
                           max_concurrent_requests: int = 10,
                           max_request_rate: int = 3000) -> 'SecurityBuilder':
        """Set resource limits."""
        self.config.max_response_size = max_response_size
        self.config.max_processing_time = max_processing_time
        self.config.max_concurrent_requests = max_concurrent_requests
        self.config.max_request_rate = max_request_rate
        return self
    
    def with_audit_logging(self, audit_log_file: Optional[str] = None,
                          enable_debug: bool = False) -> 'SecurityBuilder':
        """Set audit logging configuration."""
        self.config.audit_log_file = audit_log_file
        self.config.enable_debug = enable_debug
        return self
    
    def with_rate_limiting(self, rate_limit_per_minute: int = 3000) -> 'SecurityBuilder':
        """Set rate limiting configuration."""
        self.config.rate_limit_per_minute = rate_limit_per_minute
        return self
    
    def with_tls_settings(self, min_tls_version: str = "TLSv1.2",
                         verify_ssl: bool = True) -> 'SecurityBuilder':
        """Set TLS configuration."""
        self.config.min_tls_version = min_tls_version
        self.config.verify_ssl = verify_ssl
        return self
    
    def build(self) -> SecurityConfig:
        """Build and return the SecurityConfig instance."""
        return self.config 