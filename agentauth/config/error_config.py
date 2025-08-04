"""
Error handling configuration for AgentAuth.

This module provides configuration classes for error handling settings.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class ErrorConfig:
    """Configuration for error handling."""
    
    # Error handling mode
    enable_debug: bool = False
    
    # Error message sanitization
    sanitize_error_messages: bool = True
    
    # Error logging
    log_error_details: bool = True
    error_log_file: Optional[str] = None
    
    # Error correlation
    generate_error_ids: bool = True
    
    # Security violation reporting
    report_security_violations: bool = True
    
    def __post_init__(self):
        """Apply environment variable overrides after initialization."""
        if os.getenv("AGENTAUTH_ENABLE_DEBUG"):
            self.enable_debug = os.getenv("AGENTAUTH_ENABLE_DEBUG").lower() == "true"
        
        if os.getenv("AGENTAUTH_SANITIZE_ERROR_MESSAGES"):
            self.sanitize_error_messages = os.getenv("AGENTAUTH_SANITIZE_ERROR_MESSAGES").lower() == "true"
        
        if os.getenv("AGENTAUTH_LOG_ERROR_DETAILS"):
            self.log_error_details = os.getenv("AGENTAUTH_LOG_ERROR_DETAILS").lower() == "true"
        
        if os.getenv("AGENTAUTH_ERROR_LOG_FILE"):
            self.error_log_file = os.getenv("AGENTAUTH_ERROR_LOG_FILE")
        
        if os.getenv("AGENTAUTH_GENERATE_ERROR_IDS"):
            self.generate_error_ids = os.getenv("AGENTAUTH_GENERATE_ERROR_IDS").lower() == "true"
        
        if os.getenv("AGENTAUTH_REPORT_SECURITY_VIOLATIONS"):
            self.report_security_violations = os.getenv("AGENTAUTH_REPORT_SECURITY_VIOLATIONS").lower() == "true"


class ErrorConfigBuilder:
    """Builder pattern for creating ErrorConfig instances."""
    
    def __init__(self):
        self.config = ErrorConfig()
    
    def with_debug_enabled(self, enabled: bool = True) -> 'ErrorConfigBuilder':
        """Enable or disable debug mode."""
        self.config.enable_debug = enabled
        return self
    
    def with_error_sanitization(self, sanitize: bool = True) -> 'ErrorConfigBuilder':
        """Enable or disable error message sanitization."""
        self.config.sanitize_error_messages = sanitize
        return self
    
    def with_error_logging(self, log_details: bool = True,
                          error_log_file: Optional[str] = None) -> 'ErrorConfigBuilder':
        """Configure error logging."""
        self.config.log_error_details = log_details
        self.config.error_log_file = error_log_file
        return self
    
    def with_error_correlation(self, generate_ids: bool = True) -> 'ErrorConfigBuilder':
        """Enable or disable error ID generation."""
        self.config.generate_error_ids = generate_ids
        return self
    
    def with_security_reporting(self, report_violations: bool = True) -> 'ErrorConfigBuilder':
        """Enable or disable security violation reporting."""
        self.config.report_security_violations = report_violations
        return self
    
    def build(self) -> ErrorConfig:
        """Build and return the ErrorConfig instance."""
        return self.config 