"""
Advanced security audit logging for AgentAuth.

This module provides comprehensive security event logging for monitoring,
analysis, and compliance purposes.
"""

import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from ...utils.exceptions import SecurityError

logger = logging.getLogger(__name__)


class SecurityAuditLogger:
    """Advanced security audit logging."""
    
    def __init__(self, log_file: str = None):
        # Security. Configure audit logging
        self.log_file = log_file
        self.sensitive_fields = ['token', 'secret', 'password', 'key', 'private_key', 'signature']
        
        # Security. Define sensitive JWT claims that should be redacted
        self.sensitive_jwt_claims = [
            'sub', 'name', 'email', 'phone_number', 'address', 'ssn', 'credit_card',
            'password', 'secret', 'private_key', 'api_key', 'access_token', 'refresh_token',
            'id_token', 'user_id', 'employee_id', 'customer_id', 'account_number',
            'social_security', 'tax_id', 'passport', 'driver_license', 'medical_info',
            'financial_info', 'personal_data', 'confidential', 'restricted', 'internal'
        ]
        
        # Security. Initialize audit log format
        self.audit_logger = logging.getLogger('agentauth.audit')
        if log_file:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            self.audit_logger.addHandler(handler)
            self.audit_logger.setLevel(logging.INFO)
    
    def sanitize_jwt_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Security. Sanitize JWT payload to remove sensitive claims.
        
        Args:
            payload: JWT payload to sanitize
            
        Returns:
            Sanitized JWT payload with sensitive claims redacted
        """
        sanitized = {}
        
        for key, value in payload.items():
            # Security. Check if claim contains sensitive information
            if any(sensitive in key.lower() for sensitive in self.sensitive_jwt_claims):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, str) and any(sensitive in value.lower() for sensitive in self.sensitive_jwt_claims):
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = value
        
        return sanitized
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], 
                          severity: str = 'INFO', user_id: str = None):
        """
        Security. Log security events with sanitization.
        
        Args:
            event_type: Type of security event
            details: Event details
            severity: Severity level
            user_id: User identifier
        """
        # Security. Create audit event with sanitized data
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'user_id': user_id,
            'session_id': self._get_session_id(),
            'ip_address': self._get_client_ip(),
            'details': self._sanitize_details(details)
        }
        
        # Security. Hash sensitive data for correlation without storing raw data
        if 'token' in details:
            event['token_hash'] = hashlib.sha256(details['token'].encode()).hexdigest()
        
        if 'secret' in details:
            event['secret_hash'] = hashlib.sha256(details['secret'].encode()).hexdigest()
        
        # Security. Write audit log
        self._write_log(event)
    
    def log_authentication_attempt(self, client_id: str, success: bool, 
                                 failure_reason: str = None):
        """
        Security. Log authentication attempts for monitoring and analysis.
        
        Args:
            client_id: Client identifier
            success: Whether authentication succeeded
            failure_reason: Reason for failure if applicable
        """
        details = {
            'client_id': client_id,
            'success': success,
            'failure_reason': failure_reason
        }
        
        # Security. Set appropriate severity based on success
        severity = 'WARNING' if not success else 'INFO'
        self.log_security_event('authentication_attempt', details, severity, client_id)
    
    def log_token_validation(self, token_hash: str, success: bool, 
                           validation_details: Dict[str, Any]):
        """
        Security. Log token validation events for security monitoring.
        
        Args:
            token_hash: Hash of the token being validated
            success: Whether validation succeeded
            validation_details: Additional validation details
        """
        details = {
            'token_hash': token_hash,
            'success': success,
            'validation_details': validation_details
        }
        
        # Security. Set appropriate severity based on success
        severity = 'WARNING' if not success else 'INFO'
        self.log_security_event('token_validation', details, severity)
    
    def log_jwt_payload_access(self, token_hash: str, payload_claims: Dict[str, Any]):
        """
        Security. Log JWT payload access for audit trail.
        
        Args:
            token_hash: Hash of the token
            payload_claims: JWT payload claims that were accessed
        """
        # Security. Sanitize payload claims before logging
        sanitized_claims = self.sanitize_jwt_payload(payload_claims)
        
        details = {
            'token_hash': token_hash,
            'payload_claims': sanitized_claims,
            'access_type': 'payload_inspection'
        }
        
        self.log_security_event('jwt_payload_access', details, 'INFO')
    
    def log_rate_limit_violation(self, client_id: str, request_count: int):
        """
        Security. Log rate limit violations for threat detection.
        
        Args:
            client_id: Client identifier
            request_count: Number of requests in violation
        """
        details = {
            'client_id': client_id,
            'request_count': request_count,
            'limit_exceeded': True
        }
        
        self.log_security_event('rate_limit_violation', details, 'WARNING', client_id)
    
    def log_security_violation(self, violation_type: str, details: Dict[str, Any],
                             severity: str = 'ERROR'):
        """
        Security. Log security violations for incident response.
        
        Args:
            violation_type: Type of security violation
            details: Violation details
            severity: Severity level
        """
        details['violation_type'] = violation_type
        self.log_security_event('security_violation', details, severity)
    
    def log_input_validation_failure(self, input_type: str, reason: str, 
                                   suspicious_content: str = None):
        """
        Security. Log input validation failures for attack detection.
        
        Args:
            input_type: Type of input that failed validation
            reason: Reason for validation failure
            suspicious_content: Suspicious content detected
        """
        details = {
            'input_type': input_type,
            'reason': reason,
            'suspicious_content': suspicious_content
        }
        
        self.log_security_event('input_validation_failure', details, 'WARNING')
    
    def log_resource_limit_exceeded(self, resource_type: str, limit: int, 
                                  actual: int, client_id: str = None):
        """
        Security. Log resource limit violations for DoS detection.
        
        Args:
            resource_type: Type of resource that exceeded limit
            limit: Resource limit
            actual: Actual resource usage
            client_id: Client identifier if applicable
        """
        details = {
            'resource_type': resource_type,
            'limit': limit,
            'actual': actual,
            'exceeded_by': actual - limit
        }
        
        self.log_security_event('resource_limit_exceeded', details, 'WARNING', client_id)
    
    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Security. Sanitize sensitive information from audit logs.
        
        Args:
            details: Details to sanitize
            
        Returns:
            Sanitized details
        """
        sanitized = {}
        
        for key, value in details.items():
            # Security. Check if field contains sensitive information
            # Allow token_hash as it's already a hash, not raw token data
            if key == 'token_hash':
                sanitized[key] = value  # Keep token hash as-is
            elif any(sensitive in key.lower() for sensitive in self.sensitive_fields):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, str) and any(sensitive in value.lower() for sensitive in self.sensitive_fields):
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _get_session_id(self) -> str:
        """
        Security. Get current session ID for audit correlation.
        
        Returns:
            Session identifier
        """
        # Security. Implementation depends on web framework
        # For now, return placeholder
        return "session_id_placeholder"
    
    def _get_client_ip(self) -> str:
        """
        Security. Get client IP address for audit correlation.
        
        Returns:
            Client IP address
        """
        # Security. Implementation depends on web framework
        # For now, return placeholder
        return "ip_placeholder"
    
    def _write_log(self, event: Dict[str, Any]):
        """
        Security. Write audit log entry.
        
        Args:
            event: Audit event to log
        """
        # Security. Format log entry as JSON for structured logging
        log_entry = json.dumps(event) + '\n'
        
        # Security. Write to file if configured
        if self.log_file:
            try:
                with open(self.log_file, 'a') as f:
                    f.write(log_entry)
            except Exception as e:
                logger.error(f"Failed to write to audit log file: {e}")
        
        # Security. Also log to standard logger for monitoring
        self.audit_logger.info(f"Security Event: {event['event_type']} - {event['severity']}")
    
    def get_audit_summary(self, time_window_minutes: int = 60) -> Dict[str, Any]:
        """
        Security. Get audit summary for security monitoring.
        
        Args:
            time_window_minutes: Time window for summary
            
        Returns:
            Audit summary statistics
        """
        # Security. This would typically query the audit log database
        # For now, return placeholder summary
        return {
            'time_window_minutes': time_window_minutes,
            'total_events': 0,
            'authentication_attempts': 0,
            'failed_authentications': 0,
            'token_validations': 0,
            'failed_validations': 0,
            'rate_limit_violations': 0,
            'security_violations': 0,
            'input_validation_failures': 0,
            'resource_limit_exceeded': 0,
            'jwt_payload_access': 0
        }
    
    def _hash_sensitive_data(self, data: str) -> str:
        """
        Security. Hash sensitive data for correlation without storing raw data.
        
        Args:
            data: Sensitive data to hash
            
        Returns:
            SHA-256 hash of the data
        """
        return hashlib.sha256(data.encode()).hexdigest() 