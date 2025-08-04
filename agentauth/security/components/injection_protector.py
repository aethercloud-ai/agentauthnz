"""
Code injection protection for AgentAuth.

This module provides protection against code injection attacks and
malicious input that could lead to remote code execution.
"""

import re
import logging
from typing import Dict, Any, List
from ...utils.exceptions import SecurityError

logger = logging.getLogger(__name__)


class CodeInjectionProtector:
    """Protection against code injection attacks."""
    
    def __init__(self):
        # Security. Define allowed key types to prevent malicious code execution
        self.allowed_key_types = {'RSA', 'EC', 'Dilithium', 'Falcon', 'SPHINCS+'}
        
        # Security. Define allowed algorithms to prevent algorithm confusion attacks
        self.allowed_algorithms = {
            'RS256', 'ES256', 'ES384', 'ES512',
            'Dilithium2', 'Dilithium3', 'Dilithium5',
            'Falcon512', 'Falcon1024',
            'SPHINCS+-SHA256-128f-robust'
        }
        
        # Security. Define dangerous patterns that indicate code injection attempts
        self.dangerous_patterns = [
            r'<script', r'javascript:', r'data:', r'vbscript:',
            r'<iframe', r'<object', r'<embed', r'<form',
            r'../', r'..\\', r'%00', r'%0d', r'%0a',
            r'<', r'>', r'"', r"'", r'&',
            r'eval\(', r'exec\(', r'compile\(', r'__import__',
            r'os\.', r'sys\.', r'subprocess\.', r'import\s+',
            r'from\s+.*\s+import', r'globals\(\)', r'locals\('
        ]
        
        # Security. Compile dangerous patterns for efficient matching
        self.dangerous_regex = re.compile('|'.join(self.dangerous_patterns), re.IGNORECASE)
    
    def validate_jwk_structure(self, jwk: Dict) -> bool:
        """
        Security. Validate JWK structure to prevent injection attacks.
        
        Args:
            jwk: JWK dictionary to validate
            
        Returns:
            True if JWK structure is valid and safe
            
        Raises:
            SecurityError: If JWK contains dangerous data
        """
        if not isinstance(jwk, dict):
            logger.warning("Invalid JWK type - expected dict")
            return False
        
        # Security. Check for required fields
        required_fields = ['kty']
        for field in required_fields:
            if field not in jwk:
                logger.warning(f"Missing required JWK field: {field}")
                return False
        
        # Security. Validate key type
        kty = jwk.get('kty')
        if kty not in self.allowed_key_types:
            logger.warning(f"Unsupported key type: {kty}")
            return False
        
        # Security. Validate algorithm if present
        alg = jwk.get('alg')
        if alg and alg not in self.allowed_algorithms:
            logger.warning(f"Unsupported algorithm: {alg}")
            return False
        
        # Security. Validate field types and content
        for key, value in jwk.items():
            if not self._is_safe_value(value):
                logger.warning(f"Dangerous value in JWK field: {key}")
                return False
        
        return True
    
    def sanitize_jwk_data(self, jwk: Dict) -> Dict:
        """
        Security. Sanitize JWK data to prevent code injection.
        
        Args:
            jwk: JWK dictionary to sanitize
            
        Returns:
            Sanitized JWK dictionary
            
        Raises:
            SecurityError: If JWK contains dangerous data
        """
        if not isinstance(jwk, dict):
            raise SecurityError("Invalid JWK type")
        
        sanitized = {}
        
        for key, value in jwk.items():
            if isinstance(value, str):
                # Security. Remove potentially dangerous characters
                sanitized_value = re.sub(r'[<>"\']', '', value)
                
                # Security. Check for dangerous patterns
                if self.dangerous_regex.search(sanitized_value):
                    logger.warning(f"Dangerous pattern detected in JWK field {key}: {sanitized_value}")
                    raise SecurityError(f"Dangerous content detected in JWK field: {key}")
                
                if sanitized_value != value:
                    logger.warning(f"Sanitized potentially dangerous characters in JWK field: {key}")
                
                sanitized[key] = sanitized_value
            else:
                sanitized[key] = value
        
        return sanitized
    
    def validate_token_content(self, token: str) -> bool:
        """
        Security. Validate token content for dangerous patterns.
        
        Args:
            token: Token to validate
            
        Returns:
            True if token content is safe
            
        Raises:
            SecurityError: If token contains dangerous content
        """
        if not isinstance(token, str):
            return False
        
        # Security. Check for dangerous patterns in token
        if self.dangerous_regex.search(token):
            logger.warning("Dangerous pattern detected in token")
            return False
        
        return True
    
    def validate_url_content(self, url: str) -> bool:
        """
        Security. Validate URL content for dangerous patterns.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL content is safe
            
        Raises:
            SecurityError: If URL contains dangerous content
        """
        if not isinstance(url, str):
            return False
        
        # Security. Check for dangerous patterns in URL
        if self.dangerous_regex.search(url):
            logger.warning("Dangerous pattern detected in URL")
            return False
        
        return True
    
    def _is_safe_value(self, value: Any) -> bool:
        """
        Security. Check if value is safe from code injection.
        
        Args:
            value: Value to check
            
        Returns:
            True if value is safe
        """
        if isinstance(value, (int, float, bool)):
            return True
        elif isinstance(value, str):
            # Security. Check string for dangerous patterns
            return not self.dangerous_regex.search(value)
        elif isinstance(value, list):
            # Security. Check all list items
            return all(self._is_safe_value(item) for item in value)
        elif isinstance(value, dict):
            # Security. Check all dict values
            return all(self._is_safe_value(v) for v in value.values())
        else:
            # Security. Reject unknown types
            return False
    
    def validate_algorithm_name(self, algorithm: str) -> bool:
        """
        Security. Validate algorithm name to prevent algorithm confusion attacks.
        
        Args:
            algorithm: Algorithm name to validate
            
        Returns:
            True if algorithm is allowed
        """
        if not isinstance(algorithm, str):
            return False
        
        # Security. Check if algorithm is in allowed list
        if algorithm not in self.allowed_algorithms:
            logger.warning(f"Unsupported algorithm: {algorithm}")
            return False
        
        # Security. Check for dangerous patterns in algorithm name
        if self.dangerous_regex.search(algorithm):
            logger.warning(f"Dangerous pattern in algorithm name: {algorithm}")
            return False
        
        return True
    
    def validate_key_type(self, key_type: str) -> bool:
        """
        Security. Validate key type to prevent malicious key type injection.
        
        Args:
            key_type: Key type to validate
            
        Returns:
            True if key type is allowed
        """
        if not isinstance(key_type, str):
            return False
        
        # Security. Check if key type is in allowed list
        if key_type not in self.allowed_key_types:
            logger.warning(f"Unsupported key type: {key_type}")
            return False
        
        # Security. Check for dangerous patterns in key type
        if self.dangerous_regex.search(key_type):
            logger.warning(f"Dangerous pattern in key type: {key_type}")
            return False
        
        return True
    
    def get_allowed_algorithms(self) -> List[str]:
        """
        Security. Get list of allowed algorithms for validation.
        
        Returns:
            List of allowed algorithm names
        """
        return list(self.allowed_algorithms)
    
    def get_allowed_key_types(self) -> List[str]:
        """
        Security. Get list of allowed key types for validation.
        
        Returns:
            List of allowed key type names
        """
        return list(self.allowed_key_types) 