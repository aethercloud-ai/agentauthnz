"""
Enhanced input validation and sanitization for AgentAuth.

This module provides comprehensive input sanitization to prevent injection attacks,
SSRF attacks, and other malicious input-based vulnerabilities.
"""

import re
import urllib.parse
import logging
from typing import Optional
from ...utils.exceptions import SecurityError

logger = logging.getLogger(__name__)


class InputSanitizer:
    """Enhanced input validation and sanitization."""
    
    def __init__(self):
        # Security. Define allowed patterns for JWT tokens, URLs, and client IDs
        self.jwt_pattern = re.compile(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$')
        self.url_pattern = re.compile(r'^https://[A-Za-z0-9\-\.]+\.[A-Za-z]{2,}(:[0-9]+)?(/.*)?$')
        self.client_id_pattern = re.compile(r'^[A-Za-z0-9\-_]{1,64}$')
        
        # Security. Define size limits to prevent memory exhaustion attacks
        self.max_token_length = 8192  # 8KB limit
        self.max_url_length = 2048
        self.max_client_id_length = 64
        
        # Security. Define suspicious patterns that indicate potential attacks
        self.suspicious_patterns = [
            r'<script', r'javascript:', r'data:', r'vbscript:',
            r'<iframe', r'<object', r'<embed', r'<form',
            r'../', r'..\\', r'%00', r'%0d', r'%0a',
            r'<', r'>', r'"', r"'", r'&'
        ]
        
        # Security. Define dangerous hosts for SSRF protection
        self.dangerous_hosts = [
            'localhost', '127.0.0.1', '0.0.0.0', '::1',
            '169.254.169.254',  # AWS metadata
            '169.254.170.2',    # ECS metadata
            'fd00:ec2::254',    # AWS metadata IPv6
            '10.0.0.0/8',      # Private networks
            '172.16.0.0/12',   # Private networks
            '192.168.0.0/16'   # Private networks
        ]
    
    def sanitize_jwt_token(self, token: str) -> str:
        """
        Security. Sanitize and validate JWT token to prevent injection attacks.
        
        Args:
            token: JWT token to sanitize
            
        Returns:
            Sanitized token
            
        Raises:
            SecurityError: If token is invalid or contains suspicious patterns
        """
        if not token or not isinstance(token, str):
            raise SecurityError("Invalid token type")
        
        # Security. Check length to prevent memory exhaustion
        if len(token) > self.max_token_length:
            raise SecurityError("Token too long")
        
        # Security. Validate JWT format
        if not self.jwt_pattern.match(token):
            raise SecurityError("Invalid JWT format")
        
        # Security. Check for suspicious patterns that indicate injection attempts
        if self._contains_suspicious_patterns(token):
            raise SecurityError("Token contains suspicious patterns")
        
        return token.strip()
    
    def sanitize_url(self, url: str) -> str:
        """
        Security. Sanitize and validate URLs to prevent SSRF attacks.
        
        Args:
            url: URL to sanitize
            
        Returns:
            Sanitized URL
            
        Raises:
            SecurityError: If URL is invalid or potentially dangerous
        """
        if not url or not isinstance(url, str):
            raise SecurityError("Invalid URL type")
        
        # Security. Check length to prevent buffer overflow
        if len(url) > self.max_url_length:
            raise SecurityError("URL too long")
        
        # Security. Validate URL format
        if not self.url_pattern.match(url):
            raise SecurityError("Invalid URL format")
        
        # Security. Prevent SSRF attacks by checking for dangerous hosts
        if self._is_ssrf_vulnerable(url):
            raise SecurityError("URL potentially vulnerable to SSRF")
        
        return url.strip()
    
    def sanitize_client_id(self, client_id: str) -> str:
        """
        Security. Sanitize and validate client IDs to prevent injection attacks.
        
        Args:
            client_id: Client ID to sanitize
            
        Returns:
            Sanitized client ID
            
        Raises:
            SecurityError: If client ID is invalid
        """
        if not client_id or not isinstance(client_id, str):
            raise SecurityError("Invalid client ID type")
        
        # Security. Check length to prevent buffer overflow
        if len(client_id) > self.max_client_id_length:
            raise SecurityError("Client ID too long")
        
        # Security. Validate client ID format
        if not self.client_id_pattern.match(client_id):
            raise SecurityError("Invalid client ID format")
        
        return client_id.strip()
    
    def sanitize_jwk(self, jwk: dict) -> dict:
        """
        Security. Sanitize JWK data to prevent code injection attacks.
        
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
                if sanitized_value != value:
                    logger.warning(f"Sanitized potentially dangerous characters in JWK field: {key}")
                sanitized[key] = sanitized_value
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _contains_suspicious_patterns(self, token: str) -> bool:
        """
        Security. Check for suspicious patterns that indicate injection attempts.
        
        Args:
            token: Token to check
            
        Returns:
            True if suspicious patterns are found
        """
        for pattern in self.suspicious_patterns:
            if re.search(pattern, token, re.IGNORECASE):
                logger.warning(f"Suspicious pattern detected in token: {pattern}")
                return True
        
        return False
    
    def _is_ssrf_vulnerable(self, url: str) -> bool:
        """
        Security. Check for SSRF vulnerabilities in URLs.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is potentially vulnerable to SSRF
        """
        try:
            parsed_url = urllib.parse.urlparse(url)
            host = parsed_url.hostname.lower() if parsed_url.hostname else ""
            
            # Security. Check for dangerous hosts
            for dangerous_host in self.dangerous_hosts:
                if host == dangerous_host or host.endswith(f'.{dangerous_host}'):
                    logger.warning(f"SSRF vulnerable URL detected: {url}")
                    return True
            
            # Security. Check for private IP ranges
            if self._is_private_ip(host):
                logger.warning(f"Private IP detected in URL: {url}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error parsing URL for SSRF check: {e}")
            return True  # Fail secure
    
    def _is_private_ip(self, host: str) -> bool:
        """
        Security. Check if host is a private IP address.
        
        Args:
            host: Host to check
            
        Returns:
            True if host is a private IP
        """
        try:
            # Simple check for common private IP patterns
            if host.startswith(('10.', '172.', '192.168.')):
                return True
            return False
        except Exception:
            return False 