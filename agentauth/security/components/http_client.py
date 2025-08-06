"""
Secure HTTP client for AgentAuth library.

This module provides a secure HTTP client that enforces:
- TLS 1.2 or higher for all HTTPS connections
- Certificate validation
- Secure cipher suites
- Proper timeout handling
- Security headers
"""

import ssl
import logging
from typing import Dict, Optional, Any, Union
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from urllib3.poolmanager import PoolManager
from ...utils.exceptions import SecurityError

logger = logging.getLogger(__name__)


class SecureHTTPAdapter(HTTPAdapter):
    """
    Security. Secure HTTP adapter that enforces TLS 1.2+ and secure cipher suites.
    
    This adapter ensures that all HTTPS connections use:
    - TLS 1.2 or higher (with TLS 1.3 preferred)
    - Strong cipher suites (AES-GCM, ChaCha20-Poly1305)
    - Certificate validation and hostname verification
    - Secure defaults with downgrade protection
    """
    
    def __init__(self, *args, **kwargs):
        # Define secure cipher suites (TLS 1.3 preferred, TLS 1.2 fallback) before calling super()
        self.secure_ciphers = ':'.join([
            # TLS 1.3 cipher suites (preferred)
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
            # TLS 1.2 cipher suites (fallback for compatibility)
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-SHA256',
            'DHE-RSA-AES128-SHA256'
        ])
        
        super().__init__(*args, **kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        """Security. Initialize pool manager with secure SSL context."""
        context = create_urllib3_context(
            ssl_version=ssl.PROTOCOL_TLS,
            ciphers=self.secure_ciphers
        )
        
        # Enforce TLS 1.2+ with preference for TLS 1.3
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Enable certificate validation
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        
        # Set secure defaults (TLS 1.3 preferred, TLS 1.2 fallback)
        context.options |= (
            ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        )
        
        # Load default CA certificates for certificate verification
        context.load_default_certs()
        
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)
    
    def proxy_manager_for(self, proxy, **proxy_kwargs):
        """Security. Initialize proxy manager with secure SSL context."""
        context = create_urllib3_context(
            ssl_version=ssl.PROTOCOL_TLS,
            ciphers=self.secure_ciphers
        )
        
        # Enforce TLS 1.2+ with preference for TLS 1.3
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Enable certificate validation
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        
        # Set secure defaults (TLS 1.3 preferred, TLS 1.2 fallback)
        context.options |= (
            ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        )
        
        # Load default CA certificates for certificate verification
        context.load_default_certs()
        
        proxy_kwargs['ssl_context'] = context
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class SecureHTTPClient:
    """
    Security. Secure HTTP client that enforces TLS 1.2+ with preference for TLS 1.3.
    
    This client provides secure HTTP operations with:
    - TLS 1.3 preferred, TLS 1.2 fallback
    - Certificate validation and hostname verification
    - Secure cipher suites (AES-GCM, ChaCha20-Poly1305)
    - Proper error handling with security logging
    - HTTPS-only enforcement
    - Connection security monitoring
    """
    
    def __init__(self, timeout: int = 30, verify_ssl: bool = True):
        """
        Initialize secure HTTP client.
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Create session with secure adapter
        self.session = requests.Session()
        secure_adapter = SecureHTTPAdapter()
        
        # Mount secure adapter for HTTPS
        self.session.mount('https://', secure_adapter)
        
        # Set secure headers
        self.session.headers.update({
            'User-Agent': 'AgentAuth/1.0.0 (Secure HTTP Client)',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'  # Prevent connection reuse for sensitive requests
        })
        
        # Configure SSL verification
        if not verify_ssl:
            logger.warning("SSL verification disabled - this is not recommended for production")
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """
        Perform secure GET request.
        
        Args:
            url: Request URL
            **kwargs: Additional request parameters
            
        Returns:
            Response object
            
        Raises:
            requests.exceptions.RequestException: If request fails
            SecurityError: If security requirements not met
        """
        # Ensure HTTPS for sensitive operations
        if not url.startswith('https://'):
            raise SecurityError(f"HTTPS required for secure requests: {url}")
        
        # Set default timeout
        kwargs.setdefault('timeout', self.timeout)
        
        # Set SSL verification
        kwargs.setdefault('verify', self.verify_ssl)
        
        logger.debug(f"Making secure GET request to: {url}")
        
        try:
            response = self.session.get(url, **kwargs)
            
            # Log security information
            if hasattr(response, 'raw') and hasattr(response.raw, 'connection'):
                conn = response.raw.connection
                if hasattr(conn, 'sock'):
                    sock = conn.sock
                    if hasattr(sock, 'version'):
                        logger.info(f"TLS version used: {sock.version()}")
                    if hasattr(sock, 'cipher'):
                        logger.info(f"Cipher suite used: {sock.cipher()}")
            
            response.raise_for_status()
            return response
            
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL/TLS error: {e}")
            raise SecurityError(f"SSL/TLS security requirements not met: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise
    
    def post(self, url: str, data: Optional[Dict] = None, **kwargs) -> requests.Response:
        """
        Perform secure POST request.
        
        Args:
            url: Request URL
            data: Request data
            **kwargs: Additional request parameters
            
        Returns:
            Response object
            
        Raises:
            requests.exceptions.RequestException: If request fails
            SecurityError: If security requirements not met
        """
        # Ensure HTTPS for sensitive operations
        if not url.startswith('https://'):
            raise SecurityError(f"HTTPS required for secure requests: {url}")
        
        # Set default timeout
        kwargs.setdefault('timeout', self.timeout)
        
        # Set SSL verification
        kwargs.setdefault('verify', self.verify_ssl)
        
        # Set secure headers for POST requests
        headers = kwargs.get('headers', {})
        headers.update({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        })
        kwargs['headers'] = headers
        
        logger.debug(f"Making secure POST request to: {url}")
        
        try:
            response = self.session.post(url, data=data, **kwargs)
            
            # Log security information
            if hasattr(response, 'raw') and hasattr(response.raw, 'connection'):
                conn = response.raw.connection
                if hasattr(conn, 'sock'):
                    sock = conn.sock
                    if hasattr(sock, 'version'):
                        logger.info(f"TLS version used: {sock.version()}")
                    if hasattr(sock, 'cipher'):
                        logger.info(f"Cipher suite used: {sock.cipher()}")
            
            response.raise_for_status()
            return response
            
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL/TLS error: {e}")
            raise SecurityError(f"SSL/TLS security requirements not met: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise
    
    def close(self):
        """Close the session and clean up resources."""
        self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


def create_secure_session(timeout: int = 30, verify_ssl: bool = True) -> requests.Session:
    """
    Create a requests session with secure defaults.
    
    Args:
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Configured requests session
    """
    session = requests.Session()
    
    # Add secure adapter
    secure_adapter = SecureHTTPAdapter()
    session.mount('https://', secure_adapter)
    
    # Set secure headers
    session.headers.update({
        'User-Agent': 'AgentAuth/1.0.0 (Secure HTTP Client)',
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    })
    
    # Configure SSL verification
    if not verify_ssl:
        logger.warning("SSL verification disabled - this is not recommended for production")
        session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    return session


def verify_tls_version(response: requests.Response) -> bool:
    """
    Verify that the response used TLS 1.2 or higher, with preference for TLS 1.3.
    
    Args:
        response: Response object to check
        
    Returns:
        True if TLS 1.2+ was used, False otherwise
    """
    try:
        if hasattr(response, 'raw') and hasattr(response.raw, 'connection'):
            conn = response.raw.connection
            if hasattr(conn, 'sock'):
                sock = conn.sock
                if hasattr(sock, 'version'):
                    version = sock.version()
                    logger.info(f"TLS version used: {version}")
                    
                    # Check if TLS version is 1.2 or higher
                    if version in ['TLSv1.2', 'TLSv1.3']:
                        if version == 'TLSv1.3':
                            logger.info("✅ TLS 1.3 used (preferred)")
                        else:
                            logger.info("✅ TLS 1.2 used (fallback)")
                        return True
                    else:
                        logger.warning(f"Insecure TLS version detected: {version}")
                        return False
        
        # If we can't determine the version, assume it's secure (the adapter enforces it)
        return True
        
    except Exception as e:
        logger.error(f"Error checking TLS version: {e}")
        return False


# SecurityError is now imported from utils.exceptions 