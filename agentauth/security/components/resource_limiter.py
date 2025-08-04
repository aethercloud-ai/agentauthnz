"""
Resource limiting and DoS protection for AgentAuth.

This module provides resource limits to prevent DoS attacks and ensure
stable operation under high load conditions.
"""

import time
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Any, Callable
import requests
from ...utils.exceptions import SecurityError

logger = logging.getLogger(__name__)


class ResourceLimiter:
    """Resource limiting and DoS protection."""
    
    def __init__(self):
        # Security. Define resource limits to prevent DoS attacks
        self.max_response_size = 1024 * 1024  # 1MB limit
        self.max_processing_time = 30  # 30 seconds
        self.max_concurrent_requests = 10
        self.max_request_rate = 100  # requests per minute
        
        # Security. Initialize concurrency controls
        self.request_semaphore = threading.Semaphore(self.max_concurrent_requests)
        self.executor = ThreadPoolExecutor(max_workers=self.max_concurrent_requests)
        
        # Security. Track request rates for rate limiting
        self.request_times = {}
        self.rate_limit_lock = threading.Lock()
    
    def limit_response_size(self, response: requests.Response) -> requests.Response:
        """
        Security. Limit response size to prevent memory exhaustion attacks.
        
        Args:
            response: HTTP response to check
            
        Returns:
            Response if within limits
            
        Raises:
            SecurityError: If response is too large
        """
        # Security. Check content-length header
        content_length = response.headers.get('content-length')
        if content_length and int(content_length) > self.max_response_size:
            logger.warning(f"Response too large: {content_length} bytes")
            raise SecurityError("Response too large")
        
        # Security. Check actual content size
        content = response.content
        if len(content) > self.max_response_size:
            logger.warning(f"Response content too large: {len(content)} bytes")
            raise SecurityError("Response content too large")
        
        return response
    
    def limit_processing_time(self, func: Callable, *args, **kwargs) -> Any:
        """
        Security. Limit processing time to prevent CPU exhaustion attacks.
        
        Args:
            func: Function to execute with timeout
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result if completed within timeout
            
        Raises:
            SecurityError: If processing timeout is exceeded
        """
        # Security. Execute function with timeout protection
        future = self.executor.submit(func, *args, **kwargs)
        try:
            result = future.result(timeout=self.max_processing_time)
            return result
        except TimeoutError:
            # Security. Cancel the future to prevent resource leaks
            future.cancel()
            logger.warning(f"Processing timeout exceeded: {func.__name__}")
            raise SecurityError("Processing timeout exceeded")
        except Exception as e:
            # Security. Re-raise other exceptions
            raise e
    
    def acquire_request_slot(self, client_id: str = None):
        """
        Security. Acquire a request slot to limit concurrency.
        
        Args:
            client_id: Client identifier for rate limiting
            
        Raises:
            SecurityError: If too many concurrent requests
        """
        # Security. Check rate limits
        if client_id and not self._check_rate_limit(client_id):
            logger.warning(f"Rate limit exceeded for client: {client_id}")
            raise SecurityError("Rate limit exceeded")
        
        # Security. Acquire semaphore with timeout
        if not self.request_semaphore.acquire(timeout=5):
            logger.warning("Too many concurrent requests")
            raise SecurityError("Too many concurrent requests")
    
    def release_request_slot(self):
        """
        Security. Release a request slot.
        """
        self.request_semaphore.release()
    
    def _check_rate_limit(self, client_id: str) -> bool:
        """
        Security. Check rate limits for a client.
        
        Args:
            client_id: Client identifier
            
        Returns:
            True if within rate limits
        """
        with self.rate_limit_lock:
            current_time = time.time()
            
            # Security. Initialize request times for new clients
            if client_id not in self.request_times:
                self.request_times[client_id] = []
            
            # Security. Remove old requests outside the window
            window_start = current_time - 60  # 1 minute window
            self.request_times[client_id] = [
                req_time for req_time in self.request_times[client_id]
                if req_time > window_start
            ]
            
            # Security. Check if client has exceeded rate limit
            if len(self.request_times[client_id]) >= self.max_request_rate:
                return False
            
            # Security. Add current request
            self.request_times[client_id].append(current_time)
            return True
    
    def limit_memory_usage(self, data: bytes, max_size: int = None) -> bytes:
        """
        Security. Limit memory usage to prevent memory exhaustion.
        
        Args:
            data: Data to check
            max_size: Maximum allowed size (defaults to max_response_size)
            
        Returns:
            Data if within limits
            
        Raises:
            SecurityError: If data is too large
        """
        if max_size is None:
            max_size = self.max_response_size
        
        if len(data) > max_size:
            logger.warning(f"Data too large: {len(data)} bytes")
            raise SecurityError("Data too large")
        
        return data
    
    def limit_cpu_usage(self, func: Callable, *args, **kwargs) -> Any:
        """
        Security. Limit CPU usage with processing time limits.
        
        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result
            
        Raises:
            SecurityError: If CPU usage limit exceeded
        """
        return self.limit_processing_time(func, *args, **kwargs)
    
    def cleanup_expired_entries(self):
        """
        Security. Clean up expired rate limit entries to prevent memory leaks.
        """
        with self.rate_limit_lock:
            current_time = time.time()
            window_start = current_time - 60  # 1 minute window
            
            for client_id in list(self.request_times.keys()):
                self.request_times[client_id] = [
                    req_time for req_time in self.request_times[client_id]
                    if req_time > window_start
                ]
                
                # Security. Remove empty entries
                if not self.request_times[client_id]:
                    del self.request_times[client_id]
    
    def get_resource_usage_stats(self) -> dict:
        """
        Security. Get current resource usage statistics.
        
        Returns:
            Dictionary with resource usage statistics
        """
        return {
            'active_requests': self.max_concurrent_requests - self.request_semaphore._value,
            'max_concurrent_requests': self.max_concurrent_requests,
            'active_clients': len(self.request_times),
            'total_requests_in_window': sum(len(times) for times in self.request_times.values()),
            'max_request_rate': self.max_request_rate
        } 