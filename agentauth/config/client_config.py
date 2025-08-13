"""
Client configuration for AgentAuth.

This module provides configuration classes for OAuth2/OIDC client settings.
"""

import os
from dataclasses import dataclass, field
from typing import Optional
from .security_config import SecurityConfig


@dataclass
class ClientConfig:
    """Configuration for OAuth2/OIDC client."""
    
    # Identity Provider settings
    idp_name: str = ""
    idp_endpoint: str = ""
    client_id: str = ""
    client_secret: str = ""
    scope: Optional[str] = None
    
    # HTTP settings
    timeout: int = 30
    cert_chain: Optional[str] = None
    
    # JWKS settings
    jwks_cache_ttl: int = 3600
    
    # Security settings
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    # Environment-based overrides
    def __post_init__(self):
        """Apply environment variable overrides after initialization."""
        if os.getenv("AGENTAUTH_TIMEOUT"):
            self.timeout = int(os.getenv("AGENTAUTH_TIMEOUT"))
        
        if os.getenv("AGENTAUTH_JWKS_CACHE_TTL"):
            self.jwks_cache_ttl = int(os.getenv("AGENTAUTH_JWKS_CACHE_TTL"))
        
        if os.getenv("AGENTAUTH_CERT_CHAIN"):
            self.cert_chain = os.getenv("AGENTAUTH_CERT_CHAIN")
        
        # Only override idp_endpoint if it's not already set (allows tests to use their own endpoints)
        if os.getenv("AGENTAUTH_IDP_BASE_URL") and not self.idp_endpoint:
            self.idp_endpoint = os.getenv("AGENTAUTH_IDP_BASE_URL").rstrip('/')


class ClientBuilder:
    """Builder pattern for creating ClientConfig instances."""
    
    def __init__(self):
        self.config = ClientConfig()
    
    def with_idp(self, name: str, endpoint: str) -> 'ClientBuilder':
        """Set Identity Provider configuration."""
        self.config.idp_name = name
        self.config.idp_endpoint = endpoint.rstrip('/')
        return self
    
    def with_credentials(self, client_id: str, client_secret: str) -> 'ClientBuilder':
        """Set OAuth2 credentials."""
        self.config.client_id = client_id
        self.config.client_secret = client_secret
        return self
    
    def with_scope(self, scope: str) -> 'ClientBuilder':
        """Set OAuth2 scope."""
        self.config.scope = scope
        return self
    
    def with_timeout(self, timeout: int) -> 'ClientBuilder':
        """Set HTTP timeout."""
        self.config.timeout = timeout
        return self
    
    def with_jwks_cache_ttl(self, ttl: int) -> 'ClientBuilder':
        """Set JWKS cache TTL."""
        self.config.jwks_cache_ttl = ttl
        return self
    
    def with_cert_chain(self, cert_chain: str) -> 'ClientBuilder':
        """Set certificate chain path."""
        self.config.cert_chain = cert_chain
        return self
    
    def with_security(self, security_config: SecurityConfig) -> 'ClientBuilder':
        """Set security configuration."""
        self.config.security = security_config
        return self
    
    def build(self) -> ClientConfig:
        """Build and return the ClientConfig instance."""
        return self.config 