#!/usr/bin/env python3
"""
Simple test to verify the new module structure works.
"""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all the new imports work correctly."""
    try:
        # Test core imports
        from agentauth.core import OAuth2OIDCClient, discover_oidc_config, retrieve_jwks
        print("✓ Core imports successful")
        
        # Test config imports
        from agentauth.config import ClientConfig, SecurityConfig, ErrorConfig
        from agentauth.config import ClientBuilder, SecurityBuilder, ErrorConfigBuilder
        print("✓ Config imports successful")
        
        # Test security imports
        from agentauth.security import SecurityFramework, CryptographicAuthenticator
        from agentauth.security import InputSanitizer, SecurityAuditLogger, ResourceLimiter
        from agentauth.security import CodeInjectionProtector, SecureErrorHandler
        from agentauth.security import SecureHTTPClient, SecureHTTPAdapter
        from agentauth.security import create_secure_session, verify_tls_version
        from agentauth.security import generate_secure_nonce, secure_wipe_memory
        from agentauth.security import validate_cryptographic_parameters, AGENTAUTH_DISABLE_SECURITY
        print("✓ Security imports successful")
        
        # Test utils imports
        from agentauth.utils import SecurityError, OAuth2OIDCError
        print("✓ Utils imports successful")
        
        # Test main package imports
        from agentauth import OAuth2OIDCClient, SecurityFramework, ClientBuilder
        print("✓ Main package imports successful")
        
        print("\n🎉 All imports successful! New structure is working correctly.")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_builder_pattern():
    """Test the new builder pattern."""
    try:
        from agentauth import ClientBuilder, SecurityBuilder
        
        # Test client builder
        config = (ClientBuilder()
                 .with_idp("Test IdP", "https://test.example.com")
                 .with_credentials("client_id", "client_secret")
                 .with_timeout(30)
                 .build())
        
        print("✓ Client builder pattern works")
        
        # Test security builder
        security_config = (SecurityBuilder()
                         .with_security_enabled(True)
                         .with_input_limits(max_token_length=8192)
                         .with_resource_limits(max_response_size=1024*1024)
                         .build())
        
        print("✓ Security builder pattern works")
        
        return True
        
    except Exception as e:
        print(f"❌ Builder pattern error: {e}")
        return False

if __name__ == "__main__":
    print("Testing new AgentAuth module structure...\n")
    
    success = True
    success &= test_imports()
    success &= test_builder_pattern()
    
    if success:
        print("\n✅ All tests passed! The refactoring was successful.")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
        sys.exit(1) 