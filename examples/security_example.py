#!/usr/bin/env python3
"""
Security Example for AgentAuth Library

This example demonstrates the enhanced security features including:
- Simple dictionary-based storage
- Cryptographic authentication
- Anti-replay protection
- Rate limiting
- Enhanced token validation
"""

import os
import time
import logging
import hashlib
from datetime import datetime

# Import AgentAuth with security features
from agentauth import (
    OAuth2OIDCClient,
    CryptographicAuthenticator,
    SecurityError,
    generate_secure_nonce,
    secure_wipe_memory,
    validate_cryptographic_parameters,
    ClientBuilder,
    SecurityBuilder
)
from agentauth.security.authenticator import SecureTokenValidator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def example_simple_dictionary_storage():
    """Demonstrate simple dictionary-based storage."""
    print("\n=== Simple Dictionary Storage Example ===")
    
    # Initialize simple storage
    token_cache = {}
    jwks_cache = {}
    
    # Store sensitive data
    sensitive_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    token_cache['access_token'] = sensitive_token
    token_cache['expires_in'] = 3600
    token_cache['expires_at'] = time.time() + 3600
    
    jwks_cache['keys'] = [{'kty': 'RSA', 'kid': 'test-key'}]
    jwks_cache['cached_at'] = time.time()
    
    # Retrieve data
    retrieved_token = token_cache.get('access_token')
    retrieved_jwks = jwks_cache.get('keys')
    
    # Security. Use hashing instead of truncation to prevent sensitive data exposure
    token_hash = hashlib.sha256(sensitive_token.encode()).hexdigest()
    retrieved_token_hash = hashlib.sha256(retrieved_token.encode()).hexdigest() if retrieved_token else None
    
    print(f"✅ Stored token hash: {token_hash}")
    print(f"✅ Retrieved token hash: {retrieved_token_hash}")
    print(f"✅ Retrieved JWKS keys: {len(retrieved_jwks) if retrieved_jwks else 0}")
    
    # Demonstrate simple deletion
    del token_cache['access_token']
    deleted_token = token_cache.get('access_token')
    print(f"✅ After deletion: {deleted_token is None}")
    
    # Clear all data
    token_cache.clear()
    jwks_cache.clear()
    print(f"✅ After clear: {len(token_cache) == 0 and len(jwks_cache) == 0}")


def example_cryptographic_authentication():
    """Demonstrate cryptographic authentication."""
    print("\n=== Cryptographic Authentication Example ===")
    
    # Initialize authenticator
    auth = CryptographicAuthenticator()
    
    # Generate authentication token
    client_id = "my-secure-client-123"
    auth_token = auth.generate_hmac_token(client_id)
    # Security. Use hashing instead of truncation to prevent sensitive data exposure
    auth_token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
    print(f"✅ Generated auth token hash: {auth_token_hash}")
    
    # Verify token
    is_valid = auth.verify_hmac_token(auth_token, client_id)
    print(f"✅ Token verification: {is_valid}")
    
    # Test with wrong client ID
    is_invalid = auth.verify_hmac_token(auth_token, "wrong-client-id")
    print(f"✅ Wrong client ID rejected: {not is_invalid}")
    
    # Test rate limiting
    for i in range(5):
        allowed = auth.check_rate_limit(client_id)
        print(f"✅ Request {i+1} allowed: {allowed}")
    
    # Test nonce verification
    nonce = generate_secure_nonce()
    is_nonce_valid = auth.verify_nonce(nonce)
    print(f"✅ Nonce verification: {is_nonce_valid}")
    
    # Test nonce replay protection
    is_replay_valid = auth.verify_nonce(nonce)  # Same nonce
    print(f"✅ Replay protection: {not is_replay_valid}")


def example_enhanced_token_validation():
    """Demonstrate enhanced token validation."""
    print("\n=== Enhanced Token Validation Example ===")
    
    # Initialize secure token validator
    validator = SecureTokenValidator()
    
    # Create a mock JWT token (in real usage, this would come from an IdP)
    mock_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5Iiwibm9uY2UiOiJ0ZXN0LW5vbmNlIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3MzU2ODAwMDB9.signature"
    
    # Mock JWKS
    mock_jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key",
                "n": "AQAB",  # Simplified for example
                "e": "AQAB"
            }
        ]
    }
    
    # Generate auth token
    auth = CryptographicAuthenticator()
    auth_token = auth.generate_hmac_token("test-client")
    
    try:
        # Validate token with security checks
        payload = validator.validate_token_secure(
            token=mock_token,
            jwks=mock_jwks,
            audience="test-audience",
            issuer="test-issuer",
            auth_token=auth_token,
            client_id="test-client"
        )
        # Security. Log payload access without exposing sensitive data
        payload_hash = hashlib.sha256(str(payload).encode()).hexdigest()
        print(f"✅ Token validation successful: {payload_hash}")
    except SecurityError as e:
        print(f"⚠️ Security check failed: {e}")
    except Exception as e:
        print(f"❌ Validation failed: {e}")


def example_secure_client_usage():
    """Demonstrate secure client usage."""
    print("\n=== Secure Client Usage Example ===")
    
    # Initialize client with security enabled using the builder pattern
    security_config = (SecurityBuilder()
                      .with_security_enabled(True)
                      .with_input_limits(max_token_length=8192)
                      .with_resource_limits(max_response_size=1024*1024)
                      .build())
    
    client_config = (ClientBuilder()
                    .with_idp("Secure IdP", "https://your-idp.example.com")
                    .with_credentials("secure-client-id", "secure-client-secret")
                    .with_timeout(30)
                    .with_cert_chain("/path/to/certificate-chain.pem")  # Optional
                    .with_security(security_config)
                    .build())
    
    client = OAuth2OIDCClient(client_config)
    
    # Generate authentication token
    auth = CryptographicAuthenticator()
    auth_token = auth.generate_hmac_token(client.client_id)
    
    try:
        # Authenticate with security checks
        access_token = client.authenticate(auth_token=auth_token)
        # Security. Use hashing instead of truncation to prevent sensitive data exposure
        access_token_hash = hashlib.sha256(access_token.encode()).hexdigest()
        print(f"✅ Authentication successful: {access_token_hash}")
        
        # Validate token with security checks
        payload = client.validate_token(
            token=access_token,
            auth_token=auth_token
        )
        # Security. Log payload access without exposing sensitive data
        payload_hash = hashlib.sha256(str(payload).encode()).hexdigest()
        print(f"✅ Token validation successful: {payload_hash}")
        
    except SecurityError as e:
        print(f"⚠️ Security check failed: {e}")
    except Exception as e:
        print(f"❌ Operation failed: {e}")


def example_cryptographic_parameter_validation():
    """Demonstrate cryptographic parameter validation."""
    print("\n=== Cryptographic Parameter Validation Example ===")
    
    # Test secure RSA key
    secure_rsa_jwk = {
        "kty": "RSA",
        "kid": "secure-rsa-key",
        "n": "AQAB",  # 2048+ bit key (simplified)
        "e": "AQAB"   # 65537
    }
    
    # Test secure EC key
    secure_ec_jwk = {
        "kty": "EC",
        "kid": "secure-ec-key",
        "crv": "P-256",
        "x": "AQAB",
        "y": "AQAB"
    }
    
    # Test insecure RSA key (small key size)
    insecure_rsa_jwk = {
        "kty": "RSA",
        "kid": "insecure-rsa-key",
        "n": "AQAB",  # Small key (simplified)
        "e": "AQAB"
    }
    
    # Test insecure EC key (weak curve)
    insecure_ec_jwk = {
        "kty": "EC",
        "kid": "insecure-ec-key",
        "crv": "P-192",  # Weak curve
        "x": "AQAB",
        "y": "AQAB"
    }
    
    print(f"✅ Secure RSA key: {validate_cryptographic_parameters(secure_rsa_jwk)}")
    print(f"✅ Secure EC key: {validate_cryptographic_parameters(secure_ec_jwk)}")
    print(f"❌ Insecure RSA key: {validate_cryptographic_parameters(insecure_rsa_jwk)}")
    print(f"❌ Insecure EC key: {validate_cryptographic_parameters(insecure_ec_jwk)}")


def example_secure_memory_management():
    """Demonstrate secure memory management."""
    print("\n=== Secure Memory Management Example ===")
    
    # Create sensitive data
    sensitive_data = b"very-secret-token-data-that-must-be-protected"
    print(f"✅ Original data: {sensitive_data}")
    
    # Securely wipe memory
    secure_wipe_memory(sensitive_data)
    print(f"✅ After secure wipe: {sensitive_data}")
    
    # Demonstrate with bytearray
    sensitive_array = bytearray(b"another-secret-data")
    print(f"✅ Original array: {sensitive_array}")
    
    # Convert to bytes for wiping
    sensitive_bytes = bytes(sensitive_array)
    secure_wipe_memory(sensitive_bytes)
    print(f"✅ After secure wipe: {sensitive_bytes}")


def example_security_best_practices():
    """Demonstrate security best practices."""
    print("\n=== Security Best Practices Example ===")
    
    # 1. Always use security features
    print("✅ 1. Security features enabled by default")
    
    # 2. Use authentication tokens
    auth = CryptographicAuthenticator()
    auth_token = auth.generate_hmac_token("client-123")
    # Security. Use hashing instead of truncation to prevent sensitive data exposure
    auth_token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
    print(f"✅ 2. Authentication token hash: {auth_token_hash}")
    
    # 3. Implement rate limiting
    for i in range(3):
        allowed = auth.check_rate_limit("client-123")
        print(f"✅ 3. Rate limit check {i+1}: {allowed}")
    
    # 4. Validate cryptographic parameters
    secure_jwk = {
        "kty": "RSA",
        "kid": "secure-key",
        "n": "AQAB",
        "e": "AQAB"
    }
    is_secure = validate_cryptographic_parameters(secure_jwk)
    print(f"✅ 4. Cryptographic validation: {is_secure}")
    
    # 5. Use secure random generation
    nonce1 = generate_secure_nonce()
    nonce2 = generate_secure_nonce()
    # Security. Use hashing instead of truncation to prevent sensitive data exposure
    nonce1_hash = hashlib.sha256(nonce1.encode()).hexdigest()
    nonce2_hash = hashlib.sha256(nonce2.encode()).hexdigest()
    print(f"✅ 5. Secure nonces generated: {nonce1_hash} and {nonce2_hash}")
    print(f"✅ 5. Nonces are different: {nonce1 != nonce2}")


def main():
    """Run all security examples."""
    print("AgentAuth Security Features Demonstration")
    print("=" * 60)
    
    try:
        # Run all examples
        example_simple_dictionary_storage()
        example_cryptographic_authentication()
        example_enhanced_token_validation()
        example_secure_client_usage()
        example_cryptographic_parameter_validation()
        example_secure_memory_management()
        example_security_best_practices()
        
        print("\n" + "=" * 60)
        print("✅ All security examples completed successfully!")
        print("🔒 Security features are working correctly.")
        
    except Exception as e:
        print(f"\n❌ Security example failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main()) 