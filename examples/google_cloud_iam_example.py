#!/usr/bin/env python3
"""
Google Cloud IAM OAuth2/OIDC Example

This example demonstrates how to use the oauth2_oidc_lib library
with Google Cloud IAM for machine-to-machine authentication and
JWT token validation.

Prerequisites:
1. Google Cloud project with IAM enabled
2. Service account with appropriate permissions
3. Service account key file (JSON)
4. Required environment variables (see setup below)

Setup:
1. Create a service account in Google Cloud Console
2. Download the service account key file
3. Set environment variables:
   export GOOGLE_CLOUD_PROJECT="your-project-id"
   export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account-key.json"
   export GOOGLE_CLOUD_CLIENT_ID="your-client-id"
   export GOOGLE_CLOUD_CLIENT_SECRET="your-client-secret"
"""

import os
import json
import logging
from datetime import datetime
from agentauth import (
    OAuth2OIDCClient,
    discover_oidc_config,
    retrieve_jwks,
    validate_token_signature,
    validate_multiple_token_signatures,
    OAuth2OIDCError
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def setup_google_cloud_client():
    """
    Set up the OAuth2/OIDC client for Google Cloud IAM.
    
    Returns:
        OAuth2OIDCClient instance configured for Google Cloud IAM
    """
    # Google Cloud IAM configuration
    idp_name = "Google Cloud IAM"
    idp_endpoint = "https://accounts.google.com"
    client_id = os.getenv("GOOGLE_CLOUD_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLOUD_CLIENT_SECRET")
    
    if not client_id or not client_secret:
        raise ValueError(
            "Please set GOOGLE_CLOUD_CLIENT_ID and GOOGLE_CLOUD_CLIENT_SECRET "
            "environment variables"
        )
    
    # Create client with Google Cloud IAM scopes
    scope = "https://www.googleapis.com/auth/cloud-platform"
    
    client = OAuth2OIDCClient(
        idp_name=idp_name,
        idp_endpoint=idp_endpoint,
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
        timeout=30,
        jwks_cache_ttl=3600
    )
    
    logger.info(f"Successfully initialized {idp_name} client")
    return client


def example_authentication(client):
    """
    Example: Authenticate with Google Cloud IAM and get access token.
    
    Args:
        client: OAuth2OIDCClient instance
    """
    print("\n=== Google Cloud IAM Authentication Example ===")
    
    try:
        # Authenticate and get access token
        access_token = client.authenticate()
        print(f"✅ Successfully authenticated with Google Cloud IAM")
        # Security. Use hashing instead of truncation to prevent sensitive data exposure
        import hashlib
        access_token_hash = hashlib.sha256(access_token.encode()).hexdigest()
        print(f"Access token hash: {access_token_hash}")
        
        # Get token information
        token_info = client.get_token_info(access_token)
        print(f"Token expires at: {token_info['expires_at']}")
        print(f"Token issued at: {token_info['issued_at']}")
        print(f"Token audience: {token_info['aud']}")
        print(f"Token issuer: {token_info['iss']}")
        
        return access_token
        
    except OAuth2OIDCError as e:
        print(f"❌ Authentication failed: {e}")
        return None


def example_jwks_retrieval(client):
    """
    Example: Retrieve JWKS from Google Cloud IAM.
    
    Args:
        client: OAuth2OIDCClient instance
    """
    print("\n=== JWKS Retrieval Example ===")
    
    try:
        # Get JWKS
        jwks = client.get_jwks()
        print(f"✅ Successfully retrieved JWKS from Google Cloud IAM")
        print(f"Number of keys: {len(jwks.get('keys', []))}")
        
        # Display key information
        for i, key in enumerate(jwks.get('keys', [])[:3]):  # Show first 3 keys
            print(f"Key {i+1}:")
            print(f"  Key ID: {key.get('kid')}")
            print(f"  Key Type: {key.get('kty')}")
            print(f"  Algorithm: {key.get('alg')}")
            if key.get('use'):
                print(f"  Use: {key.get('use')}")
            print()
        
        return jwks
        
    except OAuth2OIDCError as e:
        print(f"❌ JWKS retrieval failed: {e}")
        return None


def example_token_validation(client, access_token):
    """
    Example: Validate JWT tokens from Google Cloud IAM.
    
    Args:
        client: OAuth2OIDCClient instance
        access_token: Access token to validate
    """
    print("\n=== Token Validation Example ===")
    
    try:
        # Validate the access token
        payload = client.validate_token(
            token=access_token,
            token_type='access_token',
            audience=os.getenv("GOOGLE_CLOUD_CLIENT_ID"),
            issuer="https://accounts.google.com"
        )
        
        print(f"✅ Successfully validated access token")
        # Security. Log payload access without exposing sensitive data
        payload_hash = hashlib.sha256(str(payload).encode()).hexdigest()
        print(f"Token payload hash: {payload_hash}")
        print(f"  Audience: {payload.get('aud')}")
        print(f"  Issuer: {payload.get('iss')}")
        print(f"  Scope: {payload.get('scope')}")
        print(f"  Expires: {datetime.fromtimestamp(payload.get('exp', 0))}")
        
        return payload
        
    except OAuth2OIDCError as e:
        print(f"❌ Token validation failed: {e}")
        return None


def example_multiple_token_validation(client):
    """
    Example: Validate multiple tokens.
    
    Args:
        client: OAuth2OIDCClient instance
    """
    print("\n=== Multiple Token Validation Example ===")
    
    try:
        # Get multiple access tokens (in real scenario, these would be different tokens)
        token1 = client.authenticate(force_refresh=True)
        token2 = client.authenticate(force_refresh=True)
        
        # Prepare tokens for validation
        tokens = [
            {'token': token1, 'type': 'access_token'},
            {'token': token2, 'type': 'access_token'}
        ]
        
        # Validate multiple tokens
        results = client.validate_multiple_tokens(
            tokens=tokens,
            audience=os.getenv("GOOGLE_CLOUD_CLIENT_ID"),
            issuer="https://accounts.google.com"
        )
        
        print(f"✅ Validated {len(results)} tokens")
        for i, result in enumerate(results):
            status = "✅ Valid" if result['valid'] else "❌ Invalid"
            print(f"Token {i+1}: {status}")
            if result['error']:
                print(f"  Error: {result['error']}")
            else:
                # Security. Log payload access without exposing sensitive data
                payload_hash = hashlib.sha256(str(result.get('payload', {})).encode()).hexdigest()
                print(f"  Payload hash: {payload_hash}")
        
        return results
        
    except OAuth2OIDCError as e:
        print(f"❌ Multiple token validation failed: {e}")
        return None


def example_standalone_functions():
    """
    Example: Using standalone utility functions.
    """
    print("\n=== Standalone Functions Example ===")
    
    try:
        # Discover OIDC configuration
        oidc_config = discover_oidc_config("https://accounts.google.com")
        print(f"✅ Discovered OIDC configuration")
        print(f"Token endpoint: {oidc_config.get('token_endpoint')}")
        print(f"JWKS URI: {oidc_config.get('jwks_uri')}")
        
        # Retrieve JWKS
        jwks = retrieve_jwks(oidc_config.get('jwks_uri'))
        print(f"✅ Retrieved JWKS with {len(jwks.get('keys', []))} keys")
        
        # Example token (this would be a real token in practice)
        example_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHdERTdYZ9Fzpl1pbK6O0YHqgTDJ_4WbwOKC1BR89HZo0GhhQkGjgrQqY_3w9_9y3GJQ"
        
        # Validate token signature (this will fail with the example token)
        try:
            payload = validate_token_signature(
                token=example_token,
                jwks=jwks,
                audience="example-audience",
                issuer="https://accounts.google.com"
            )
            print(f"✅ Token signature validation successful")
        except OAuth2OIDCError as e:
            print(f"❌ Token signature validation failed (expected): {e}")
        
        return oidc_config, jwks
        
    except OAuth2OIDCError as e:
        print(f"❌ Standalone functions failed: {e}")
        return None, None


def example_error_handling():
    """
    Example: Error handling scenarios.
    """
    print("\n=== Error Handling Example ===")
    
    # Test with invalid client credentials
    try:
        invalid_client = OAuth2OIDCClient(
            idp_name="Google Cloud IAM",
            idp_endpoint="https://accounts.google.com",
            client_id="invalid-client-id",
            client_secret="invalid-client-secret"
        )
        invalid_client.authenticate()
    except OAuth2OIDCError as e:
        print(f"✅ Properly handled invalid credentials: {e}")
    
    # Test with invalid token
    try:
        client = setup_google_cloud_client()
        client.validate_token("invalid.token.here")
    except OAuth2OIDCError as e:
        print(f"✅ Properly handled invalid token: {e}")
    
    # Test with expired token (simulated)
    try:
        expired_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.invalid_signature"
        client.validate_token(expired_token)
    except OAuth2OIDCError as e:
        print(f"✅ Properly handled expired token: {e}")


def main():
    """
    Main function demonstrating all examples.
    """
    print("Google Cloud IAM OAuth2/OIDC Library Examples")
    print("=" * 60)
    
    # Check environment variables
    required_vars = [
        "GOOGLE_CLOUD_CLIENT_ID",
        "GOOGLE_CLOUD_CLIENT_SECRET"
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"❌ Missing required environment variables: {missing_vars}")
        print("Please set the required environment variables before running this example.")
        return
    
    try:
        # Set up client
        client = setup_google_cloud_client()
        
        # Run examples
        access_token = example_authentication(client)
        if access_token:
            jwks = example_jwks_retrieval(client)
            if jwks:
                example_token_validation(client, access_token)
                example_multiple_token_validation(client)
        
        # Standalone functions example
        example_standalone_functions()
        
        # Error handling example
        example_error_handling()
        
        print("\n" + "=" * 60)
        print("✅ All examples completed successfully!")
        
    except Exception as e:
        print(f"❌ Example execution failed: {e}")
        logger.exception("Unexpected error during example execution")


if __name__ == "__main__":
    main() 