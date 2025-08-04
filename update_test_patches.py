#!/usr/bin/env python3
"""
Script to update patch decorators in test files to use new module paths.
"""

import re
import os

def update_patches_in_file(file_path):
    """Update patch decorators in a test file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Update verify_tls_version patches
    content = re.sub(
        r"@patch\('agentauth\.agentauth\.verify_tls_version'\)",
        "@patch('agentauth.security.components.http_client.verify_tls_version')",
        content
    )
    
    # Update SecureHTTPClient patches
    content = re.sub(
        r"@patch\('agentauth\.agentauth\.SecureHTTPClient'\)",
        "@patch('agentauth.security.components.http_client.SecureHTTPClient')",
        content
    )
    
    # Update requests.get patches
    content = re.sub(
        r"@patch\('agentauth\.agentauth\.requests\.get'\)",
        "@patch('agentauth.core.discovery.requests.get')",
        content
    )
    
    # Update other agentauth.agentauth references
    content = re.sub(
        r"agentauth\.agentauth\.",
        "agentauth.core.",
        content
    )
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Updated patches in {file_path}")

def main():
    """Update all test files."""
    test_files = [
        "tests/test_agentauth.py",
        "tests/test_agentauth_security.py",
        "tests/test_config.py"
    ]
    
    for test_file in test_files:
        if os.path.exists(test_file):
            update_patches_in_file(test_file)
        else:
            print(f"Warning: {test_file} not found")

if __name__ == "__main__":
    main() 