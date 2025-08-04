#!/usr/bin/env python3
"""
Setup script for AgentAuth package

AgentAuth is a comprehensive Python library for OAuth2 and OpenID Connect (OIDC) 
authentication with JWT token validation. This library supports machine-to-machine 
(M2M) authentication and works with any Identity Provider (IdP) that implements 
OAuth2/OIDC standards.
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    return "AgentAuth - OAuth2/OIDC Authentication and JWT Token Validation Library"

# Read requirements
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
    if os.path.exists(requirements_path):
        with open(requirements_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return [
        "requests>=2.31.0",
        "pyjwt>=2.8.0",
        "cryptography>=41.0.0"
    ]

setup(
    name="agentauth",
    version="0.0.1",
    author="Ron Herardian",
    author_email="agentauth@aethercloud.net",
    description="OAuth2/OIDC Authentication and JWT Token Validation Library",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/agentauth/agentauth",
    project_urls={
        "Bug Tracker": "https://github.com/agentauth/agentauth/issues",
        "Documentation": "https://github.com/agentauth/agentauth/docs",
        "Source Code": "https://github.com/agentauth/agentauth",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    python_requires=">=3.7",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "coverage>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "coverage>=7.0.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.0.0",
            "myst-parser>=1.0.0",
        ],
    },
    include_package_data=True,
    package_data={
        "agentauth": ["py.typed"],
    },
    zip_safe=False,
    keywords=[
        "oauth2",
        "oidc",
        "openid-connect",
        "jwt",
        "authentication",
        "authorization",
        "identity-provider",
        "machine-to-machine",
        "m2m",
        "jwks",
        "security",
    ],

) 