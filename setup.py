from setuptools import setup, find_packages

setup(
    name="ad-ldaps-proxy",
    version="1.0.0",
    description="Enterprise Active Directory Secure LDAPS Proxy for AI Agents and Service Accounts",
    author="Enterprise Security Operations",
    packages=find_packages(include=["ad_proxy", "ad_proxy.*"]),
    python_requires=">=3.10",
    install_requires=[
        "pyyaml>=6.0.1",
        "ldap3>=2.9.1",
        "cryptography>=42.0.0",
        "hvac>=2.1.0",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "ad-proxy=ad_proxy.cli:main",
        ],
    },
)
