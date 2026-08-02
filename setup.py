"""
WebVulnPro - Enterprise Web Vulnerability Assessment Tool

Installation:
    pip install -e .
    
Usage:
    webvulnpro scan https://example.com
    python -m webvulnpro scan https://example.com
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
this_directory = Path(__file__).parent
long_description = ""
readme_path = this_directory / "README.md"
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")

setup(
    name="webvulnpro",
    version="1.0.0",
    author="WebVulnPro Team",
    author_email="security@webvulnpro.io",
    description="Enterprise Web Vulnerability Assessment Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/razzsecdev/webvulnpro",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "webvulnpro": [
            "wordlists/*.txt",
            "signatures/*.json",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.9",
    install_requires=[
        "aiohttp>=3.9.0",
        "typer>=0.9.0",
        "click>=8.0.0",
        "rich>=13.0.0",
        "reportlab>=4.0.0",
        "urllib3>=2.0.0",
        "certifi>=2023.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "ruff>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "webvulnpro=webvulnpro.cli:cli_main",
        ],
    },
    zip_safe=False,
)
