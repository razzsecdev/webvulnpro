"""
WebVulnPro - Main entry point
"""

import sys


def main():
    """Main entry point for python -m webvulnpro"""
    from webvulnpro.cli import app
    app()


if __name__ == "__main__":
    main()
