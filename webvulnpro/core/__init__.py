"""Core module for WebVulnPro"""

from .models import Vulnerability, ScanResult, ScanProfile, Severity, TechnologyFingerprint, TechnologyCategory
from .reporter import ReportGenerator

# Lazy import to avoid circular dependency
def get_scanner():
    from .scanner import WebVulnScanner
    return WebVulnScanner

__all__ = [
    "Vulnerability",
    "ScanResult", 
    "ScanProfile",
    "Severity",
    "TechnologyFingerprint",
    "TechnologyCategory",
    "ReportGenerator",
    "get_scanner",
]
