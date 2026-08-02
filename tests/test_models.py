"""
Tests for core models
"""

import pytest
from datetime import datetime

from webvulnpro.core.models import (
    Vulnerability, 
    ScanResult, 
    ScanProfile,
    Severity,
    TechnologyFingerprint,
)


class TestSeverity:
    """Test Severity enum"""
    
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"
    
    def test_severity_weights(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFO.weight
    
    def test_severity_colors(self):
        assert Severity.CRITICAL.color == "red"
        assert Severity.HIGH.color == "orange1"


class TestVulnerability:
    """Test Vulnerability dataclass"""
    
    def test_create_vulnerability(self):
        vuln = Vulnerability(
            title="Test Vulnerability",
            severity=Severity.HIGH,
            cvss_score=7.5,
            description="Test description",
            remediation="Fix it",
            evidence="Test evidence",
        )
        
        assert vuln.title == "Test Vulnerability"
        assert vuln.severity == Severity.HIGH
        assert vuln.cvss_score == 7.5
    
    def test_vulnerability_to_dict(self):
        vuln = Vulnerability(
            title="Missing HSTS",
            severity=Severity.HIGH,
            cvss_score=7.5,
            description="HSTS header missing",
            remediation="Add HSTS header",
            evidence="Header not found",
            cwe_id="CWE-319",
        )
        
        d = vuln.to_dict()
        
        assert d["title"] == "Missing HSTS"
        assert d["severity"] == "HIGH"
        assert d["cvss_score"] == 7.5
        assert d["cwe_id"] == "CWE-319"
    
    def test_vulnerability_from_dict(self):
        data = {
            "title": "XSS Found",
            "severity": "CRITICAL",
            "cvss_score": 9.0,
            "description": "XSS vulnerability",
            "remediation": "Sanitize input",
            "evidence": "Payload reflected",
        }
        
        vuln = Vulnerability.from_dict(data)
        
        assert vuln.title == "XSS Found"
        assert vuln.severity == Severity.CRITICAL


class TestScanResult:
    """Test ScanResult dataclass"""
    
    def test_create_scan_result(self):
        result = ScanResult(
            target="https://example.com",
            start_time=datetime.now(),
        )
        
        assert result.target == "https://example.com"
        assert result.vulnerabilities == []
        assert result.error is None
    
    def test_scan_result_risk_score(self):
        result = ScanResult(
            target="https://example.com",
            start_time=datetime.now(),
        )
        
        # Empty should be 0
        assert result.risk_score == 0
        
        # Add vulnerabilities
        result.vulnerabilities = [
            Vulnerability(
                title="Critical Issue",
                severity=Severity.CRITICAL,
                cvss_score=9.5,
                description="",
                remediation="",
                evidence="",
            ),
            Vulnerability(
                title="High Issue",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description="",
                remediation="",
                evidence="",
            ),
        ]
        
        assert result.risk_score > 0
        assert result.risk_score <= 100
    
    def test_count_by_severity(self):
        result = ScanResult(
            target="https://example.com",
            start_time=datetime.now(),
            vulnerabilities=[
                Vulnerability(title="V1", severity=Severity.CRITICAL, cvss_score=9.0,
                             description="", remediation="", evidence=""),
                Vulnerability(title="V2", severity=Severity.CRITICAL, cvss_score=9.0,
                             description="", remediation="", evidence=""),
                Vulnerability(title="V3", severity=Severity.HIGH, cvss_score=7.0,
                             description="", remediation="", evidence=""),
            ],
        )
        
        counts = result.count_by_severity()
        
        assert counts["CRITICAL"] == 2
        assert counts["HIGH"] == 1
        assert counts["MEDIUM"] == 0
    
    def test_scan_result_to_dict(self):
        result = ScanResult(
            target="https://example.com",
            start_time=datetime.now(),
            end_time=datetime.now(),
            status_code=200,
        )
        
        d = result.to_dict()
        
        assert d["target"] == "https://example.com"
        assert d["status_code"] == 200
        assert "risk_score" in d


class TestScanProfile:
    """Test ScanProfile dataclass"""
    
    def test_get_quick_profile(self):
        profile = ScanProfile.get_profile("quick")
        
        assert profile.name == "quick"
        assert profile.scan_headers is True
        assert profile.scan_paths is False
        assert profile.scan_vulns is False
    
    def test_get_standard_profile(self):
        profile = ScanProfile.get_profile("standard")
        
        assert profile.name == "standard"
        assert profile.scan_headers is True
        assert profile.scan_ssl is True
        assert profile.scan_paths is True
        assert profile.scan_vulns is True
    
    def test_get_comprehensive_profile(self):
        profile = ScanProfile.get_profile("comprehensive")
        
        assert profile.name == "comprehensive"
        assert profile.max_paths == 500
        assert profile.timeout == 30
    
    def test_get_passive_profile(self):
        profile = ScanProfile.get_profile("passive")
        
        assert profile.name == "passive"
        assert profile.scan_paths is False
        assert profile.scan_vulns is False
    
    def test_unknown_profile_returns_standard(self):
        profile = ScanProfile.get_profile("nonexistent")
        
        assert profile.name == "standard"


class TestTechnologyFingerprint:
    """Test TechnologyFingerprint dataclass"""
    
    def test_create_fingerprint(self):
        tech = TechnologyFingerprint(
            name="WordPress",
            version="6.0",
            category="CMS",
            confidence=0.9,
            evidence="wp-content found",
        )
        
        assert tech.name == "WordPress"
        assert tech.version == "6.0"
        assert tech.confidence == 0.9
    
    def test_fingerprint_to_dict(self):
        tech = TechnologyFingerprint(
            name="Nginx",
            version="1.24.0",
            category="Web Server",
        )
        
        d = tech.to_dict()
        
        assert d["name"] == "Nginx"
        assert d["version"] == "1.24.0"
        assert d["category"] == "Web Server"
