"""
Tests for scanner modules
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime

from webvulnpro.core.models import Vulnerability, Severity, ScanProfile
from webvulnpro.scanners.http_headers import HTTPHeadersScanner
from webvulnpro.scanners.ssl_checker import SSLChecker
from webvulnpro.scanners.vuln_patterns import VulnPatternScanner
from webvulnpro.scanners.path_enum import PathEnumerator


class TestHTTPHeadersScanner:
    """Tests for HTTP Headers Scanner"""
    
    def test_scanner_initialization(self):
        scanner = HTTPHeadersScanner(timeout=60, user_agent="TestAgent/1.0")
        
        assert scanner.timeout == 60
        assert scanner.user_agent == "TestAgent/1.0"
    
    def test_security_headers_defined(self):
        """Verify all required security headers are checked"""
        scanner = HTTPHeadersScanner()
        
        required_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ]
        
        for header in required_headers:
            assert header in scanner.SECURITY_HEADERS
    
    def test_disclosure_headers_defined(self):
        """Verify disclosure headers are checked"""
        scanner = HTTPHeadersScanner()
        
        assert "server" in scanner.DISCLOSURE_HEADERS
        assert "x-powered-by" in scanner.DISCLOSURE_HEADERS
    
    def test_contains_version_info(self):
        """Test version detection in headers"""
        scanner = HTTPHeadersScanner()
        
        assert scanner._contains_version_info("Apache/2.4.41") is True
        assert scanner._contains_version_info("nginx/1.18.0") is True
        assert scanner._contains_version_info("Apache") is False
    
    def test_check_missing_headers(self):
        """Test missing header detection"""
        scanner = HTTPHeadersScanner()
        
        # Empty headers - should find missing security headers
        vulns = scanner._check_missing_headers({}, "https://example.com")
        
        assert len(vulns) > 0
        assert any("HSTS" in v.title or "Strict" in v.title for v in vulns)
        assert any("CSP" in v.title or "Content-Security-Policy" in v.title for v in vulns)
    
    def test_check_missing_headers_http(self):
        """HSTS should not be flagged for HTTP"""
        scanner = HTTPHeadersScanner()
        
        vulns = scanner._check_missing_headers({}, "http://example.com")
        
        # HSTS should not be in findings for HTTP
        assert not any("HSTS" in v.title for v in vulns)
    
    def test_check_disclosure_headers(self):
        """Test information disclosure detection"""
        scanner = HTTPHeadersScanner()
        
        headers = {
            "server": "Apache/2.4.41 (Ubuntu)",
            "x-powered-by": "PHP/7.4.3",
        }
        
        vulns = scanner._check_disclosure_headers(headers, "https://example.com")
        
        assert len(vulns) >= 2
        assert any("Server" in v.title for v in vulns)
        assert any("X-Powered-By" in v.title for v in vulns)
    
    def test_check_hsts_config_weak(self):
        """Test weak HSTS detection"""
        scanner = HTTPHeadersScanner()
        
        # Weak HSTS - short max-age
        headers = {"strict-transport-security": "max-age=3600"}
        vulns = scanner._check_hsts_config(headers, "https://example.com")
        
        assert len(vulns) >= 1
        assert any("max-age" in v.title.lower() or "includesubdomains" in v.title.lower() 
                   for v in vulns)
    
    def test_check_csp_unsafe_inline(self):
        """Test CSP unsafe-inline detection"""
        scanner = HTTPHeadersScanner()
        
        headers = {
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"
        }
        
        vulns = scanner._check_csp_config(headers, "https://example.com")
        
        assert any("unsafe-inline" in v.title.lower() for v in vulns)


class TestSSLChecker:
    """Tests for SSL/TLS Scanner"""
    
    def test_scanner_initialization(self):
        scanner = SSLChecker(timeout=60)
        
        assert scanner.timeout == 60
    
    def test_weak_ciphers_defined(self):
        """Verify weak ciphers are listed"""
        scanner = SSLChecker()
        
        assert "RC4" in scanner.WEAK_CIPHERS
        assert "DES" in scanner.WEAK_CIPHERS
        assert "3DES" in scanner.WEAK_CIPHERS
        assert "NULL" in scanner.WEAK_CIPHERS
    
    def test_check_cert_expiry_expired(self):
        """Test expired certificate detection"""
        scanner = SSLChecker()
        
        # Expired cert
        cert = {"notAfter": "Jan  1 00:00:00 2020 GMT"}
        vulns = scanner._check_cert_expiry(cert, "example.com")
        
        assert len(vulns) >= 1
        assert any("Expired" in v.title for v in vulns)
        assert vulns[0].severity == Severity.CRITICAL
    
    def test_check_cert_expiry_expiring_soon(self):
        """Test expiring soon certificate detection"""
        scanner = SSLChecker()
        
        # Expiring in 15 days
        from datetime import datetime, timedelta
        future = datetime.now() + timedelta(days=15)
        not_after = future.strftime("%b %d %H:%M:%S %Y GMT")
        
        cert = {"notAfter": not_after}
        vulns = scanner._check_cert_expiry(cert, "example.com")
        
        assert len(vulns) >= 1
        assert any("Expiring" in v.title for v in vulns)
    
    def test_check_self_signed(self):
        """Test self-signed certificate detection"""
        scanner = SSLChecker()
        
        cert = {
            "subject": ((("commonName", "example.com"),), (("organizationName", "Self"),)),
            "issuer": ((("commonName", "example.com"),), (("organizationName", "Self"),)),
        }
        
        vulns = scanner._check_self_signed(cert, "example.com")
        
        assert len(vulns) >= 1
        assert any("Self-Signed" in v.title for v in vulns)


class TestVulnPatternScanner:
    """Tests for Vulnerability Pattern Scanner"""
    
    def test_scanner_initialization(self):
        scanner = VulnPatternScanner(timeout=30, user_agent="Test/1.0")
        
        assert scanner.timeout == 30
        assert scanner.user_agent == "Test/1.0"
    
    def test_sql_error_patterns_defined(self):
        """Verify SQL error patterns for major databases"""
        scanner = VulnPatternScanner()
        
        assert "MySQL" in scanner.SQL_ERROR_PATTERNS
        assert "PostgreSQL" in scanner.SQL_ERROR_PATTERNS
        assert "MSSQL" in scanner.SQL_ERROR_PATTERNS
        assert "Oracle" in scanner.SQL_ERROR_PATTERNS
        assert "SQLite" in scanner.SQL_ERROR_PATTERNS
    
    def test_xss_payloads_defined(self):
        """Verify XSS payloads exist"""
        scanner = VulnPatternScanner()
        
        assert len(scanner.XSS_PAYLOADS) >= 10
        assert "<script>" in scanner.XSS_PAYLOADS[0].lower() or "alert" in scanner.XSS_PAYLOADS[0].lower()
    
    def test_tech_signatures_defined(self):
        """Verify technology signatures are loaded"""
        scanner = VulnPatternScanner()
        
        # Tech signatures are now loaded from JSON file
        assert len(scanner.tech_signatures) > 0
        assert "WordPress" in scanner.tech_signatures
        assert "Cloudflare" in scanner.tech_signatures
        assert "Apache" in scanner.tech_signatures
        assert "Laravel" in scanner.tech_signatures
    
    def test_fingerprint_technology(self):
        """Test technology fingerprinting"""
        scanner = VulnPatternScanner()
        
        headers = {"server": "nginx/1.18.0"}
        body = "powered by WordPress /wp-content/"
        cookies = {}
        
        techs = scanner._fingerprint_technologies(headers, body, cookies, "https://example.com")
        
        assert len(techs) >= 1
        tech_names = [t.name for t in techs]
        assert "WordPress" in tech_names or "Nginx" in tech_names
    
    def test_check_csrf_protection(self):
        """Test CSRF detection"""
        scanner = VulnPatternScanner()
        
        # Form without CSRF token
        body = """
        <form action="/submit" method="POST">
            <input type="text" name="username">
            <button type="submit">Submit</button>
        </form>
        """
        
        vulns = scanner._check_csrf_protection(body, "https://example.com")
        
        assert len(vulns) >= 1
        assert any("CSRF" in v.title for v in vulns)
    
    def test_check_csrf_protection_with_token(self):
        """Test CSRF detection with token present"""
        scanner = VulnPatternScanner()
        
        # Form with CSRF token
        body = """
        <form action="/submit" method="POST">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="text" name="username">
            <button type="submit">Submit</button>
        </form>
        """
        
        vulns = scanner._check_csrf_protection(body, "https://example.com")
        
        assert len(vulns) == 0
    
    def test_extract_version(self):
        """Test version extraction"""
        scanner = VulnPatternScanner()
        
        headers = {"server": "Apache/2.4.41"}
        body = ""
        
        version = scanner._extract_version("Apache", headers, body)
        
        assert version == "2.4.41"


class TestPathEnumerator:
    """Tests for Path Enumeration Scanner"""
    
    def test_scanner_initialization(self):
        scanner = PathEnumerator(timeout=10, max_concurrent=50)
        
        assert scanner.timeout == 10
        assert scanner.max_concurrent == 50
    
    def test_critical_paths_defined(self):
        """Verify critical paths are defined"""
        scanner = PathEnumerator()
        
        assert "/.git/config" in scanner.CRITICAL_PATHS
        assert "/.env" in scanner.CRITICAL_PATHS
        assert "/phpinfo.php" in scanner.CRITICAL_PATHS
    
    def test_backup_extensions_defined(self):
        """Verify backup extensions"""
        scanner = PathEnumerator()
        
        assert ".bak" in scanner.BACKUP_EXTENSIONS
        assert ".old" in scanner.BACKUP_EXTENSIONS
        assert "~" in scanner.BACKUP_EXTENSIONS
    
    def test_dir_listing_patterns(self):
        """Verify directory listing patterns"""
        scanner = PathEnumerator()
        
        assert any("Index of" in p for p in scanner.DIR_LISTING_PATTERNS)
    
    def test_is_valid_finding_200(self):
        """Test valid finding detection"""
        scanner = PathEnumerator()
        
        baseline = {"status": 404, "content_length": 100, "title": "not found"}
        
        # 200 with different content should be valid
        assert scanner._is_valid_finding(200, 5000, "admin", baseline) is True
    
    def test_is_valid_finding_soft_404(self):
        """Test soft 404 detection"""
        scanner = PathEnumerator()
        
        baseline = {"status": 200, "content_length": 100, "title": "not found"}
        
        # Same content length as baseline - soft 404
        assert scanner._is_valid_finding(200, 100, "not found", baseline) is False
    
    def test_wordlist_includes_critical(self):
        """Test that critical paths are always included"""
        scanner = PathEnumerator()
        scanner._load_wordlist()
        
        assert "/.git/config" in scanner.wordlist
        assert "/.env" in scanner.wordlist


class TestIntegration:
    """Integration tests"""
    
    def test_headers_scanner_can_be_created(self):
        """Test headers scanner creation"""
        scanner = HTTPHeadersScanner(timeout=10)
        
        # Verify the scanner is properly configured
        assert scanner is not None
        assert scanner.timeout == 10
    
    def test_all_scanners_importable(self):
        """Verify all scanners can be imported"""
        from webvulnpro.scanners import (
            HTTPHeadersScanner,
            SSLChecker,
            VulnPatternScanner,
            PathEnumerator,
        )
        
        assert HTTPHeadersScanner is not None
        assert SSLChecker is not None
        assert VulnPatternScanner is not None
        assert PathEnumerator is not None
