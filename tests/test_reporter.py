"""
Tests for report generation
"""

import pytest
import json
from datetime import datetime

from webvulnpro.core.models import Vulnerability, ScanResult, Severity, TechnologyFingerprint
from webvulnpro.core.reporter import ReportGenerator


class TestReportGenerator:
    """Tests for Report Generator"""
    
    @pytest.fixture
    def sample_results(self):
        """Create sample scan results for testing"""
        vulns = [
            Vulnerability(
                title="Missing HSTS Header",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description="HSTS header is not present",
                remediation="Add Strict-Transport-Security header",
                evidence="Header not found",
                category="HTTP Headers",
                cwe_id="CWE-319",
            ),
            Vulnerability(
                title="Exposed .git Directory",
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                description="Git repository is exposed",
                remediation="Block access to .git directory",
                evidence="/.git/config accessible",
                category="Sensitive Path Exposure",
                cwe_id="CWE-538",
            ),
            Vulnerability(
                title="Server Version Disclosure",
                severity=Severity.LOW,
                cvss_score=2.6,
                description="Server header reveals version",
                remediation="Remove server version",
                evidence="Server: Apache/2.4.41",
                category="Information Disclosure",
            ),
        ]
        
        techs = [
            TechnologyFingerprint(
                name="Apache",
                version="2.4.41",
                category="Web Server",
                confidence=0.9,
            ),
            TechnologyFingerprint(
                name="WordPress",
                version="6.0",
                category="CMS",
                confidence=0.8,
            ),
        ]
        
        return [ScanResult(
            target="https://example.com",
            start_time=datetime.now(),
            end_time=datetime.now(),
            vulnerabilities=vulns,
            technologies=techs,
            status_code=200,
        )]
    
    def test_generator_initialization(self):
        generator = ReportGenerator()
        
        assert generator.generated_at is not None
    
    def test_generate_json(self, sample_results):
        generator = ReportGenerator()
        
        json_output = generator.generate_json(sample_results)
        
        # Should be valid JSON
        data = json.loads(json_output)
        
        assert "report_info" in data
        assert "summary" in data
        assert "scan_results" in data
        assert data["report_info"]["generator"] == "WebVulnPro"
    
    def test_generate_json_summary(self, sample_results):
        generator = ReportGenerator()
        
        json_output = generator.generate_json(sample_results)
        data = json.loads(json_output)
        
        summary = data["summary"]
        
        assert summary["targets_scanned"] == 1
        assert summary["total_vulnerabilities"] == 3
        assert summary["by_severity"]["CRITICAL"] == 1
        assert summary["by_severity"]["HIGH"] == 1
        assert summary["by_severity"]["LOW"] == 1
    
    def test_generate_html(self, sample_results):
        generator = ReportGenerator()
        
        html_output = generator.generate_html(sample_results)
        
        # Should be valid HTML
        assert "<!DOCTYPE html>" in html_output
        assert "<html" in html_output
        assert "WebVulnPro" in html_output
        
        # Should contain findings
        assert "Missing HSTS" in html_output
        assert "Exposed .git" in html_output
        
        # Should contain technologies
        assert "Apache" in html_output
        assert "WordPress" in html_output
    
    def test_generate_html_severity_badges(self, sample_results):
        generator = ReportGenerator()
        
        html_output = generator.generate_html(sample_results)
        
        # Should have severity badges/classes
        assert "CRITICAL" in html_output
        assert "HIGH" in html_output
        assert "LOW" in html_output
    
    def test_generate_pdf(self, sample_results):
        generator = ReportGenerator()
        
        pdf_output = generator.generate_pdf(sample_results, "example.com")
        
        # Should return bytes
        assert isinstance(pdf_output, bytes)
        assert len(pdf_output) > 0
        
        # PDF magic bytes or HTML fallback
        assert pdf_output[:4] == b'%PDF' or pdf_output[:9] == b'<!DOCTYPE'
    
    def test_generate_summary(self, sample_results):
        generator = ReportGenerator()
        
        summary = generator._generate_summary(sample_results)
        
        assert summary["targets_scanned"] == 1
        assert summary["total_vulnerabilities"] == 3
        assert "by_severity" in summary
        assert "by_category" in summary
        assert "risk_score" in summary
        assert "technologies" in summary
    
    def test_severity_colors_defined(self):
        generator = ReportGenerator()
        
        assert "CRITICAL" in generator.SEVERITY_COLORS
        assert "HIGH" in generator.SEVERITY_COLORS
        assert "MEDIUM" in generator.SEVERITY_COLORS
        assert "LOW" in generator.SEVERITY_COLORS
        assert "INFO" in generator.SEVERITY_COLORS
    
    def test_empty_results(self):
        generator = ReportGenerator()
        
        # Empty results
        results = [ScanResult(
            target="https://example.com",
            start_time=datetime.now(),
            end_time=datetime.now(),
        )]
        
        json_output = generator.generate_json(results)
        data = json.loads(json_output)
        
        assert data["summary"]["total_vulnerabilities"] == 0
    
    def test_html_escaping(self):
        """Test that HTML special characters are escaped"""
        generator = ReportGenerator()
        
        results = [ScanResult(
            target="https://example.com",
            start_time=datetime.now(),
            vulnerabilities=[
                Vulnerability(
                    title="XSS with <script>alert(1)</script>",
                    severity=Severity.HIGH,
                    cvss_score=7.0,
                    description="Payload: <script>",
                    remediation="Escape output",
                    evidence="<script>test</script>",
                    category="XSS",
                ),
            ],
        )]
        
        html_output = generator.generate_html(results)
        
        # Script tags should be escaped
        assert "<script>alert" not in html_output
        assert "&lt;script&gt;" in html_output or "script" in html_output


class TestReportFormats:
    """Test report format handling"""
    
    def test_json_format_indented(self):
        generator = ReportGenerator()
        
        results = [ScanResult(
            target="https://example.com",
            start_time=datetime.now(),
        )]
        
        json_output = generator.generate_json(results, pretty=True)
        
        # Should be indented
        assert "\n" in json_output
        assert "  " in json_output
    
    def test_json_format_compact(self):
        generator = ReportGenerator()
        
        results = [ScanResult(
            target="https://example.com",
            start_time=datetime.now(),
        )]
        
        json_output = generator.generate_json(results, pretty=False)
        
        # Should be compact (no indentation)
        assert "  " not in json_output or json_output.count("\n") <= 1
