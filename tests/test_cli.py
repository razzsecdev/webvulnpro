"""
Tests for CLI interface
"""

import pytest
from typer.testing import CliRunner
from unittest.mock import patch, AsyncMock

runner = CliRunner()


class TestCLI:
    """Tests for CLI commands"""
    
    def test_version_flag(self):
        """Test --version flag"""
        from webvulnpro.cli import app
        
        result = runner.invoke(app, ["--version"])
        
        assert result.exit_code == 0
        assert "WebVulnPro" in result.stdout
        assert "1.0.0" in result.stdout
    
    def test_profiles_command(self):
        """Test profiles command"""
        from webvulnpro.cli import app
        
        result = runner.invoke(app, ["profiles"])
        
        assert result.exit_code == 0
        assert "quick" in result.stdout
        assert "standard" in result.stdout
        assert "comprehensive" in result.stdout
        assert "passive" in result.stdout
    
    def test_scan_missing_target(self):
        """Test scan without target"""
        from webvulnpro.cli import app
        
        result = runner.invoke(app, ["scan"])
        
        # Should fail - missing required argument
        assert result.exit_code != 0
    
    def test_headers_missing_target(self):
        """Test headers without target"""
        from webvulnpro.cli import app
        
        result = runner.invoke(app, ["headers"])
        
        # Should fail - missing required argument
        assert result.exit_code != 0
    
    def test_ssl_missing_target(self):
        """Test ssl without target"""
        from webvulnpro.cli import app
        
        result = runner.invoke(app, ["ssl"])
        
        # Should fail - missing required argument
        assert result.exit_code != 0
    
    def test_paths_missing_target(self):
        """Test paths without target"""
        from webvulnpro.cli import app
        
        result = runner.invoke(app, ["paths"])
        
        # Should fail - missing required argument
        assert result.exit_code != 0


class TestCLIHelpers:
    """Tests for CLI helper functions"""
    
    def test_resolve_targets_url(self):
        """Test target resolution for URLs"""
        from webvulnpro.cli import _resolve_targets
        
        targets = _resolve_targets(["https://example.com", "https://test.com"])
        
        assert len(targets) == 2
        assert "https://example.com" in targets
        assert "https://test.com" in targets
    
    def test_resolve_targets_from_file(self, tmp_path):
        """Test target resolution from file"""
        from webvulnpro.cli import _resolve_targets
        
        # Create temp file with targets
        target_file = tmp_path / "targets.txt"
        target_file.write_text("https://example.com\nhttps://test.com\n# comment\n")
        
        targets = _resolve_targets([str(target_file)])
        
        assert len(targets) == 2
        assert "https://example.com" in targets
        assert "https://test.com" in targets
    
    def test_banner_function(self):
        """Test banner printing"""
        from webvulnpro.cli import _print_banner
        from io import StringIO
        from rich.console import Console
        
        # Just verify it doesn't crash
        _print_banner()
