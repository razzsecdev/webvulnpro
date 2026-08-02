"""
HTTP Security Headers Scanner - 25+ security header checks
"""

import asyncio
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
import aiohttp

from ..core.models import Vulnerability, Severity


class HTTPHeadersScanner:
    """Comprehensive HTTP security headers analyzer"""
    
    # Security headers and their configurations
    SECURITY_HEADERS = {
        "strict-transport-security": {
            "required": True,
            "severity": Severity.HIGH,
            "cvss": 7.5,
            "cwe": "CWE-319",
            "title": "Missing HTTP Strict Transport Security (HSTS)",
            "description": "The Strict-Transport-Security header is missing. This allows attackers to perform SSL stripping attacks.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
            "min_max_age": 31536000,
        },
        "content-security-policy": {
            "required": True,
            "severity": Severity.HIGH,
            "cvss": 7.1,
            "cwe": "CWE-1021",
            "title": "Missing Content Security Policy (CSP)",
            "description": "No Content-Security-Policy header found. This makes the application vulnerable to XSS and data injection attacks.",
            "remediation": "Implement a strict CSP. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
        },
        "x-frame-options": {
            "required": True,
            "severity": Severity.MEDIUM,
            "cvss": 5.4,
            "cwe": "CWE-1021",
            "title": "Missing X-Frame-Options Header",
            "description": "X-Frame-Options header is missing. The site may be vulnerable to clickjacking attacks.",
            "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header.",
            "valid_values": ["DENY", "SAMEORIGIN"],
        },
        "x-content-type-options": {
            "required": True,
            "severity": Severity.MEDIUM,
            "cvss": 5.3,
            "cwe": "CWE-693",
            "title": "Missing X-Content-Type-Options Header",
            "description": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, potentially executing malicious content.",
            "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
            "valid_values": ["nosniff"],
        },
        "x-xss-protection": {
            "required": False,  # Deprecated but still checked
            "severity": Severity.LOW,
            "cvss": 3.1,
            "cwe": "CWE-79",
            "title": "Missing X-XSS-Protection Header",
            "description": "X-XSS-Protection header is missing. While deprecated, it provides defense-in-depth for older browsers.",
            "remediation": "Add 'X-XSS-Protection: 1; mode=block' header or use CSP instead.",
        },
        "referrer-policy": {
            "required": True,
            "severity": Severity.MEDIUM,
            "cvss": 4.3,
            "cwe": "CWE-200",
            "title": "Missing Referrer-Policy Header",
            "description": "Referrer-Policy header is missing. Sensitive information may leak via the Referer header.",
            "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' header.",
        },
        "permissions-policy": {
            "required": True,
            "severity": Severity.MEDIUM,
            "cvss": 4.3,
            "cwe": "CWE-16",
            "title": "Missing Permissions-Policy Header",
            "description": "Permissions-Policy (formerly Feature-Policy) header is missing. Browser features are not restricted.",
            "remediation": "Add Permissions-Policy header to restrict features: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        },
        "cross-origin-embedder-policy": {
            "required": False,
            "severity": Severity.LOW,
            "cvss": 3.1,
            "cwe": "CWE-346",
            "title": "Missing Cross-Origin-Embedder-Policy Header",
            "description": "COEP header is missing. Cross-origin isolation is not enabled.",
            "remediation": "Add 'Cross-Origin-Embedder-Policy: require-corp' for cross-origin isolation.",
        },
        "cross-origin-opener-policy": {
            "required": False,
            "severity": Severity.LOW,
            "cvss": 3.1,
            "cwe": "CWE-346",
            "title": "Missing Cross-Origin-Opener-Policy Header",
            "description": "COOP header is missing. The document may share its browsing context with cross-origin documents.",
            "remediation": "Add 'Cross-Origin-Opener-Policy: same-origin' header.",
        },
        "cross-origin-resource-policy": {
            "required": False,
            "severity": Severity.LOW,
            "cvss": 3.1,
            "cwe": "CWE-346",
            "title": "Missing Cross-Origin-Resource-Policy Header",
            "description": "CORP header is missing. Resources may be loaded by cross-origin contexts.",
            "remediation": "Add 'Cross-Origin-Resource-Policy: same-origin' or 'same-site' header.",
        },
        "cache-control": {
            "required": True,
            "severity": Severity.LOW,
            "cvss": 3.7,
            "cwe": "CWE-525",
            "title": "Missing or Weak Cache-Control Header",
            "description": "Cache-Control header is missing or misconfigured. Sensitive data may be cached by browsers or proxies.",
            "remediation": "For sensitive pages, add 'Cache-Control: no-store, no-cache, must-revalidate, private'",
        },
    }
    
    # Headers that should NOT be present (information disclosure)
    DISCLOSURE_HEADERS = {
        "server": {
            "severity": Severity.LOW,
            "cvss": 2.6,
            "cwe": "CWE-200",
            "title": "Server Version Disclosure",
            "description": "The Server header reveals web server software and version information.",
            "remediation": "Remove or obfuscate the Server header to hide implementation details.",
        },
        "x-powered-by": {
            "severity": Severity.LOW,
            "cvss": 2.6,
            "cwe": "CWE-200",
            "title": "Technology Stack Disclosure (X-Powered-By)",
            "description": "X-Powered-By header reveals the technology stack used by the application.",
            "remediation": "Remove the X-Powered-By header from responses.",
        },
        "x-aspnet-version": {
            "severity": Severity.LOW,
            "cvss": 2.6,
            "cwe": "CWE-200",
            "title": "ASP.NET Version Disclosure",
            "description": "X-AspNet-Version header reveals the ASP.NET version.",
            "remediation": "Remove X-AspNet-Version header via web.config or IIS configuration.",
        },
        "x-aspnetmvc-version": {
            "severity": Severity.LOW,
            "cvss": 2.6,
            "cwe": "CWE-200",
            "title": "ASP.NET MVC Version Disclosure",
            "description": "X-AspNetMvc-Version header reveals the MVC framework version.",
            "remediation": "Remove X-AspNetMvc-Version header in Application_Start.",
        },
    }
    
    # CSP directives that should be present
    CSP_DIRECTIVES = [
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "connect-src",
        "font-src",
        "object-src",
        "frame-ancestors",
        "base-uri",
        "form-action",
    ]
    
    # Dangerous CSP values
    CSP_DANGEROUS_VALUES = ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]
    
    def __init__(self, timeout: int = 30, user_agent: str = "WebVulnPro/1.0"):
        self.timeout = timeout
        self.user_agent = user_agent
    
    async def scan(self, target: str, session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """Perform complete header security scan"""
        vulnerabilities = []
        
        close_session = False
        if session is None:
            connector = aiohttp.TCPConnector(ssl=False)
            session = aiohttp.ClientSession(connector=connector)
            close_session = True
        
        try:
            headers_dict = {"User-Agent": self.user_agent}
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            async with session.get(target, headers=headers_dict, timeout=timeout, allow_redirects=True) as response:
                resp_headers = {k.lower(): v for k, v in response.headers.items()}
                
                # Check missing security headers
                vulns = self._check_missing_headers(resp_headers, target)
                vulnerabilities.extend(vulns)
                
                # Check disclosure headers
                vulns = self._check_disclosure_headers(resp_headers, target)
                vulnerabilities.extend(vulns)
                
                # Check HSTS configuration
                vulns = self._check_hsts_config(resp_headers, target)
                vulnerabilities.extend(vulns)
                
                # Check CSP configuration
                vulns = self._check_csp_config(resp_headers, target)
                vulnerabilities.extend(vulns)
                
                # Check cookie security
                vulns = self._check_cookies(response, target)
                vulnerabilities.extend(vulns)
                
        except asyncio.TimeoutError:
            vulnerabilities.append(Vulnerability(
                title="Connection Timeout",
                severity=Severity.INFO,
                cvss_score=0.0,
                description=f"Connection to {target} timed out after {self.timeout} seconds.",
                remediation="Verify target is accessible.",
                evidence=f"Timeout: {self.timeout}s",
                category="Connectivity",
            ))
        except aiohttp.ClientError as e:
            vulnerabilities.append(Vulnerability(
                title="Connection Error",
                severity=Severity.INFO,
                cvss_score=0.0,
                description=f"Could not connect to {target}: {str(e)}",
                remediation="Verify target URL is correct and accessible.",
                evidence=str(e),
                category="Connectivity",
            ))
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    def _check_missing_headers(self, headers: Dict[str, str], target: str) -> List[Vulnerability]:
        """Check for missing security headers"""
        vulnerabilities = []
        is_https = target.lower().startswith("https")
        
        for header_name, config in self.SECURITY_HEADERS.items():
            # Skip HSTS check for non-HTTPS
            if header_name == "strict-transport-security" and not is_https:
                continue
            
            if header_name not in headers:
                if config["required"]:
                    vulnerabilities.append(Vulnerability(
                        title=config["title"],
                        severity=config["severity"],
                        cvss_score=config["cvss"],
                        description=config["description"],
                        remediation=config["remediation"],
                        evidence=f"Header '{header_name}' not found in response",
                        category="HTTP Headers",
                        cwe_id=config.get("cwe"),
                        references=[
                            "https://owasp.org/www-project-secure-headers/",
                            f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_name}",
                        ],
                    ))
            else:
                # Check for valid values if specified
                if "valid_values" in config:
                    value = headers[header_name].upper()
                    # Extract directive (e.g., "SAMEORIGIN" from "SAMEORIGIN; ...")
                    value = value.split(";")[0].strip()
                    if value not in [v.upper() for v in config["valid_values"]]:
                        vulnerabilities.append(Vulnerability(
                            title=f"Invalid {header_name} Value",
                            severity=Severity.LOW,
                            cvss_score=2.0,
                            description=f"The {header_name} header has an invalid value: {headers[header_name]}",
                            remediation=f"Use one of: {', '.join(config['valid_values'])}",
                            evidence=f"{header_name}: {headers[header_name]}",
                            category="HTTP Headers",
                        ))
        
        return vulnerabilities
    
    def _check_disclosure_headers(self, headers: Dict[str, str], target: str) -> List[Vulnerability]:
        """Check for information disclosure headers"""
        vulnerabilities = []
        
        for header_name, config in self.DISCLOSURE_HEADERS.items():
            if header_name in headers:
                value = headers[header_name]
                # Only flag if it contains version info or detailed info
                if self._contains_version_info(value):
                    vulnerabilities.append(Vulnerability(
                        title=config["title"],
                        severity=config["severity"],
                        cvss_score=config["cvss"],
                        description=config["description"],
                        remediation=config["remediation"],
                        evidence=f"{header_name}: {value}",
                        category="Information Disclosure",
                        cwe_id=config.get("cwe"),
                    ))
        
        return vulnerabilities
    
    def _contains_version_info(self, value: str) -> bool:
        """Check if header value contains version information"""
        import re
        # Match version patterns like 1.0, 2.4.41, etc.
        version_pattern = r'\d+\.\d+(\.\d+)?'
        return bool(re.search(version_pattern, value))
    
    def _check_hsts_config(self, headers: Dict[str, str], target: str) -> List[Vulnerability]:
        """Check HSTS header configuration"""
        vulnerabilities = []
        
        if "strict-transport-security" not in headers:
            return vulnerabilities
        
        hsts = headers["strict-transport-security"].lower()
        
        # Check max-age
        import re
        max_age_match = re.search(r'max-age=(\d+)', hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                vulnerabilities.append(Vulnerability(
                    title="HSTS max-age Too Short",
                    severity=Severity.LOW,
                    cvss_score=3.1,
                    description=f"HSTS max-age is {max_age} seconds (less than recommended 1 year).",
                    remediation="Set max-age to at least 31536000 (1 year).",
                    evidence=f"strict-transport-security: {headers['strict-transport-security']}",
                    category="HTTP Headers",
                    cwe_id="CWE-319",
                ))
        
        # Check for includeSubDomains
        if "includesubdomains" not in hsts:
            vulnerabilities.append(Vulnerability(
                title="HSTS Missing includeSubDomains",
                severity=Severity.LOW,
                cvss_score=3.1,
                description="HSTS header does not include 'includeSubDomains' directive.",
                remediation="Add 'includeSubDomains' to HSTS header.",
                evidence=f"strict-transport-security: {headers['strict-transport-security']}",
                category="HTTP Headers",
            ))
        
        return vulnerabilities
    
    def _check_csp_config(self, headers: Dict[str, str], target: str) -> List[Vulnerability]:
        """Check Content-Security-Policy configuration"""
        vulnerabilities = []
        
        if "content-security-policy" not in headers:
            return vulnerabilities
        
        csp = headers["content-security-policy"]
        
        # Check for dangerous values
        for dangerous in self.CSP_DANGEROUS_VALUES:
            if dangerous in csp.lower():
                directive = self._find_directive_with_value(csp, dangerous)
                if dangerous == "'unsafe-inline'" and "script-src" in directive:
                    vulnerabilities.append(Vulnerability(
                        title="CSP allows unsafe-inline Scripts",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        description="Content-Security-Policy allows 'unsafe-inline' for scripts, reducing XSS protection.",
                        remediation="Remove 'unsafe-inline' from script-src and use nonces or hashes.",
                        evidence=f"CSP directive: {directive}",
                        category="HTTP Headers",
                        cwe_id="CWE-79",
                    ))
                elif dangerous == "'unsafe-eval'":
                    vulnerabilities.append(Vulnerability(
                        title="CSP allows unsafe-eval",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        description="Content-Security-Policy allows 'unsafe-eval', enabling JavaScript eval().",
                        remediation="Remove 'unsafe-eval' from CSP directives.",
                        evidence=f"CSP directive: {directive}",
                        category="HTTP Headers",
                        cwe_id="CWE-95",
                    ))
                elif dangerous == "*":
                    vulnerabilities.append(Vulnerability(
                        title="CSP uses Wildcard Source",
                        severity=Severity.MEDIUM,
                        cvss_score=4.3,
                        description="Content-Security-Policy uses wildcard (*) which allows any source.",
                        remediation="Replace wildcard with specific trusted domains.",
                        evidence=f"CSP directive: {directive}",
                        category="HTTP Headers",
                    ))
        
        # Check for missing frame-ancestors
        if "frame-ancestors" not in csp:
            vulnerabilities.append(Vulnerability(
                title="CSP Missing frame-ancestors Directive",
                severity=Severity.LOW,
                cvss_score=3.1,
                description="CSP does not include frame-ancestors directive for clickjacking protection.",
                remediation="Add 'frame-ancestors 'self'' or 'frame-ancestors 'none'' to CSP.",
                evidence=f"CSP: {csp[:100]}...",
                category="HTTP Headers",
            ))
        
        return vulnerabilities
    
    def _find_directive_with_value(self, csp: str, value: str) -> str:
        """Find which CSP directive contains a value"""
        directives = csp.split(";")
        for directive in directives:
            if value.lower() in directive.lower():
                return directive.strip()
        return csp[:100]
    
    def _check_cookies(self, response: aiohttp.ClientResponse, target: str) -> List[Vulnerability]:
        """Check cookie security attributes"""
        vulnerabilities = []
        is_https = target.lower().startswith("https")
        
        cookies = response.cookies
        for cookie in cookies.values():
            cookie_name = cookie.key
            
            # Check Secure flag
            if is_https and not cookie.get("secure"):
                vulnerabilities.append(Vulnerability(
                    title=f"Cookie Missing Secure Flag: {cookie_name}",
                    severity=Severity.MEDIUM,
                    cvss_score=4.3,
                    description=f"Cookie '{cookie_name}' is missing the Secure flag on HTTPS site.",
                    remediation="Add Secure flag to prevent cookie transmission over HTTP.",
                    evidence=f"Cookie: {cookie_name}",
                    category="Cookies",
                    cwe_id="CWE-614",
                ))
            
            # Check HttpOnly flag
            if not cookie.get("httponly"):
                vulnerabilities.append(Vulnerability(
                    title=f"Cookie Missing HttpOnly Flag: {cookie_name}",
                    severity=Severity.MEDIUM,
                    cvss_score=4.3,
                    description=f"Cookie '{cookie_name}' is missing the HttpOnly flag.",
                    remediation="Add HttpOnly flag to prevent JavaScript access to cookie.",
                    evidence=f"Cookie: {cookie_name}",
                    category="Cookies",
                    cwe_id="CWE-1004",
                ))
            
            # Check SameSite attribute
            samesite = cookie.get("samesite", "").lower()
            if not samesite or samesite == "none":
                vulnerabilities.append(Vulnerability(
                    title=f"Cookie Missing/Weak SameSite: {cookie_name}",
                    severity=Severity.LOW,
                    cvss_score=3.1,
                    description=f"Cookie '{cookie_name}' has missing or weak SameSite attribute.",
                    remediation="Set SameSite=Strict or SameSite=Lax for CSRF protection.",
                    evidence=f"Cookie: {cookie_name}, SameSite: {samesite or 'not set'}",
                    category="Cookies",
                    cwe_id="CWE-1275",
                ))
        
        return vulnerabilities
