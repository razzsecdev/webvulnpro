"""
Vulnerability Pattern Scanner - XSS, SQLi, Open Redirect, CSRF detection
Enhanced Technology Fingerprinting with Wappalyzer-like categorization
"""

import asyncio
import re
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set, Any
from urllib.parse import urlparse, urlencode, parse_qs, urljoin, quote
import aiohttp

from ..core.models import Vulnerability, Severity, TechnologyFingerprint, TechnologyCategory


class VulnPatternScanner:
    """Scan for common web vulnerabilities using passive and active techniques"""
    
    # SQL error patterns for different databases
    SQL_ERROR_PATTERNS = {
        "MySQL": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySqlException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL server version",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Unclosed quotation mark after the character string",
            r"MySQL server version for the right syntax",
        ],
        "PostgreSQL": [
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s*syntax error at or near",
        ],
        "MSSQL": [
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"SQLServer JDBC Driver",
            r"SqlClient\.",
            r"macromedia\.jdbc\.sqlserver",
            r"\bSQL Server\b.*Driver",
            r"Warning.*mssql_",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for ODBC Drivers",
        ],
        "Oracle": [
            r"\bORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_",
            r"Warning.*ora_",
            r"oracle\.jdbc",
        ],
        "SQLite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"sqlite3\.OperationalError:",
            r"SQLite3::SQLException",
            r"SQLITE_ERROR",
        ],
    }
    
    # XSS payloads for reflection testing
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "javascript:alert(1)",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=prompt(1)>",
        "<svg/onload=alert(1)>",
        "<img src=1 onerror=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "'\"><script>alert(document.domain)</script>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
    ]
    
    # Open redirect patterns
    REDIRECT_PARAMS = ["url", "redirect", "next", "return", "returnUrl", "redir", 
                       "destination", "dest", "go", "target", "link", "out", "continue"]
    
    # Version extraction patterns for common technologies
    VERSION_PATTERNS = {
        "WordPress": [
            r'<meta name="generator" content="WordPress ([^"]+)"',
            r'wordpress[/-]?(\d+\.\d+(?:\.\d+)?)',
            r'/wp-includes/.*\?ver=([0-9.]+)',
        ],
        "Drupal": [
            r'<meta name="generator" content="Drupal ([^"]+)"',
            r'Drupal[/-]?(\d+\.\d+(?:\.\d+)?)',
            r'drupal\.js\?[^"]*v=(\d+\.\d+)',
        ],
        "Joomla": [
            r'<meta name="generator" content="Joomla[!]? - Open Source Content Management[^"]*(\d+\.\d+)',
            r'Joomla[!]?[/-]?(\d+\.\d+(?:\.\d+)?)',
        ],
        "Apache": [
            r'Server:\s*Apache/(\d+\.\d+(?:\.\d+)?)',
            r'Apache/(\d+\.\d+(?:\.\d+)?)',
        ],
        "Nginx": [
            r'Server:\s*nginx/(\d+\.\d+(?:\.\d+)?)',
            r'nginx/(\d+\.\d+(?:\.\d+)?)',
        ],
        "IIS": [
            r'Server:\s*Microsoft-IIS/(\d+\.\d+)',
            r'Microsoft-IIS/(\d+\.\d+)',
        ],
        "PHP": [
            r'X-Powered-By:\s*PHP/(\d+\.\d+(?:\.\d+)?)',
            r'PHP/(\d+\.\d+(?:\.\d+)?)',
        ],
        "jQuery": [
            r'jquery[.-](\d+\.\d+(?:\.\d+)?)',
            r'jquery\.min\.js\?.*ver=(\d+\.\d+\.\d+)',
            r'jQuery v(\d+\.\d+\.\d+)',
        ],
        "Bootstrap": [
            r'bootstrap[/-](\d+\.\d+(?:\.\d+)?)',
            r'bootstrap\.min\.css\?.*ver=(\d+\.\d+\.\d+)',
            r'Bootstrap v(\d+\.\d+\.\d+)',
        ],
        "React": [
            r'react[.-](\d+\.\d+(?:\.\d+)?)',
            r'React v(\d+\.\d+\.\d+)',
        ],
        "Vue.js": [
            r'vue[.-](\d+\.\d+(?:\.\d+)?)',
            r'Vue\.js v(\d+\.\d+\.\d+)',
        ],
        "Angular": [
            r'ng-version="(\d+\.\d+\.\d+)"',
            r'angular[/-](\d+\.\d+(?:\.\d+)?)',
        ],
        "ASP.NET": [
            r'X-AspNet-Version:\s*(\d+\.\d+(?:\.\d+)?)',
        ],
        "Next.js": [
            r'Next\.js\s+(\d+\.\d+(?:\.\d+)?)',
            r'"next":"(\d+\.\d+\.\d+)"',
        ],
        "Font Awesome": [
            r'font-awesome[/-](\d+\.\d+(?:\.\d+)?)',
            r'fontawesome[/-](\d+\.\d+(?:\.\d+)?)',
        ],
        "OpenResty": [
            r'openresty/(\d+\.\d+(?:\.\d+)?)',
        ],
        "LiteSpeed": [
            r'LiteSpeed/(\d+\.\d+(?:\.\d+)?)',
        ],
        "Varnish": [
            r'Varnish/(\d+\.\d+(?:\.\d+)?)',
            r'varnish[/-](\d+\.\d+)',
        ],
    }
    
    def __init__(self, timeout: int = 30, user_agent: str = "WebVulnPro/1.0",
                 signatures_path: Optional[Path] = None):
        self.timeout = timeout
        self.user_agent = user_agent
        self.signatures_path = signatures_path
        self.tech_signatures: Dict[str, Any] = {}
        self._load_technology_signatures()
        self._load_custom_signatures()
    
    def _load_technology_signatures(self):
        """Load technology signatures from JSON file"""
        # Default path for technology signatures
        package_dir = Path(__file__).parent.parent
        default_path = package_dir / "signatures" / "technologies.json"
        
        if default_path.exists():
            try:
                with open(default_path) as f:
                    data = json.load(f)
                    self.tech_signatures = data.get("technologies", {})
            except Exception:
                pass
    
    def _load_custom_signatures(self):
        """Load custom vulnerability signatures from JSON file"""
        if self.signatures_path and self.signatures_path.exists():
            try:
                with open(self.signatures_path) as f:
                    custom = json.load(f)
                    # Merge with defaults
                    if "sql_errors" in custom:
                        for db, patterns in custom["sql_errors"].items():
                            if db in self.SQL_ERROR_PATTERNS:
                                self.SQL_ERROR_PATTERNS[db].extend(patterns)
                            else:
                                self.SQL_ERROR_PATTERNS[db] = patterns
            except Exception:
                pass
    
    async def scan(self, target: str, session: Optional[aiohttp.ClientSession] = None,
                   scan_xss: bool = True, scan_sqli: bool = True,
                   scan_redirect: bool = True, scan_csrf: bool = True) -> Tuple[List[Vulnerability], List[TechnologyFingerprint]]:
        """Perform vulnerability pattern scan"""
        vulnerabilities = []
        technologies = []
        
        close_session = False
        if session is None:
            connector = aiohttp.TCPConnector(ssl=False)
            session = aiohttp.ClientSession(connector=connector)
            close_session = True
        
        try:
            headers = {"User-Agent": self.user_agent}
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            async with session.get(target, headers=headers, timeout=timeout, allow_redirects=True) as response:
                body = await response.text()
                resp_headers = {k.lower(): v for k, v in response.headers.items()}
                cookies = {c.key: c.value for c in response.cookies.values()}
                
                # Enhanced technology fingerprinting
                techs = self._fingerprint_technologies(resp_headers, body, cookies, target)
                technologies.extend(techs)
                
                # Check for CSRF tokens
                if scan_csrf:
                    csrf_vulns = self._check_csrf_protection(body, target)
                    vulnerabilities.extend(csrf_vulns)
                
                # Check for sensitive data exposure
                data_vulns = self._check_sensitive_data(body, target)
                vulnerabilities.extend(data_vulns)
                
                # Check error pages for info disclosure
                error_vulns = self._check_error_disclosure(body, resp_headers, target)
                vulnerabilities.extend(error_vulns)
            
            # Active tests (if URL has parameters)
            parsed = urlparse(target)
            if parsed.query:
                params = parse_qs(parsed.query)
                
                # XSS reflection testing
                if scan_xss:
                    xss_vulns = await self._test_xss_reflection(target, params, session)
                    vulnerabilities.extend(xss_vulns)
                
                # SQL injection error testing
                if scan_sqli:
                    sqli_vulns = await self._test_sql_errors(target, params, session)
                    vulnerabilities.extend(sqli_vulns)
                
                # Open redirect testing
                if scan_redirect:
                    redirect_vulns = await self._test_open_redirect(target, params, session)
                    vulnerabilities.extend(redirect_vulns)
            
        except asyncio.TimeoutError:
            pass
        except aiohttp.ClientError:
            pass
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities, technologies
    
    def _fingerprint_technologies(self, headers: Dict[str, str], body: str, 
                                   cookies: Dict[str, str], url: str) -> List[TechnologyFingerprint]:
        """Enhanced technology fingerprinting with comprehensive detection"""
        technologies = []
        detected: Dict[str, TechnologyFingerprint] = {}
        body_lower = body.lower()
        
        # Process technology signatures from JSON
        for tech_name, signatures in self.tech_signatures.items():
            confidence = 0.0
            evidence_parts = []
            
            # Check headers
            if "headers" in signatures:
                for header_key, header_val in signatures["headers"].items():
                    header_key_lower = header_key.lower()
                    if header_key_lower in headers:
                        if not header_val or header_val.lower() in headers[header_key_lower].lower():
                            confidence += 0.35
                            evidence_parts.append(f"Header: {header_key}")
            
            # Check cookies
            if "cookies" in signatures:
                for cookie_name, cookie_val in signatures["cookies"].items():
                    for key in cookies.keys():
                        if cookie_name.lower() in key.lower():
                            confidence += 0.25
                            evidence_parts.append(f"Cookie: {cookie_name}")
                            break
            
            # Check HTML patterns
            if "html" in signatures:
                for pattern in signatures["html"]:
                    if pattern.lower() in body_lower:
                        confidence += 0.2
                        evidence_parts.append(f"HTML: {pattern[:30]}")
                        break  # Only count once per type
            
            # Check scripts
            if "scripts" in signatures:
                for script in signatures["scripts"]:
                    if script.lower() in body_lower:
                        confidence += 0.25
                        evidence_parts.append(f"Script: {script[:30]}")
                        break
            
            # Check CSS
            if "css" in signatures:
                for css in signatures["css"]:
                    if css.lower() in body_lower:
                        confidence += 0.15
                        evidence_parts.append(f"CSS: {css[:30]}")
                        break
            
            # Check meta tags
            if "meta" in signatures:
                for meta_name, meta_pattern in signatures["meta"].items():
                    meta_regex = rf'<meta[^>]*name=["\']?{meta_name}["\']?[^>]*content=["\']([^"\']+)["\']'
                    match = re.search(meta_regex, body, re.IGNORECASE)
                    if match:
                        if not meta_pattern or meta_pattern.lower() in match.group(1).lower():
                            confidence += 0.3
                            evidence_parts.append(f"Meta: {meta_name}={match.group(1)[:20]}")
            
            if confidence > 0:
                # Extract version
                version = self._extract_version_enhanced(tech_name, headers, body, signatures)
                
                # Get category
                category = signatures.get("category", "Unknown")
                
                # Get website
                website = signatures.get("website")
                
                detected[tech_name] = TechnologyFingerprint(
                    name=tech_name,
                    version=version,
                    category=category,
                    confidence=min(1.0, confidence),
                    evidence=", ".join(evidence_parts[:5]),
                    website=website,
                )
        
        # Fallback to built-in detection for common techs
        builtin_techs = self._builtin_fingerprint(headers, body, cookies)
        for tech in builtin_techs:
            if tech.name not in detected:
                detected[tech.name] = tech
            elif tech.version and not detected[tech.name].version:
                detected[tech.name].version = tech.version
        
        # Process implied technologies
        for tech_name, tech in list(detected.items()):
            if tech_name in self.tech_signatures:
                implies = self.tech_signatures[tech_name].get("implies", [])
                for implied in implies:
                    if implied not in detected:
                        impl_sig = self.tech_signatures.get(implied, {})
                        detected[implied] = TechnologyFingerprint(
                            name=implied,
                            category=impl_sig.get("category", "Unknown"),
                            confidence=tech.confidence * 0.5,  # Lower confidence for implied
                            evidence=f"Implied by {tech_name}",
                            website=impl_sig.get("website"),
                        )
        
        return list(detected.values())
    
    def _builtin_fingerprint(self, headers: Dict[str, str], body: str, 
                              cookies: Dict[str, str]) -> List[TechnologyFingerprint]:
        """Built-in technology fingerprinting for common technologies"""
        technologies = []
        body_lower = body.lower()
        
        # Common technologies not in JSON
        builtin_sigs = {
            "PHP": {
                "category": "Programming Language",
                "headers": {"x-powered-by": "php"},
                "cookies": ["PHPSESSID"],
            },
            "Java": {
                "category": "Programming Language",
                "cookies": ["JSESSIONID"],
            },
            "ASP.NET": {
                "category": "Framework",
                "headers": {"x-aspnet-version": "", "x-powered-by": "asp.net"},
                "body": ["__VIEWSTATE", "__EVENTVALIDATION"],
                "cookies": ["ASP.NET_SessionId"],
            },
        }
        
        for tech_name, sigs in builtin_sigs.items():
            confidence = 0.0
            evidence = []
            
            # Check headers
            if "headers" in sigs:
                for key, val in sigs["headers"].items():
                    if key in headers:
                        if not val or val.lower() in headers[key].lower():
                            confidence += 0.4
                            evidence.append(f"Header: {key}")
            
            # Check cookies
            if "cookies" in sigs:
                for cookie in sigs["cookies"]:
                    if cookie in cookies:
                        confidence += 0.3
                        evidence.append(f"Cookie: {cookie}")
            
            # Check body
            if "body" in sigs:
                for pattern in sigs["body"]:
                    if pattern.lower() in body_lower:
                        confidence += 0.3
                        evidence.append(f"Body: {pattern}")
            
            if confidence > 0:
                version = self._extract_version(tech_name, headers, body)
                technologies.append(TechnologyFingerprint(
                    name=tech_name,
                    version=version,
                    category=sigs.get("category", "Unknown"),
                    confidence=min(1.0, confidence),
                    evidence=", ".join(evidence),
                ))
        
        return technologies
    
    def _extract_version_enhanced(self, tech: str, headers: Dict[str, str], 
                                   body: str, signatures: Dict) -> Optional[str]:
        """Enhanced version extraction using signatures and patterns"""
        # First try signature-based extraction
        version_sig = signatures.get("version", {})
        
        # Check header
        if "header" in version_sig:
            header_name = version_sig["header"].lower()
            if header_name in headers:
                header_val = headers[header_name]
                if "regex" in version_sig:
                    match = re.search(version_sig["regex"], header_val, re.IGNORECASE)
                    if match:
                        return match.group(1)
        
        # Check regex patterns
        if "regex" in version_sig:
            # Search in headers
            for val in headers.values():
                match = re.search(version_sig["regex"], val, re.IGNORECASE)
                if match:
                    return match.group(1)
            # Search in body
            match = re.search(version_sig["regex"], body, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Fallback to built-in version patterns
        return self._extract_version(tech, headers, body)
    
    def _extract_version(self, tech: str, headers: Dict[str, str], body: str) -> Optional[str]:
        """Extract version from headers or body using built-in patterns"""
        patterns = self.VERSION_PATTERNS.get(tech, [])
        
        # Combine headers for searching
        header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        combined = header_text + "\n" + body
        
        for pattern in patterns:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _check_csrf_protection(self, body: str, target: str) -> List[Vulnerability]:
        """Check for CSRF protection mechanisms"""
        vulnerabilities = []
        
        # Look for forms
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, body, re.IGNORECASE | re.DOTALL)
        
        csrf_tokens = ["csrf", "_token", "authenticity_token", "csrfmiddlewaretoken", 
                       "__RequestVerificationToken", "_csrf_token", "nonce"]
        
        forms_without_csrf = 0
        for form in forms:
            has_csrf = False
            for token in csrf_tokens:
                if token.lower() in form.lower():
                    has_csrf = True
                    break
            if not has_csrf:
                forms_without_csrf += 1
        
        if forms_without_csrf > 0:
            vulnerabilities.append(Vulnerability(
                title="Forms Missing CSRF Protection",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description=f"Found {forms_without_csrf} form(s) without visible CSRF token protection.",
                remediation="Implement CSRF tokens in all state-changing forms.",
                evidence=f"{forms_without_csrf} forms without csrf tokens detected",
                category="CSRF",
                cwe_id="CWE-352",
                references=["https://owasp.org/www-community/attacks/csrf"],
            ))
        
        return vulnerabilities
    
    def _check_sensitive_data(self, body: str, target: str) -> List[Vulnerability]:
        """Check for sensitive data exposure in response"""
        vulnerabilities = []
        
        # Patterns for sensitive data
        patterns = {
            "Email Address": (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', Severity.INFO, 2.0),
            "AWS Access Key": (r'AKIA[0-9A-Z]{16}', Severity.CRITICAL, 9.8),
            "AWS Secret Key": (r'[A-Za-z0-9/+=]{40}', Severity.CRITICAL, 9.8),
            "Private Key": (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', Severity.CRITICAL, 9.8),
            "API Key Pattern": (r'api[_-]?key[\'"\s:=]+[\'"]?([a-zA-Z0-9]{20,})', Severity.HIGH, 7.5),
            "Password in URL": (r'password[=:][^\s&]+', Severity.HIGH, 7.5),
            "Internal IP": (r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', Severity.LOW, 3.1),
            "SQL Query": (r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+\*?\s*(?:FROM|INTO|SET)?\s*\w+', Severity.MEDIUM, 5.3),
        }
        
        for name, (pattern, severity, cvss) in patterns.items():
            if name in ["Email Address", "Internal IP"]:
                # Don't report common false positives
                continue
            
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                # Limit to first few matches
                sample = matches[:3]
                if name == "Private Key":
                    vulnerabilities.append(Vulnerability(
                        title=f"Sensitive Data Exposure: {name}",
                        severity=severity,
                        cvss_score=cvss,
                        description=f"Detected {name} in response body.",
                        remediation="Remove sensitive data from public responses immediately.",
                        evidence=f"Pattern: {name} found",
                        category="Information Disclosure",
                        cwe_id="CWE-200",
                    ))
                elif name == "AWS Access Key":
                    vulnerabilities.append(Vulnerability(
                        title=f"Exposed AWS Credentials",
                        severity=severity,
                        cvss_score=cvss,
                        description="AWS Access Key ID found in response.",
                        remediation="Rotate exposed credentials immediately.",
                        evidence=f"Found: {sample[0][:10]}...",
                        category="Information Disclosure",
                        cwe_id="CWE-798",
                    ))
        
        return vulnerabilities
    
    def _check_error_disclosure(self, body: str, headers: Dict[str, str], 
                                 target: str) -> List[Vulnerability]:
        """Check for error messages that disclose sensitive information"""
        vulnerabilities = []
        
        # Stack trace patterns
        stack_patterns = [
            (r'at\s+[\w\.$]+\([\w]+\.java:\d+\)', "Java Stack Trace"),
            (r'File\s+"[^"]+",\s+line\s+\d+', "Python Stack Trace"),
            (r'in\s+[\w\\\/]+\.php\s+on\s+line\s+\d+', "PHP Error"),
            (r'at\s+[\w\.]+\s+in\s+[\w:\\\/]+:\d+', ".NET Stack Trace"),
            (r'Parse error:\s+syntax error', "PHP Parse Error"),
            (r'Fatal error:\s+', "PHP Fatal Error"),
            (r'Warning:\s+\w+\(\)', "PHP Warning"),
            (r'Traceback \(most recent call last\)', "Python Traceback"),
            (r'Error:\s+ENOENT:', "Node.js Error"),
        ]
        
        for pattern, error_type in stack_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    title=f"Application Error Disclosure: {error_type}",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=f"Application error message ({error_type}) is exposed in response.",
                    remediation="Configure custom error pages and disable debug mode in production.",
                    evidence=f"Pattern: {error_type}",
                    category="Information Disclosure",
                    cwe_id="CWE-209",
                ))
                break  # One finding is enough
        
        return vulnerabilities
    
    async def _test_xss_reflection(self, target: str, params: Dict[str, List[str]],
                                    session: aiohttp.ClientSession) -> List[Vulnerability]:
        """Test for XSS reflection vulnerabilities"""
        vulnerabilities = []
        parsed = urlparse(target)
        
        # Test only first 5 payloads to be safe and fast
        test_payloads = self.XSS_PAYLOADS[:5]
        
        for param_name in params.keys():
            for payload in test_payloads:
                # Build test URL
                test_params = params.copy()
                test_params[param_name] = [payload]
                query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                
                try:
                    headers = {"User-Agent": self.user_agent}
                    timeout = aiohttp.ClientTimeout(total=10)
                    
                    async with session.get(test_url, headers=headers, timeout=timeout, 
                                          allow_redirects=True) as response:
                        body = await response.text()
                        
                        # Check if payload is reflected without encoding
                        if payload in body:
                            vulnerabilities.append(Vulnerability(
                                title=f"Potential XSS Reflection in '{param_name}'",
                                severity=Severity.HIGH,
                                cvss_score=6.1,
                                description=f"Parameter '{param_name}' reflects input without proper encoding.",
                                remediation="Implement proper output encoding for all user input.",
                                evidence=f"Payload reflected: {payload[:50]}...",
                                category="XSS",
                                cwe_id="CWE-79",
                                request=test_url[:200],
                                references=["https://owasp.org/www-community/attacks/xss/"],
                            ))
                            break  # Found XSS in this param, move to next
                            
                except:
                    continue
        
        return vulnerabilities
    
    async def _test_sql_errors(self, target: str, params: Dict[str, List[str]],
                                session: aiohttp.ClientSession) -> List[Vulnerability]:
        """Test for SQL injection error-based detection"""
        vulnerabilities = []
        parsed = urlparse(target)
        
        # SQL injection test payloads
        sqli_payloads = ["'", "\"", "' OR '1'='1", "1' AND '1'='2", "1; DROP TABLE--"]
        
        for param_name in params.keys():
            for payload in sqli_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                
                try:
                    headers = {"User-Agent": self.user_agent}
                    timeout = aiohttp.ClientTimeout(total=10)
                    
                    async with session.get(test_url, headers=headers, timeout=timeout,
                                          allow_redirects=True) as response:
                        body = await response.text()
                        
                        # Check for SQL error patterns
                        for db_name, patterns in self.SQL_ERROR_PATTERNS.items():
                            for pattern in patterns:
                                if re.search(pattern, body, re.IGNORECASE):
                                    vulnerabilities.append(Vulnerability(
                                        title=f"Potential SQL Injection ({db_name}) in '{param_name}'",
                                        severity=Severity.CRITICAL,
                                        cvss_score=9.8,
                                        description=f"SQL error from {db_name} detected when testing parameter '{param_name}'.",
                                        remediation="Use parameterized queries/prepared statements.",
                                        evidence=f"Payload: {payload}, Database: {db_name}",
                                        category="SQL Injection",
                                        cwe_id="CWE-89",
                                        request=test_url[:200],
                                        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                                    ))
                                    return vulnerabilities  # Critical finding, return immediately
                except:
                    continue
        
        return vulnerabilities
    
    async def _test_open_redirect(self, target: str, params: Dict[str, List[str]],
                                   session: aiohttp.ClientSession) -> List[Vulnerability]:
        """Test for open redirect vulnerabilities"""
        vulnerabilities = []
        parsed = urlparse(target)
        
        # Check if any param name suggests redirect functionality
        redirect_params = [p for p in params.keys() if p.lower() in self.REDIRECT_PARAMS]
        
        for param_name in redirect_params:
            # Test with external domain
            test_value = "https://evil.com"
            test_params = params.copy()
            test_params[param_name] = [test_value]
            query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
            
            try:
                headers = {"User-Agent": self.user_agent}
                timeout = aiohttp.ClientTimeout(total=10)
                
                async with session.get(test_url, headers=headers, timeout=timeout,
                                       allow_redirects=False) as response:
                    location = response.headers.get("Location", "")
                    
                    if "evil.com" in location.lower():
                        vulnerabilities.append(Vulnerability(
                            title=f"Open Redirect in '{param_name}'",
                            severity=Severity.MEDIUM,
                            cvss_score=4.7,
                            description=f"Parameter '{param_name}' allows redirection to external domains.",
                            remediation="Validate redirect URLs against a whitelist of allowed domains.",
                            evidence=f"Redirects to: {location}",
                            category="Open Redirect",
                            cwe_id="CWE-601",
                            references=["https://cwe.mitre.org/data/definitions/601.html"],
                        ))
            except:
                continue
        
        return vulnerabilities
    
    def group_technologies_by_category(self, technologies: List[TechnologyFingerprint]) -> Dict[str, List[TechnologyFingerprint]]:
        """Group technologies by their category for display"""
        grouped: Dict[str, List[TechnologyFingerprint]] = {}
        
        # Define category display order
        category_order = [
            "CMS", "E-commerce", "Framework", "JavaScript Framework", 
            "JavaScript Library", "UI Framework", "Programming Language",
            "Web Server", "Operating System", "Database", "Cache",
            "CDN", "WAF", "Security", "Hosting", "PaaS",
            "Analytics", "Tag Manager", "Font", "Payment", "SEO",
            "Live Chat", "Comment", "Video", "Search", "Build Tool",
            "Static Site Generator", "Miscellaneous", "Unknown"
        ]
        
        for tech in technologies:
            category = tech.category
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(tech)
        
        # Sort by confidence within each category
        for category in grouped:
            grouped[category].sort(key=lambda t: t.confidence, reverse=True)
        
        # Return in ordered format
        ordered: Dict[str, List[TechnologyFingerprint]] = {}
        for cat in category_order:
            if cat in grouped:
                ordered[cat] = grouped[cat]
        
        # Add any remaining categories not in our order
        for cat in grouped:
            if cat not in ordered:
                ordered[cat] = grouped[cat]
        
        return ordered
