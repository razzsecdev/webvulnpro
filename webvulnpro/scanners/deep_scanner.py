"""
Deep Scanner Module - Advanced vulnerability detection methods for WebVulnPro

This module provides comprehensive deep scanning capabilities including:
- Advanced subdomain enumeration (DNS brute-force, CT logs, permutations)
- JavaScript security analysis (secrets, endpoints, DOM sinks)
- SSRF detection and testing
- Open redirect vulnerability scanning
- CRLF injection testing
- Cache poisoning detection
- GraphQL introspection and security testing
- WebSocket security analysis
- Server-Side Template Injection (SSTI) detection
- XML External Entity (XXE) testing
- Directory traversal detection
- Backup file discovery
- Git/SVN repository exposure detection
"""

import asyncio
import base64
import hashlib
import re
import socket
import ssl
from pathlib import Path
from typing import List, Optional, Dict, Tuple, Set, Any, Union
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote
from datetime import datetime
import json

import aiohttp

from ..core.models import Vulnerability, Severity, TechnologyFingerprint


class DeepScanner:
    """
    Advanced vulnerability detection methods including:
    - Subdomain enumeration
    - JavaScript analysis
    - Parameter discovery
    - WAF detection
    - CMS vulnerability scanning
    - API endpoint discovery
    - CORS misconfiguration testing
    - Host header injection testing
    - HTTP request smuggling detection
    - Subdomain takeover detection
    - SSRF testing
    - Open redirect detection
    - CRLF injection testing
    - GraphQL security analysis
    - Backup file discovery
    - Git/SVN exposure detection
    - SSTI detection
    - XXE testing
    """
    
    def __init__(self, timeout: int = 30, user_agent: str = "WebVulnPro/1.0"):
        self.timeout = timeout
        self.user_agent = user_agent
        self.package_dir = Path(__file__).parent.parent
        
        # WAF signatures for detection
        self.waf_signatures = {
            "Cloudflare": [
                "cf-ray", "cf-cache-status", "__cfduid", "cloudflare",
                "cf-request-id", "server: cloudflare"
            ],
            "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "awswaf"],
            "Akamai": ["akamai", "x-akamai-transformed", "akamai-origin-hop"],
            "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-cdn: incapsula", "incapsula"],
            "Sucuri": ["x-sucuri-id", "sucuri", "x-sucuri-cache"],
            "ModSecurity": ["mod_security", "modsecurity", "nyob"],
            "F5 BIG-IP": ["x-wa-info", "f5", "bigip", "ts="],
            "Barracuda": ["barra_counter_session", "barracuda"],
            "Fortinet FortiWeb": ["fortiwafsid", "fortiweb"],
            "Citrix NetScaler": ["ns_af", "citrix_ns_id", "netscaler"],
            "DDoS-Guard": ["ddos-guard"],
            "Wordfence": ["wordfence"],
            "AWS CloudFront": ["x-amz-cf-pop", "x-amz-cf-id", "via.*cloudfront"],
            "Fastly": ["fastly", "x-fastly-request-id"],
            "StackPath": ["x-sp-", "stackpath"],
            "Reblaze": ["rbzid", "reblaze"],
        }
        
        # CMS detection patterns
        self.cms_patterns = {
            "WordPress": {
                "paths": ["/wp-admin/", "/wp-content/", "/wp-includes/", "/wp-login.php"],
                "headers": ["x-powered-by: php", "link: <.*>; rel=\"https://api.w.org/\""],
                "body": ["wp-content", "wp-includes", "wordpress", "/wp-json/"],
            },
            "Drupal": {
                "paths": ["/core/", "/sites/default/", "/misc/drupal.js"],
                "headers": ["x-drupal-cache", "x-generator: drupal"],
                "body": ["drupal", "sites/all", "sites/default"],
            },
            "Joomla": {
                "paths": ["/administrator/", "/components/", "/modules/", "/templates/"],
                "headers": [],
                "body": ["joomla", "/media/jui/", "com_content"],
            },
            "Magento": {
                "paths": ["/admin/", "/skin/frontend/", "/js/mage/"],
                "headers": [],
                "body": ["mage", "magento", "varien"],
            },
            "Shopify": {
                "paths": [],
                "headers": ["x-shopify-stage"],
                "body": ["shopify", "cdn.shopify.com"],
            },
            "Laravel": {
                "paths": [],
                "headers": ["set-cookie: laravel_session"],
                "body": ["laravel", "csrf-token"],
            },
            "Django": {
                "paths": ["/admin/"],
                "headers": ["set-cookie: csrftoken", "set-cookie: django"],
                "body": ["django", "csrfmiddlewaretoken"],
            },
        }
        
        # Common subdomain prefixes
        self.subdomain_wordlist: List[str] = []
        
        # CORS test origins
        self.cors_test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://localhost",
        ]
        
        # Open redirect payloads
        self.redirect_payloads = [
            "//evil.com",
            "///evil.com",
            "////evil.com",
            "https://evil.com",
            "//evil.com/%2f%2e%2e",
            "/\\evil.com",
            "/.evil.com",
            "///evil.com@good.com",
            "//evil.com?good.com",
            "https:evil.com",
            "//evil%E3%80%82com",
            "\\/\\/evil.com/",
            "/evil.com",
        ]
        
        # SSTI payloads for different engines
        self.ssti_payloads = {
            "jinja2": ["{{7*7}}", "{{config}}", "{{''.__class__.__mro__}}"],
            "freemarker": ["${7*7}", "<#assign x=7*7>${x}"],
            "velocity": ["#set($x=7*7)$x", "$class.inspect('java.lang.Runtime')"],
            "smarty": ["{$smarty.version}", "{php}echo 'test';{/php}"],
            "twig": ["{{7*7}}", "{{dump(app)}}"],
            "erb": ["<%= 7*7 %>", "<%= system('id') %>"],
            "generic": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "${{7*7}}"],
        }
        
        # Backup file extensions
        self.backup_extensions = [
            ".bak", ".backup", ".old", ".orig", ".original",
            ".save", ".saved", ".swp", ".swo", ".tmp", ".temp",
            ".copy", ".1", ".2", "~", ".inc", ".inc.old",
        ]
        
        # Sensitive backup files to check
        self.backup_files = [
            "web.config", "web.config.bak", "web.config.old",
            ".htaccess", ".htaccess.bak", ".htpasswd",
            "config.php", "config.php.bak", "config.inc.php",
            "database.yml", "database.yml.bak", "secrets.yml",
            ".env", ".env.bak", ".env.local", ".env.production",
            "settings.py", "settings.py.bak", "local_settings.py",
            "wp-config.php.bak", "configuration.php.bak",
            "appsettings.json", "appsettings.json.bak",
            "composer.json", "package.json", "Gemfile",
        ]
        
        # Git/SVN exposure paths
        self.vcs_paths = [
            "/.git/config", "/.git/HEAD", "/.git/index",
            "/.git/logs/HEAD", "/.git/COMMIT_EDITMSG",
            "/.gitignore", "/.gitattributes",
            "/.svn/entries", "/.svn/wc.db",
            "/.hg/hgrc", "/.hg/requires",
            "/.bzr/branch-format",
            "/CVS/Root", "/CVS/Entries",
        ]
    
    async def enumerate_subdomains(self, domain: str, 
                                   session: Optional[aiohttp.ClientSession] = None) -> List[str]:
        """
        Enumerate subdomains using DNS brute-force and CT logs.
        
        Args:
            domain: Target domain (e.g., example.com)
            session: Optional aiohttp session
            
        Returns:
            List of discovered subdomains
        """
        discovered: Set[str] = set()
        
        # Load subdomain wordlist
        wordlist_path = self.package_dir / "wordlists" / "subdomains.txt"
        if wordlist_path.exists():
            with open(wordlist_path) as f:
                self.subdomain_wordlist = [line.strip() for line in f if line.strip()]
        else:
            # Default common subdomains if no wordlist
            self.subdomain_wordlist = [
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
                "dns", "dns1", "dns2", "mx", "mx1", "mx2", "admin", "administrator",
                "blog", "shop", "dev", "development", "stage", "staging", "test", "testing",
                "api", "api1", "api2", "app", "apps", "m", "mobile", "web", "www2", "www3",
                "secure", "vpn", "remote", "portal", "gateway", "gw", "proxy", "cdn", "static",
                "assets", "media", "images", "img", "video", "upload", "uploads", "files",
                "download", "downloads", "beta", "alpha", "demo", "support", "help", "docs",
                "documentation", "status", "stats", "analytics", "monitor", "monitoring",
                "dashboard", "panel", "cp", "cpanel", "control", "internal", "intranet",
                "extranet", "private", "public", "corp", "corporate", "office", "home",
                "backup", "backups", "db", "database", "mysql", "postgres", "redis", "mongo",
                "elasticsearch", "kibana", "grafana", "jenkins", "gitlab", "github", "git",
                "svn", "hg", "ci", "cd", "build", "deploy", "release", "prod", "production",
                "uat", "qa", "sandbox", "lab", "labs", "research", "old", "new", "legacy",
                "v1", "v2", "v3", "api-v1", "api-v2", "rest", "graphql", "socket", "ws",
                "websocket", "auth", "oauth", "sso", "login", "signin", "signup", "register",
                "account", "accounts", "user", "users", "member", "members", "customer",
                "payment", "pay", "billing", "invoice", "order", "orders", "cart", "checkout",
                "store", "e", "en", "es", "de", "fr", "it", "pt", "ru", "cn", "jp", "kr",
            ]
        
        # DNS brute-force
        dns_results = await self._dns_bruteforce(domain)
        discovered.update(dns_results)
        
        # Certificate Transparency logs lookup
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            ct_results = await self._ct_logs_lookup(domain, session)
            discovered.update(ct_results)
            
            # Also try subdomain permutations
            perm_results = await self._subdomain_permutations(domain)
            discovered.update(perm_results)
        finally:
            if close_session:
                await session.close()
        
        return list(discovered)
    
    async def _dns_bruteforce(self, domain: str) -> Set[str]:
        """Perform DNS brute-force subdomain discovery"""
        discovered: Set[str] = set()
        
        async def check_subdomain(subdomain: str):
            fqdn = f"{subdomain}.{domain}"
            try:
                # Use socket for DNS resolution
                loop = asyncio.get_event_loop()
                await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, fqdn),
                    timeout=2.0
                )
                discovered.add(fqdn)
            except (socket.gaierror, asyncio.TimeoutError, OSError):
                pass
        
        # Run DNS checks concurrently with limit
        semaphore = asyncio.Semaphore(50)
        
        async def limited_check(subdomain: str):
            async with semaphore:
                await check_subdomain(subdomain)
        
        tasks = [limited_check(sub) for sub in self.subdomain_wordlist[:500]]  # Limit for speed
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return discovered
    
    async def _ct_logs_lookup(self, domain: str, session: aiohttp.ClientSession) -> Set[str]:
        """Query Certificate Transparency logs for subdomains"""
        discovered: Set[str] = set()
        
        # Use crt.sh API for CT log lookup
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            timeout = aiohttp.ClientTimeout(total=15)
            headers = {"User-Agent": self.user_agent}
            
            async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            if name.endswith(f".{domain}") or name == domain:
                                # Remove wildcard prefix
                                if name.startswith("*."):
                                    name = name[2:]
                                discovered.add(name)
        except Exception:
            pass
        
        return discovered
    
    async def _subdomain_permutations(self, domain: str) -> Set[str]:
        """Generate subdomain permutations based on discovered subdomains"""
        discovered: Set[str] = set()
        
        # Common permutation patterns
        permutation_patterns = [
            "dev-{}", "{}-dev", "dev{}", "{}dev",
            "test-{}", "{}-test", "test{}", "{}test",
            "stage-{}", "{}-stage", "staging-{}", "{}-staging",
            "prod-{}", "{}-prod", "production-{}", "{}-production",
            "api-{}", "{}-api", "v1-{}", "{}-v1", "v2-{}", "{}-v2",
            "new-{}", "{}-new", "old-{}", "{}-old",
            "internal-{}", "{}-internal", "external-{}", "{}-external",
            "1", "2", "01", "02", "001", "002",
        ]
        
        base_subs = ["www", "api", "app", "mail", "web", "admin"]
        
        async def check_subdomain(subdomain: str):
            fqdn = f"{subdomain}.{domain}"
            try:
                loop = asyncio.get_event_loop()
                await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, fqdn),
                    timeout=2.0
                )
                discovered.add(fqdn)
            except (socket.gaierror, asyncio.TimeoutError, OSError):
                pass
        
        semaphore = asyncio.Semaphore(30)
        
        async def limited_check(subdomain: str):
            async with semaphore:
                await check_subdomain(subdomain)
        
        # Generate permutations
        permutations_to_check = []
        for base in base_subs:
            for pattern in permutation_patterns[:10]:  # Limit patterns
                if "{}" in pattern:
                    permutations_to_check.append(pattern.format(base))
                else:
                    permutations_to_check.append(f"{base}{pattern}")
        
        tasks = [limited_check(p) for p in permutations_to_check[:100]]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return discovered
    
    async def analyze_javascript(self, target: str, 
                                 session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """
        Extract endpoints, secrets, and API keys from JavaScript files.
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            List of vulnerabilities found in JS
        """
        vulnerabilities: List[Vulnerability] = []
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            # Get main page and find JS files
            js_urls = await self._find_js_files(target, session)
            
            # Analyze each JS file
            for js_url in js_urls[:20]:  # Limit to 20 files
                vulns = await self._analyze_js_content(js_url, session)
                vulnerabilities.extend(vulns)
            
            # Check for DOM-based XSS sinks
            dom_vulns = await self._check_dom_xss(target, session)
            vulnerabilities.extend(dom_vulns)
                
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def _find_js_files(self, target: str, session: aiohttp.ClientSession) -> List[str]:
        """Find JavaScript files on the target"""
        js_urls: Set[str] = set()
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {"User-Agent": self.user_agent}
            
            async with session.get(target, headers=headers, timeout=timeout, ssl=False) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    
                    # Find script tags
                    script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
                    for match in script_pattern.finditer(html):
                        src = match.group(1)
                        if src.endswith('.js') or '.js?' in src or '/js/' in src:
                            full_url = urljoin(target, src)
                            js_urls.add(full_url)
                    
                    # Also look for inline webpack/module patterns
                    chunk_pattern = re.compile(r'["\']([^"\']*\.chunk\.js)["\']', re.I)
                    for match in chunk_pattern.finditer(html):
                        full_url = urljoin(target, match.group(1))
                        js_urls.add(full_url)
                        
        except Exception:
            pass
        
        return list(js_urls)
    
    async def _analyze_js_content(self, js_url: str, session: aiohttp.ClientSession) -> List[Vulnerability]:
        """Analyze JS file content for secrets and endpoints"""
        vulnerabilities: List[Vulnerability] = []
        
        # Patterns to look for
        secret_patterns = {
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "AWS Secret Key": r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])',
            "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
            "Google OAuth": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,}',
            "GitHub OAuth": r'github[_-]?oauth[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_]{40})',
            "Slack Token": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
            "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
            "Private Key": r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            "JWT Token": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*',
            "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
            "Firebase API Key": r'AIza[0-9A-Za-z\-_]{35}',
            "Twilio API Key": r'SK[a-fA-F0-9]{32}',
            "SendGrid API Key": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
            "Mailgun API Key": r'key-[a-zA-Z0-9]{32}',
            "Stripe API Key": r'(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}',
            "Square Access Token": r'sq0atp-[0-9A-Za-z\-_]{22}',
            "Heroku API Key": r'[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            "Generic API Key": r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
            "Generic Secret": r'["\']?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\']',
            "Password in Code": r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
            "Authorization Header": r'["\']?authorization["\']?\s*[:=]\s*["\']Bearer\s+([a-zA-Z0-9._-]+)["\']',
        }
        
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            headers = {"User-Agent": self.user_agent}
            
            async with session.get(js_url, headers=headers, timeout=timeout, ssl=False) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    for secret_type, pattern in secret_patterns.items():
                        matches = re.findall(pattern, content, re.I)
                        if matches:
                            # Avoid false positives for common patterns
                            match_str = matches[0] if isinstance(matches[0], str) else str(matches[0])
                            if len(match_str) > 8 and not match_str.lower().startswith(("example", "test", "demo", "sample")):
                                vulnerabilities.append(Vulnerability(
                                    title=f"Potential {secret_type} Exposed in JavaScript",
                                    severity=Severity.HIGH if "key" in secret_type.lower() or "token" in secret_type.lower() else Severity.MEDIUM,
                                    cvss_score=7.5 if "key" in secret_type.lower() else 5.0,
                                    description=f"A potential {secret_type} was found in JavaScript file.",
                                    remediation="Remove sensitive data from client-side JavaScript files. Use server-side proxies for API calls requiring credentials.",
                                    evidence=f"Found in: {js_url}\nPattern matched: {secret_type}",
                                    category="Information Disclosure",
                                    cwe_id="CWE-200",
                                ))
                    
                    # Look for API endpoints
                    endpoint_patterns = [
                        r'["\']/(api|v[0-9]+)/[^"\']+["\']',
                        r'fetch\(["\']([^"\']+)["\']',
                        r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
                        r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
                        r'XMLHttpRequest.*open\([^,]+,\s*["\']([^"\']+)["\']',
                        r'\$\.(get|post|ajax)\(["\']([^"\']+)["\']',
                    ]
                    
                    endpoints_found = set()
                    for pattern in endpoint_patterns:
                        matches = re.findall(pattern, content, re.I)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[-1]  # Get the URL part
                            if match.startswith('/') or match.startswith('http'):
                                endpoints_found.add(match)
                    
                    if len(endpoints_found) > 5:
                        vulnerabilities.append(Vulnerability(
                            title="Multiple API Endpoints Discovered in JavaScript",
                            severity=Severity.INFO,
                            cvss_score=0.0,
                            description=f"Found {len(endpoints_found)} API endpoints in JavaScript file.",
                            remediation="Ensure all discovered endpoints have proper authentication and authorization.",
                            evidence=f"File: {js_url}\nEndpoints found: {', '.join(list(endpoints_found)[:10])}",
                            category="Information Disclosure",
                            cwe_id="CWE-200",
                        ))
                        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _check_dom_xss(self, target: str, session: aiohttp.ClientSession) -> List[Vulnerability]:
        """Check for potential DOM-based XSS sinks in JavaScript"""
        vulnerabilities: List[Vulnerability] = []
        
        # DOM XSS sinks
        dom_sinks = [
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'\.insertAdjacentHTML\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\([^,]*["\']',
            r'setInterval\s*\([^,]*["\']',
            r'new\s+Function\s*\(',
            r'location\s*=',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
            r'location\.assign\s*\(',
            r'\.src\s*=\s*[^"\']*\+',
            r'\.href\s*=\s*[^"\']*\+',
        ]
        
        # DOM XSS sources
        dom_sources = [
            r'location\.hash',
            r'location\.search',
            r'location\.href',
            r'location\.pathname',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.referrer',
            r'window\.name',
            r'document\.cookie',
            r'localStorage\.',
            r'sessionStorage\.',
        ]
        
        try:
            js_urls = await self._find_js_files(target, session)
            
            for js_url in js_urls[:10]:
                timeout = aiohttp.ClientTimeout(total=10)
                headers = {"User-Agent": self.user_agent}
                
                async with session.get(js_url, headers=headers, timeout=timeout, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        sinks_found = []
                        sources_found = []
                        
                        for sink in dom_sinks:
                            if re.search(sink, content, re.I):
                                sinks_found.append(sink.replace('\\', ''))
                        
                        for source in dom_sources:
                            if re.search(source, content, re.I):
                                sources_found.append(source.replace('\\', ''))
                        
                        if sinks_found and sources_found:
                            vulnerabilities.append(Vulnerability(
                                title=f"Potential DOM-based XSS in {js_url.split('/')[-1]}",
                                severity=Severity.MEDIUM,
                                cvss_score=6.1,
                                description="JavaScript contains both DOM XSS sources and sinks that could be exploitable.",
                                remediation="Review and sanitize all DOM manipulation operations. Use textContent instead of innerHTML where possible.",
                                evidence=f"File: {js_url}\nSinks: {', '.join(sinks_found[:5])}\nSources: {', '.join(sources_found[:5])}",
                                category="Cross-Site Scripting",
                                cwe_id="CWE-79",
                            ))
                            break  # Only report once per target
                            
        except Exception:
            pass
        
        return vulnerabilities
    
    async def discover_parameters(self, target: str,
                                  session: Optional[aiohttp.ClientSession] = None) -> List[str]:
        """
        Discover hidden GET/POST parameters.
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            List of discovered parameters
        """
        discovered: Set[str] = set()
        
        # Load parameter wordlist
        params_path = self.package_dir / "wordlists" / "parameters.txt"
        if params_path.exists():
            with open(params_path) as f:
                param_list = [line.strip() for line in f if line.strip()]
        else:
            param_list = [
                "id", "page", "search", "query", "q", "s", "keyword", "keywords",
                "name", "user", "username", "email", "password", "pass", "pwd",
                "login", "token", "key", "api_key", "apikey", "secret", "auth",
                "redirect", "url", "next", "return", "returnUrl", "goto", "dest",
                "file", "path", "dir", "folder", "document", "doc", "download",
                "upload", "action", "cmd", "command", "exec", "execute", "run",
                "debug", "test", "admin", "format", "type", "callback", "jsonp",
                "lang", "language", "locale", "limit", "offset", "sort", "order",
                "filter", "category", "cat", "tag", "ref", "source", "utm_source",
                "view", "mode", "template", "theme", "style", "css", "js",
                "from", "to", "start", "end", "date", "time", "year", "month",
                "day", "data", "content", "text", "message", "msg", "body", "title",
                "description", "comment", "note", "item", "product", "sku", "code",
                "coupon", "discount", "price", "quantity", "qty", "amount", "total",
            ]
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {"User-Agent": self.user_agent}
            
            # Get baseline response
            async with session.get(target, headers=headers, timeout=timeout, ssl=False) as resp:
                baseline_text = await resp.text()
                baseline_length = len(baseline_text)
                baseline_status = resp.status
            
            # Test parameters
            async def test_param(param: str):
                test_url = f"{target}{'&' if '?' in target else '?'}{param}=test123"
                try:
                    async with session.get(test_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                        response_text = await resp.text()
                        response_length = len(response_text)
                        
                        # Parameter is likely processed if:
                        # 1. Response length differs significantly
                        # 2. Status code changes
                        # 3. Parameter value is reflected
                        if (abs(response_length - baseline_length) > 100 or 
                            resp.status != baseline_status or
                            "test123" in response_text):
                            discovered.add(param)
                except Exception:
                    pass
            
            # Test parameters concurrently
            semaphore = asyncio.Semaphore(20)
            
            async def limited_test(param: str):
                async with semaphore:
                    await test_param(param)
            
            tasks = [limited_test(p) for p in param_list[:100]]
            await asyncio.gather(*tasks, return_exceptions=True)
            
        finally:
            if close_session:
                await session.close()
        
        return list(discovered)
    
    async def detect_waf(self, target: str,
                         session: Optional[aiohttp.ClientSession] = None) -> Tuple[Optional[str], float]:
        """
        Identify WAF type and confidence level.
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            Tuple of (WAF name or None, confidence 0-1)
        """
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        detected_waf: Optional[str] = None
        confidence: float = 0.0
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {"User-Agent": self.user_agent}
            
            # Normal request to get headers
            async with session.get(target, headers=headers, timeout=timeout, ssl=False) as resp:
                response_headers = str(resp.headers).lower()
                
                # Check for WAF signatures in headers
                for waf_name, signatures in self.waf_signatures.items():
                    matches = 0
                    for sig in signatures:
                        if sig.lower() in response_headers:
                            matches += 1
                    
                    if matches > 0:
                        match_confidence = min(1.0, matches / len(signatures) + 0.3)
                        if match_confidence > confidence:
                            detected_waf = waf_name
                            confidence = match_confidence
            
            # If no WAF detected, try triggering it with malicious requests
            if detected_waf is None:
                payloads = [
                    "/<script>alert(1)</script>",
                    "/?id=1' OR '1'='1",
                    "/?file=../../etc/passwd",
                    "/?cmd=;cat /etc/passwd",
                ]
                
                for payload in payloads:
                    malicious_url = target.rstrip('/') + payload
                    try:
                        async with session.get(malicious_url, headers=headers, timeout=timeout, ssl=False) as resp:
                            if resp.status in [403, 406, 429, 503]:
                                response_text = await resp.text()
                                response_lower = response_text.lower()
                                
                                for waf_name, signatures in self.waf_signatures.items():
                                    for sig in signatures:
                                        if sig.lower() in response_lower:
                                            detected_waf = waf_name
                                            confidence = 0.6
                                            break
                                    if detected_waf:
                                        break
                                
                                # Generic WAF detection if blocked but not identified
                                if not detected_waf and resp.status in [403, 406]:
                                    detected_waf = "Unknown WAF"
                                    confidence = 0.4
                                
                                if detected_waf:
                                    break
                    except Exception:
                        pass
                        
        finally:
            if close_session:
                await session.close()
        
        return detected_waf, confidence
    
    async def scan_cms_vulns(self, target: str, cms: str,
                             session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """
        Check for known CMS vulnerabilities (WordPress, Drupal, Joomla).
        
        Args:
            target: Target URL
            cms: CMS type (wordpress, drupal, joomla)
            session: Optional aiohttp session
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {"User-Agent": self.user_agent}
            
            cms_lower = cms.lower()
            
            if cms_lower == "wordpress":
                vulnerabilities.extend(await self._check_wordpress(target, session, headers, timeout))
            elif cms_lower == "drupal":
                vulnerabilities.extend(await self._check_drupal(target, session, headers, timeout))
            elif cms_lower == "joomla":
                vulnerabilities.extend(await self._check_joomla(target, session, headers, timeout))
            elif cms_lower == "laravel":
                vulnerabilities.extend(await self._check_laravel(target, session, headers, timeout))
            elif cms_lower == "django":
                vulnerabilities.extend(await self._check_django(target, session, headers, timeout))
                
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def _check_wordpress(self, target: str, session: aiohttp.ClientSession,
                               headers: dict, timeout: aiohttp.ClientTimeout) -> List[Vulnerability]:
        """Check for WordPress specific vulnerabilities"""
        vulnerabilities: List[Vulnerability] = []
        
        # Check for exposed files/endpoints
        checks = [
            ("/wp-json/wp/v2/users", "WordPress User Enumeration via REST API", Severity.MEDIUM, 5.3,
             "User enumeration is possible through the WordPress REST API.",
             "Disable user enumeration by restricting access to /wp-json/wp/v2/users endpoint."),
            ("/wp-config.php.bak", "WordPress Config Backup Exposed", Severity.CRITICAL, 9.8,
             "A backup of wp-config.php containing database credentials may be accessible.",
             "Remove backup files from the web root."),
            ("/.git/config", "Git Repository Exposed", Severity.HIGH, 7.5,
             "Git repository configuration is exposed.",
             "Remove .git directory or block access via web server configuration."),
            ("/xmlrpc.php", "WordPress XML-RPC Enabled", Severity.LOW, 3.7,
             "XML-RPC is enabled which can be used for brute-force attacks.",
             "Disable XML-RPC if not needed or use a plugin to restrict access."),
            ("/wp-content/debug.log", "WordPress Debug Log Exposed", Severity.HIGH, 7.5,
             "WordPress debug log may contain sensitive information.",
             "Disable WP_DEBUG_LOG in production or move logs outside web root."),
            ("/readme.html", "WordPress Version Exposed", Severity.LOW, 2.0,
             "WordPress readme.html reveals version information.",
             "Remove or restrict access to readme.html."),
            ("/wp-json/", "WordPress REST API Accessible", Severity.INFO, 0.0,
             "WordPress REST API is accessible.",
             "Review REST API endpoints for sensitive data exposure."),
            ("/wp-content/uploads/", "WordPress Uploads Directory Listing", Severity.MEDIUM, 5.3,
             "Directory listing is enabled on uploads folder.",
             "Disable directory listing or add index file."),
            ("/wp-includes/", "WordPress Includes Directory Accessible", Severity.LOW, 2.0,
             "WordPress includes directory is accessible.",
             "Restrict access to wp-includes directory."),
        ]
        
        for path, title, severity, cvss, desc, remediation in checks:
            try:
                url = target.rstrip('/') + path
                async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # Verify it's not a custom 404
                        if 'not found' not in content.lower()[:500] and len(content) > 100:
                            vulnerabilities.append(Vulnerability(
                                title=title,
                                severity=severity,
                                cvss_score=cvss,
                                description=desc,
                                remediation=remediation,
                                evidence=f"Accessible at: {url}\nStatus: {resp.status}",
                                category="CMS Security",
                                cwe_id="CWE-200",
                            ))
            except Exception:
                pass
        
        return vulnerabilities
    
    async def _check_drupal(self, target: str, session: aiohttp.ClientSession,
                            headers: dict, timeout: aiohttp.ClientTimeout) -> List[Vulnerability]:
        """Check for Drupal specific vulnerabilities"""
        vulnerabilities: List[Vulnerability] = []
        
        checks = [
            ("/CHANGELOG.txt", "Drupal Version Exposed via CHANGELOG", Severity.LOW, 2.0,
             "Drupal CHANGELOG.txt reveals version information.",
             "Remove or restrict access to CHANGELOG.txt."),
            ("/core/CHANGELOG.txt", "Drupal Core Version Exposed", Severity.LOW, 2.0,
             "Drupal core CHANGELOG.txt reveals version information.",
             "Remove or restrict access to core/CHANGELOG.txt."),
            ("/user/register", "Drupal User Registration Enabled", Severity.INFO, 0.0,
             "User registration appears to be enabled.",
             "Review if public registration is intended."),
            ("/admin/config", "Drupal Admin Config Accessible", Severity.HIGH, 7.5,
             "Drupal admin configuration may be accessible.",
             "Restrict access to admin pages."),
            ("/sites/default/settings.php", "Drupal Settings File Exposed", Severity.CRITICAL, 9.8,
             "Drupal settings file may be accessible.",
             "Ensure settings.php is not publicly accessible."),
        ]
        
        for path, title, severity, cvss, desc, remediation in checks:
            try:
                url = target.rstrip('/') + path
                async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if 'not found' not in content.lower()[:500]:
                            vulnerabilities.append(Vulnerability(
                                title=title,
                                severity=severity,
                                cvss_score=cvss,
                                description=desc,
                                remediation=remediation,
                                evidence=f"Accessible at: {url}",
                                category="CMS Security",
                                cwe_id="CWE-200",
                            ))
            except Exception:
                pass
        
        return vulnerabilities
    
    async def _check_joomla(self, target: str, session: aiohttp.ClientSession,
                            headers: dict, timeout: aiohttp.ClientTimeout) -> List[Vulnerability]:
        """Check for Joomla specific vulnerabilities"""
        vulnerabilities: List[Vulnerability] = []
        
        checks = [
            ("/administrator/manifests/files/joomla.xml", "Joomla Version Exposed", Severity.LOW, 2.0,
             "Joomla version information is exposed.",
             "Restrict access to manifest files."),
            ("/configuration.php.bak", "Joomla Config Backup Exposed", Severity.CRITICAL, 9.8,
             "A backup of configuration.php may be accessible.",
             "Remove backup files from the web root."),
            ("/administrator/", "Joomla Admin Panel Accessible", Severity.INFO, 0.0,
             "Joomla administrator panel is accessible.",
             "Consider restricting access to admin panel."),
        ]
        
        for path, title, severity, cvss, desc, remediation in checks:
            try:
                url = target.rstrip('/') + path
                async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                    if resp.status == 200:
                        vulnerabilities.append(Vulnerability(
                            title=title,
                            severity=severity,
                            cvss_score=cvss,
                            description=desc,
                            remediation=remediation,
                            evidence=f"Accessible at: {url}",
                            category="CMS Security",
                            cwe_id="CWE-200",
                        ))
            except Exception:
                pass
        
        return vulnerabilities
    
    async def _check_laravel(self, target: str, session: aiohttp.ClientSession,
                             headers: dict, timeout: aiohttp.ClientTimeout) -> List[Vulnerability]:
        """Check for Laravel specific vulnerabilities"""
        vulnerabilities: List[Vulnerability] = []
        
        checks = [
            ("/.env", "Laravel Environment File Exposed", Severity.CRITICAL, 9.8,
             "Laravel .env file containing sensitive configuration may be accessible.",
             "Block access to .env files in web server configuration."),
            ("/storage/logs/laravel.log", "Laravel Debug Log Exposed", Severity.HIGH, 7.5,
             "Laravel debug log may contain sensitive information.",
             "Disable debug mode in production and protect log files."),
            ("/_debugbar/open", "Laravel Debugbar Enabled", Severity.MEDIUM, 5.3,
             "Laravel Debugbar is enabled in production.",
             "Disable Debugbar in production environment."),
            ("/telescope", "Laravel Telescope Enabled", Severity.HIGH, 7.5,
             "Laravel Telescope debug tool is accessible.",
             "Restrict Telescope access to authenticated users only."),
        ]
        
        for path, title, severity, cvss, desc, remediation in checks:
            try:
                url = target.rstrip('/') + path
                async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if path == "/.env" and ("APP_KEY" in content or "DB_PASSWORD" in content):
                            vulnerabilities.append(Vulnerability(
                                title=title,
                                severity=severity,
                                cvss_score=cvss,
                                description=desc,
                                remediation=remediation,
                                evidence=f"Accessible at: {url}",
                                category="CMS Security",
                                cwe_id="CWE-200",
                            ))
                        elif path != "/.env":
                            vulnerabilities.append(Vulnerability(
                                title=title,
                                severity=severity,
                                cvss_score=cvss,
                                description=desc,
                                remediation=remediation,
                                evidence=f"Accessible at: {url}",
                                category="CMS Security",
                                cwe_id="CWE-200",
                            ))
            except Exception:
                pass
        
        return vulnerabilities
    
    async def _check_django(self, target: str, session: aiohttp.ClientSession,
                            headers: dict, timeout: aiohttp.ClientTimeout) -> List[Vulnerability]:
        """Check for Django specific vulnerabilities"""
        vulnerabilities: List[Vulnerability] = []
        
        # Check for debug mode
        try:
            # Trigger a 404 and look for Django debug page
            url = target.rstrip('/') + "/a-nonexistent-page-for-testing-12345/"
            async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                content = await resp.text()
                if "You're seeing this error because you have <code>DEBUG = True</code>" in content:
                    vulnerabilities.append(Vulnerability(
                        title="Django Debug Mode Enabled",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        description="Django debug mode is enabled in production, exposing sensitive information.",
                        remediation="Set DEBUG = False in production settings.",
                        evidence=f"Debug page accessible at: {url}",
                        category="CMS Security",
                        cwe_id="CWE-200",
                    ))
        except Exception:
            pass
        
        # Check for exposed admin
        try:
            url = target.rstrip('/') + "/admin/"
            async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                content = await resp.text()
                if "Django administration" in content or "django-admin" in content.lower():
                    vulnerabilities.append(Vulnerability(
                        title="Django Admin Panel Exposed",
                        severity=Severity.INFO,
                        cvss_score=0.0,
                        description="Django admin panel is accessible at default location.",
                        remediation="Consider changing admin URL path or restricting access by IP.",
                        evidence=f"Admin panel at: {url}",
                        category="CMS Security",
                        cwe_id="CWE-200",
                    ))
        except Exception:
            pass
        
        return vulnerabilities
    
    async def discover_api_endpoints(self, target: str,
                                     session: Optional[aiohttp.ClientSession] = None) -> List[str]:
        """
        Find REST/GraphQL endpoints from robots.txt, sitemap.xml, and JS files.
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            List of discovered API endpoints
        """
        endpoints: Set[str] = set()
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {"User-Agent": self.user_agent}
            
            # Check robots.txt
            try:
                robots_url = target.rstrip('/') + "/robots.txt"
                async with session.get(robots_url, headers=headers, timeout=timeout, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        for line in content.split('\n'):
                            if line.lower().startswith(('disallow:', 'allow:')):
                                path = line.split(':', 1)[1].strip()
                                if '/api' in path.lower() or '/v1' in path or '/v2' in path:
                                    endpoints.add(path)
            except Exception:
                pass
            
            # Check sitemap.xml
            try:
                sitemap_url = target.rstrip('/') + "/sitemap.xml"
                async with session.get(sitemap_url, headers=headers, timeout=timeout, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        # Extract URLs from sitemap
                        loc_pattern = re.compile(r'<loc>([^<]+)</loc>', re.I)
                        for match in loc_pattern.finditer(content):
                            url = match.group(1)
                            if '/api' in url.lower() or '/v1' in url or '/v2' in url:
                                parsed = urlparse(url)
                                endpoints.add(parsed.path)
            except Exception:
                pass
            
            # Check common API paths
            api_paths = [
                "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
                "/rest", "/rest/api", "/graphql", "/graphiql",
                "/swagger.json", "/swagger.yaml", "/swagger/",
                "/openapi.json", "/openapi.yaml", "/api-docs",
                "/.well-known/openid-configuration",
                "/v1", "/v2", "/v3",
                "/api/docs", "/api/swagger", "/api/openapi",
                "/api/health", "/api/status", "/api/info",
                "/api/users", "/api/user", "/api/auth", "/api/login",
                "/api/me", "/api/profile", "/api/account",
                "/_api", "/__api", "/api__", "/api_",
                "/api-explorer", "/api-console",
            ]
            
            async def check_endpoint(path: str):
                try:
                    url = target.rstrip('/') + path
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                        if resp.status in [200, 401, 403, 405]:
                            endpoints.add(path)
                except Exception:
                    pass
            
            semaphore = asyncio.Semaphore(20)
            
            async def limited_check(path: str):
                async with semaphore:
                    await check_endpoint(path)
            
            tasks = [limited_check(p) for p in api_paths]
            await asyncio.gather(*tasks, return_exceptions=True)
            
        finally:
            if close_session:
                await session.close()
        
        return list(endpoints)
    
    async def check_cors(self, target: str,
                         session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """
        Test for CORS misconfigurations.
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            List of CORS vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            for test_origin in self.cors_test_origins:
                headers = {
                    "User-Agent": self.user_agent,
                    "Origin": test_origin,
                }
                
                try:
                    async with session.get(target, headers=headers, timeout=timeout, ssl=False) as resp:
                        acao = resp.headers.get('Access-Control-Allow-Origin', '')
                        acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                        
                        # Check for overly permissive CORS
                        if acao == '*':
                            vulnerabilities.append(Vulnerability(
                                title="CORS: Wildcard Access-Control-Allow-Origin",
                                severity=Severity.MEDIUM,
                                cvss_score=5.3,
                                description="The server allows requests from any origin using a wildcard (*) CORS policy.",
                                remediation="Implement a whitelist of allowed origins instead of using wildcard.",
                                evidence=f"Access-Control-Allow-Origin: *",
                                category="CORS Misconfiguration",
                                cwe_id="CWE-942",
                            ))
                            break
                        
                        # Check for reflected origin with credentials
                        if acao == test_origin and acac.lower() == 'true':
                            severity = Severity.HIGH if test_origin in ["null", "https://evil.com"] else Severity.MEDIUM
                            vulnerabilities.append(Vulnerability(
                                title="CORS: Origin Reflection with Credentials",
                                severity=severity,
                                cvss_score=8.1 if severity == Severity.HIGH else 5.3,
                                description=f"The server reflects the Origin header ({test_origin}) and allows credentials. This could allow cross-origin attacks.",
                                remediation="Validate origins against a whitelist and avoid reflecting untrusted origins with credentials enabled.",
                                evidence=f"Origin sent: {test_origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                                category="CORS Misconfiguration",
                                cwe_id="CWE-942",
                            ))
                            break
                        
                        # Check for null origin
                        if acao == "null":
                            vulnerabilities.append(Vulnerability(
                                title="CORS: Null Origin Allowed",
                                severity=Severity.MEDIUM,
                                cvss_score=5.3,
                                description="The server allows the null origin, which can be sent from sandboxed iframes.",
                                remediation="Do not allow the null origin. Validate origins against a strict whitelist.",
                                evidence=f"Access-Control-Allow-Origin: null",
                                category="CORS Misconfiguration",
                                cwe_id="CWE-942",
                            ))
                            break
                            
                except Exception:
                    pass
                    
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def test_host_header(self, target: str,
                               session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """
        Test for host header injection vulnerabilities.
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        
        close_session = False
        if session is None:
            connector = aiohttp.TCPConnector(ssl=False)
            session = aiohttp.ClientSession(connector=connector)
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            parsed = urlparse(target)
            
            # Test payloads
            payloads = [
                ("evil.com", "Host header replaced"),
                (f"{parsed.netloc}:@evil.com", "Host header port injection"),
                (f"{parsed.netloc}\r\nX-Injected: header", "Host header CRLF injection"),
            ]
            
            for payload, test_type in payloads:
                headers = {
                    "User-Agent": self.user_agent,
                    "Host": payload,
                }
                
                try:
                    async with session.get(target, headers=headers, timeout=timeout) as resp:
                        content = await resp.text()
                        
                        # Check if payload is reflected
                        if "evil.com" in content:
                            vulnerabilities.append(Vulnerability(
                                title="Host Header Injection Vulnerability",
                                severity=Severity.HIGH,
                                cvss_score=7.5,
                                description=f"The server reflects the Host header value in the response ({test_type}). This could lead to cache poisoning, password reset poisoning, or web cache deception.",
                                remediation="Validate the Host header against a whitelist of expected values. Do not use the Host header in redirect URLs or absolute links.",
                                evidence=f"Payload: {payload}\nReflected in response",
                                category="Header Injection",
                                cwe_id="CWE-644",
                            ))
                            break
                            
                except Exception:
                    pass
                    
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def test_request_smuggling(self, target: str,
                                     session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """
        Basic HTTP request smuggling detection (CL.TE and TE.CL).
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers_base = {"User-Agent": self.user_agent}
            
            # Check for Transfer-Encoding handling anomalies
            te_headers = {
                **headers_base,
                "Transfer-Encoding": "chunked",
                "Content-Length": "6",
            }
            
            try:
                async with session.post(target, headers=te_headers, data="0\r\n\r\n", timeout=timeout, ssl=False) as resp:
                    # If server doesn't reject conflicting headers, it might be vulnerable
                    if resp.status not in [400, 411, 501]:
                        vulnerabilities.append(Vulnerability(
                            title="Potential HTTP Request Smuggling Vector",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            description="The server accepts requests with conflicting Content-Length and Transfer-Encoding headers, which may indicate vulnerability to HTTP request smuggling.",
                            remediation="Configure the server to reject requests with conflicting Content-Length and Transfer-Encoding headers. Ensure proper HTTP parsing at all layers.",
                            evidence=f"Server accepted request with both Content-Length and Transfer-Encoding headers. Response status: {resp.status}",
                            category="HTTP Protocol",
                            cwe_id="CWE-444",
                        ))
            except Exception:
                pass
                
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def check_subdomain_takeover(self, subdomains: List[str],
                                       session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """
        Check for subdomain takeover vulnerabilities (dangling DNS).
        
        Args:
            subdomains: List of subdomains to check
            session: Optional aiohttp session
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        
        # Fingerprints for common services with takeover potential
        takeover_fingerprints = {
            "GitHub Pages": ["There isn't a GitHub Pages site here"],
            "Heroku": ["No such app", "herokucdn.com/error-pages"],
            "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
            "Shopify": ["Sorry, this shop is currently unavailable"],
            "Tumblr": ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
            "WordPress.com": ["Do you want to register"],
            "Ghost": ["The thing you were looking for is no longer here"],
            "Pantheon": ["The gods are wise"],
            "Fastly": ["Fastly error: unknown domain"],
            "Surge.sh": ["project not found"],
            "Zendesk": ["Help Center Closed"],
            "Unbounce": ["The requested URL was not found"],
            "UserVoice": ["This UserVoice subdomain is currently available"],
            "Bitbucket": ["Repository not found"],
            "Intercom": ["Uh oh. That page doesn't exist"],
            "Webflow": ["The page you are looking for doesn't exist"],
            "Kajabi": ["The page you were looking for doesn't exist"],
            "Tilda": ["Please renew your subscription"],
            "Readme.io": ["Project doesnt exist"],
            "Cargo": ["If you're moving your domain away"],
            "Netlify": ["Not Found - Request ID"],
            "Vercel": ["The deployment you tried to access does not exist"],
            "Azure": ["Web App - Pair with a custom domain"],
        }
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            headers = {"User-Agent": self.user_agent}
            
            async def check_subdomain(subdomain: str):
                for protocol in ["https://", "http://"]:
                    url = f"{protocol}{subdomain}"
                    try:
                        async with session.get(url, headers=headers, timeout=timeout, ssl=False, allow_redirects=True) as resp:
                            content = await resp.text()
                            content_lower = content.lower()
                            
                            for service, fingerprints in takeover_fingerprints.items():
                                for fp in fingerprints:
                                    if fp.lower() in content_lower:
                                        return Vulnerability(
                                            title=f"Potential Subdomain Takeover: {subdomain}",
                                            severity=Severity.HIGH,
                                            cvss_score=8.0,
                                            description=f"Subdomain {subdomain} appears to point to an unclaimed {service} resource, making it vulnerable to takeover.",
                                            remediation=f"Remove the DNS record for {subdomain} or claim the {service} resource.",
                                            evidence=f"URL: {url}\nMatched fingerprint: {fp}\nService: {service}",
                                            category="Subdomain Takeover",
                                            cwe_id="CWE-284",
                                        )
                            break  # Only check one protocol if successful
                    except aiohttp.ClientConnectorError:
                        # Connection error might indicate dangling CNAME
                        pass
                    except Exception:
                        pass
                return None
            
            # Check subdomains concurrently
            semaphore = asyncio.Semaphore(20)
            
            async def limited_check(subdomain: str):
                async with semaphore:
                    return await check_subdomain(subdomain)
            
            tasks = [limited_check(sub) for sub in subdomains]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Vulnerability):
                    vulnerabilities.append(result)
                    
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def test_open_redirect(self, target: str,
                                 session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """
        Test for open redirect vulnerabilities.
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {"User-Agent": self.user_agent}
            
            # Common redirect parameters
            redirect_params = [
                "redirect", "url", "next", "return", "returnUrl", "returnTo",
                "goto", "dest", "destination", "redir", "redirect_uri",
                "redirect_url", "return_url", "continue", "forward", "go",
                "target", "link", "out", "view", "ref", "site", "to",
            ]
            
            for param in redirect_params:
                for payload in self.redirect_payloads[:5]:  # Limit payloads
                    test_url = f"{target}{'&' if '?' in target else '?'}{param}={quote(payload)}"
                    
                    try:
                        async with session.get(test_url, headers=headers, timeout=timeout, 
                                              ssl=False, allow_redirects=False) as resp:
                            location = resp.headers.get('Location', '')
                            
                            if resp.status in [301, 302, 303, 307, 308]:
                                if 'evil.com' in location.lower():
                                    vulnerabilities.append(Vulnerability(
                                        title="Open Redirect Vulnerability",
                                        severity=Severity.MEDIUM,
                                        cvss_score=6.1,
                                        description=f"The application redirects to user-controlled URLs via the '{param}' parameter.",
                                        remediation="Validate and whitelist allowed redirect destinations. Use relative URLs or verify redirect targets.",
                                        evidence=f"URL: {test_url}\nRedirects to: {location}",
                                        category="Open Redirect",
                                        cwe_id="CWE-601",
                                    ))
                                    return vulnerabilities  # Found one, stop testing
                    except Exception:
                        pass
                        
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def test_crlf_injection(self, target: str,
                                  session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """
        Test for CRLF injection vulnerabilities.
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {"User-Agent": self.user_agent}
            
            # CRLF payloads
            crlf_payloads = [
                "%0d%0aX-Injected: header",
                "%0aX-Injected: header",
                "%0dX-Injected: header",
                "\r\nX-Injected: header",
                "\rX-Injected: header",
                "\nX-Injected: header",
                "%E5%98%8A%E5%98%8DX-Injected: header",  # Unicode bypass
            ]
            
            for payload in crlf_payloads:
                test_url = f"{target}{'/' if not target.endswith('/') else ''}{payload}"
                
                try:
                    async with session.get(test_url, headers=headers, timeout=timeout, 
                                          ssl=False, allow_redirects=False) as resp:
                        # Check if injected header appears in response
                        if 'X-Injected' in str(resp.headers):
                            vulnerabilities.append(Vulnerability(
                                title="CRLF Injection Vulnerability",
                                severity=Severity.MEDIUM,
                                cvss_score=6.1,
                                description="The application is vulnerable to CRLF injection, allowing HTTP response splitting.",
                                remediation="Sanitize user input by removing or encoding CR and LF characters.",
                                evidence=f"Payload: {payload}\nInjected header found in response",
                                category="CRLF Injection",
                                cwe_id="CWE-113",
                            ))
                            return vulnerabilities  # Found one, stop testing
                except Exception:
                    pass
                    
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def check_graphql_security(self, target: str,
                                     session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """
        Test GraphQL endpoint for security issues.
        
        Args:
            target: Target URL (GraphQL endpoint)
            session: Optional aiohttp session
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {
                "User-Agent": self.user_agent,
                "Content-Type": "application/json",
            }
            
            # Find GraphQL endpoint
            graphql_endpoints = [
                "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
                "/query", "/gql", "/api/gql",
            ]
            
            graphql_url = None
            
            # Check if target is already a GraphQL endpoint
            if any(ep in target for ep in graphql_endpoints):
                graphql_url = target
            else:
                # Try to find GraphQL endpoint
                for ep in graphql_endpoints:
                    test_url = target.rstrip('/') + ep
                    try:
                        async with session.get(test_url, headers=headers, timeout=timeout, ssl=False) as resp:
                            if resp.status in [200, 400, 405]:
                                graphql_url = test_url
                                break
                    except Exception:
                        pass
            
            if not graphql_url:
                return vulnerabilities
            
            # Test introspection query
            introspection_query = {
                "query": "query IntrospectionQuery { __schema { types { name fields { name } } } }"
            }
            
            try:
                async with session.post(graphql_url, headers=headers, json=introspection_query, 
                                       timeout=timeout, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if "__schema" in str(data) and "errors" not in data:
                            vulnerabilities.append(Vulnerability(
                                title="GraphQL Introspection Enabled",
                                severity=Severity.LOW,
                                cvss_score=3.0,
                                description="GraphQL introspection is enabled, exposing the complete API schema.",
                                remediation="Disable introspection in production or restrict it to authenticated users.",
                                evidence=f"Endpoint: {graphql_url}\nIntrospection query successful",
                                category="API Security",
                                cwe_id="CWE-200",
                            ))
            except Exception:
                pass
            
            # Test for verbose errors
            bad_query = {"query": "{ nonExistentField }"}
            try:
                async with session.post(graphql_url, headers=headers, json=bad_query, 
                                       timeout=timeout, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        data_str = str(data)
                        if "errors" in data and ("stack" in data_str.lower() or 
                                                  "at " in data_str or
                                                  "file " in data_str.lower()):
                            vulnerabilities.append(Vulnerability(
                                title="GraphQL Verbose Error Messages",
                                severity=Severity.LOW,
                                cvss_score=2.0,
                                description="GraphQL returns verbose error messages that may reveal internal implementation details.",
                                remediation="Sanitize error messages in production to not expose stack traces or file paths.",
                                evidence=f"Endpoint: {graphql_url}\nVerbose error response",
                                category="API Security",
                                cwe_id="CWE-209",
                            ))
            except Exception:
                pass
            
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def check_backup_files(self, target: str,
                                 session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """
        Check for exposed backup files.
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        found_files: List[str] = []
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            headers = {"User-Agent": self.user_agent}
            
            async def check_file(path: str):
                try:
                    url = target.rstrip('/') + '/' + path.lstrip('/')
                    async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                        if resp.status == 200:
                            content_type = resp.headers.get('Content-Type', '')
                            # Avoid false positives from HTML error pages
                            if 'text/html' not in content_type.lower() or resp.content_length and resp.content_length > 0:
                                content = await resp.text()
                                if 'not found' not in content.lower()[:200]:
                                    return path
                except Exception:
                    pass
                return None
            
            semaphore = asyncio.Semaphore(20)
            
            async def limited_check(path: str):
                async with semaphore:
                    return await check_file(path)
            
            # Check backup files
            tasks = [limited_check(f) for f in self.backup_files]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and isinstance(result, str):
                    found_files.append(result)
            
            if found_files:
                severity = Severity.HIGH if any(f in str(found_files) for f in ['.env', 'config', 'settings']) else Severity.MEDIUM
                vulnerabilities.append(Vulnerability(
                    title=f"Backup/Sensitive Files Exposed ({len(found_files)} found)",
                    severity=severity,
                    cvss_score=7.5 if severity == Severity.HIGH else 5.3,
                    description="Backup or sensitive configuration files are publicly accessible.",
                    remediation="Remove backup files from web root or restrict access.",
                    evidence=f"Files found: {', '.join(found_files[:10])}",
                    category="Information Disclosure",
                    cwe_id="CWE-200",
                ))
                
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def check_vcs_exposure(self, target: str,
                                 session: Optional[aiohttp.ClientSession] = None) -> List[Vulnerability]:
        """
        Check for exposed version control directories (.git, .svn, etc).
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            headers = {"User-Agent": self.user_agent}
            
            for path in self.vcs_paths:
                try:
                    url = target.rstrip('/') + path
                    async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            
                            vcs_type = "Git" if ".git" in path else "SVN" if ".svn" in path else "VCS"
                            
                            # Verify it's a real VCS file, not error page
                            if (".git" in path and ("[core]" in content or "ref:" in content or "DIRC" in content)) or \
                               (".svn" in path and ("svn" in content.lower() or "wc-format" in content)):
                                vulnerabilities.append(Vulnerability(
                                    title=f"{vcs_type} Repository Exposed",
                                    severity=Severity.HIGH,
                                    cvss_score=7.5,
                                    description=f"{vcs_type} repository files are publicly accessible, potentially exposing source code and sensitive data.",
                                    remediation=f"Remove the {vcs_type.lower()} directory from web root or block access.",
                                    evidence=f"Accessible at: {url}",
                                    category="Information Disclosure",
                                    cwe_id="CWE-200",
                                ))
                                break  # Found one, report it
                except Exception:
                    pass
                    
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def detect_cms(self, target: str,
                         session: Optional[aiohttp.ClientSession] = None) -> Optional[str]:
        """
        Detect CMS type from target.
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            CMS name or None
        """
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {"User-Agent": self.user_agent}
            
            # Get main page
            try:
                async with session.get(target, headers=headers, timeout=timeout, ssl=False) as resp:
                    content = await resp.text()
                    response_headers = str(resp.headers).lower()
                    
                    for cms_name, patterns in self.cms_patterns.items():
                        score = 0
                        
                        # Check body patterns
                        for pattern in patterns.get("body", []):
                            if pattern.lower() in content.lower():
                                score += 1
                        
                        # Check header patterns
                        for pattern in patterns.get("headers", []):
                            if pattern.lower() in response_headers:
                                score += 2
                        
                        if score >= 2:
                            return cms_name
            except Exception:
                pass
            
            # Check specific paths
            for cms_name, patterns in self.cms_patterns.items():
                for path in patterns.get("paths", [])[:2]:  # Check first 2 paths
                    try:
                        url = target.rstrip('/') + path
                        async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                            if resp.status == 200:
                                return cms_name
                    except Exception:
                        pass
                        
        finally:
            if close_session:
                await session.close()
        
        return None
    
    async def full_deep_scan(self, target: str,
                             session: Optional[aiohttp.ClientSession] = None) -> Tuple[List[Vulnerability], Dict[str, Any]]:
        """
        Run all deep scanning modules and return combined results.
        
        Args:
            target: Target URL
            session: Optional aiohttp session
            
        Returns:
            Tuple of (vulnerabilities, metadata dict with subdomains, endpoints, etc.)
        """
        vulnerabilities: List[Vulnerability] = []
        metadata: Dict[str, Any] = {}
        
        close_session = False
        if session is None:
            connector = aiohttp.TCPConnector(ssl=False, limit=50)
            session = aiohttp.ClientSession(connector=connector)
            close_session = True
        
        try:
            parsed = urlparse(target)
            domain = parsed.netloc.split(':')[0]  # Remove port if present
            
            # Run scans concurrently
            tasks = {
                "waf": self.detect_waf(target, session),
                "cors": self.check_cors(target, session),
                "host_header": self.test_host_header(target, session),
                "request_smuggling": self.test_request_smuggling(target, session),
                "javascript": self.analyze_javascript(target, session),
                "api_endpoints": self.discover_api_endpoints(target, session),
                "parameters": self.discover_parameters(target, session),
                "open_redirect": self.test_open_redirect(target, session),
                "crlf": self.test_crlf_injection(target, session),
                "graphql": self.check_graphql_security(target, session),
                "backup_files": self.check_backup_files(target, session),
                "vcs_exposure": self.check_vcs_exposure(target, session),
            }
            
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            task_names = list(tasks.keys())
            
            for i, result in enumerate(results):
                task_name = task_names[i]
                
                if isinstance(result, Exception):
                    continue
                
                if task_name == "waf":
                    if isinstance(result, tuple) and len(result) == 2:
                        waf_name, confidence = result
                        metadata["waf"] = {"name": waf_name, "confidence": confidence}
                        if waf_name:
                            vulnerabilities.append(Vulnerability(
                                title=f"WAF/CDN Detected: {waf_name}",
                                severity=Severity.INFO,
                                cvss_score=0.0,
                                description=f"A Web Application Firewall or CDN was detected: {waf_name} (confidence: {confidence:.0%})",
                                remediation="N/A - This is informational.",
                                evidence=f"WAF: {waf_name}\nConfidence: {confidence:.0%}",
                                category="Information",
                            ))
                
                elif task_name in ["cors", "host_header", "request_smuggling", "javascript", 
                                   "open_redirect", "crlf", "graphql", "backup_files", "vcs_exposure"]:
                    if isinstance(result, list):
                        vulnerabilities.extend(result)
                
                elif task_name == "api_endpoints":
                    if isinstance(result, list):
                        metadata["api_endpoints"] = result
                        if result:
                            vulnerabilities.append(Vulnerability(
                                title=f"API Endpoints Discovered ({len(result)} found)",
                                severity=Severity.INFO,
                                cvss_score=0.0,
                                description=f"Discovered {len(result)} API endpoints that should be tested for vulnerabilities.",
                                remediation="Ensure all API endpoints have proper authentication and authorization.",
                                evidence=f"Endpoints: {', '.join(result[:10]) if result else 'None'}",
                                category="Information",
                            ))
                
                elif task_name == "parameters":
                    if isinstance(result, list):
                        metadata["parameters"] = result
                        if result:
                            vulnerabilities.append(Vulnerability(
                                title=f"Hidden Parameters Discovered ({len(result)} found)",
                                severity=Severity.INFO,
                                cvss_score=0.0,
                                description=f"Discovered {len(result)} potentially active parameters.",
                                remediation="Test discovered parameters for injection vulnerabilities.",
                                evidence=f"Parameters: {', '.join(result[:10]) if result else 'None'}",
                                category="Information",
                            ))
            
            # Detect CMS and run CMS-specific checks
            cms = await self.detect_cms(target, session)
            if cms:
                metadata["cms"] = cms
                cms_vulns = await self.scan_cms_vulns(target, cms, session)
                vulnerabilities.extend(cms_vulns)
            
            # Subdomain enumeration for main domain
            if not domain.startswith('www.'):
                check_domain = domain
            else:
                check_domain = domain[4:]  # Remove www.
            
            subdomains = await self.enumerate_subdomains(check_domain, session)
            metadata["subdomains"] = subdomains
            
            if subdomains:
                # Check for subdomain takeover
                takeover_vulns = await self.check_subdomain_takeover(subdomains[:30], session)
                vulnerabilities.extend(takeover_vulns)
                
                vulnerabilities.append(Vulnerability(
                    title=f"Subdomains Discovered ({len(subdomains)} found)",
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    description=f"Discovered {len(subdomains)} subdomains for {check_domain}.",
                    remediation="Review all subdomains for proper security configuration.",
                    evidence=f"Subdomains: {', '.join(sorted(subdomains)[:20])}",
                    category="Information",
                ))
                
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities, metadata
