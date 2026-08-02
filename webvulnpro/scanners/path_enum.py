"""
Path Enumeration Scanner - Directory and file discovery
"""

import asyncio
from pathlib import Path
from typing import List, Set, Optional, Dict, Tuple
from urllib.parse import urljoin, urlparse
import aiohttp

from ..core.models import Vulnerability, Severity


class PathEnumerator:
    """Enumerate paths to discover hidden files and directories"""
    
    # Critical paths that indicate serious exposure
    CRITICAL_PATHS = {
        "/.git/config": ("Exposed Git Repository", 9.1, "CWE-538"),
        "/.git/HEAD": ("Exposed Git Repository", 9.1, "CWE-538"),
        "/.svn/entries": ("Exposed SVN Repository", 9.1, "CWE-538"),
        "/.env": ("Exposed Environment File", 9.8, "CWE-200"),
        "/config.php.bak": ("Backup Config File Exposed", 8.5, "CWE-530"),
        "/wp-config.php.bak": ("WordPress Config Backup", 8.5, "CWE-530"),
        "/config.yml": ("Exposed Configuration", 7.5, "CWE-200"),
        "/database.yml": ("Exposed Database Config", 9.1, "CWE-200"),
        "/credentials.json": ("Exposed Credentials File", 9.8, "CWE-798"),
        "/secrets.json": ("Exposed Secrets File", 9.8, "CWE-798"),
        "/id_rsa": ("Exposed Private Key", 9.8, "CWE-200"),
        "/id_rsa.pub": ("Exposed Public Key", 3.1, "CWE-200"),
        "/.htpasswd": ("Exposed htpasswd File", 7.5, "CWE-200"),
        "/.htaccess": ("Exposed htaccess File", 5.3, "CWE-200"),
        "/server-status": ("Apache Server Status Exposed", 5.3, "CWE-200"),
        "/server-info": ("Apache Server Info Exposed", 5.3, "CWE-200"),
        "/phpinfo.php": ("PHP Info Page Exposed", 5.3, "CWE-200"),
        "/info.php": ("PHP Info Page Exposed", 5.3, "CWE-200"),
        "/test.php": ("Test File Exposed", 3.1, "CWE-200"),
        "/debug": ("Debug Endpoint Exposed", 5.3, "CWE-200"),
        "/debug.php": ("Debug Page Exposed", 5.3, "CWE-200"),
        "/trace.axd": ("ASP.NET Trace Exposed", 5.3, "CWE-200"),
        "/elmah.axd": ("ELMAH Error Log Exposed", 5.3, "CWE-200"),
        "/web.config": ("Web.config Exposed", 7.5, "CWE-200"),
        "/crossdomain.xml": ("Flash Cross-Domain Policy", 3.1, "CWE-942"),
        "/clientaccesspolicy.xml": ("Silverlight Policy", 3.1, "CWE-942"),
        "/WEB-INF/web.xml": ("Java Web.xml Exposed", 7.5, "CWE-200"),
        "/META-INF/MANIFEST.MF": ("Java Manifest Exposed", 3.1, "CWE-200"),
        "/.DS_Store": ("MacOS DS_Store File", 3.1, "CWE-200"),
        "/Thumbs.db": ("Windows Thumbs.db File", 3.1, "CWE-200"),
        "/composer.json": ("Composer Dependencies", 3.1, "CWE-200"),
        "/package.json": ("NPM Package File", 3.1, "CWE-200"),
        "/Gemfile": ("Ruby Gemfile", 3.1, "CWE-200"),
        "/requirements.txt": ("Python Requirements", 3.1, "CWE-200"),
        "/api/swagger.json": ("Swagger API Docs", 3.1, "CWE-200"),
        "/swagger.json": ("Swagger API Docs", 3.1, "CWE-200"),
        "/openapi.json": ("OpenAPI Specification", 3.1, "CWE-200"),
        "/graphql": ("GraphQL Endpoint", 3.1, "CWE-200"),
        "/actuator": ("Spring Actuator Exposed", 5.3, "CWE-200"),
        "/actuator/env": ("Spring Environment Exposed", 7.5, "CWE-200"),
        "/actuator/health": ("Spring Health Endpoint", 3.1, "CWE-200"),
        "/metrics": ("Metrics Endpoint", 3.1, "CWE-200"),
        "/health": ("Health Check Endpoint", 3.1, "CWE-200"),
        "/.well-known/security.txt": ("Security.txt Found", 0.0, None),  # Info only
        "/robots.txt": ("Robots.txt Found", 0.0, None),  # Info only
        "/sitemap.xml": ("Sitemap Found", 0.0, None),  # Info only
    }
    
    # Backup file extensions
    BACKUP_EXTENSIONS = [".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp", 
                         "~", ".copy", ".1", ".2", "_backup", "_old"]
    
    # Directory listing indicators
    DIR_LISTING_PATTERNS = [
        "Index of /",
        "Directory listing for",
        "<title>Directory Listing",
        "Parent Directory</a>",
        "[To Parent Directory]",
        "Directory Listing</title>",
    ]
    
    # Common directories to check for listing
    COMMON_DIRS = ["/icons/", "/images/", "/uploads/", "/files/", "/assets/", 
                   "/static/", "/media/", "/backup/", "/backups/", "/logs/",
                   "/tmp/", "/temp/", "/data/", "/admin/", "/includes/"]
    
    def __init__(self, timeout: int = 10, user_agent: str = "WebVulnPro/1.0",
                 max_concurrent: int = 20, wordlist_path: Optional[Path] = None):
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_concurrent = max_concurrent
        self.wordlist_path = wordlist_path
        self.wordlist: List[str] = []
        self._load_wordlist()
    
    def _load_wordlist(self):
        """Load paths from wordlist file"""
        if self.wordlist_path and self.wordlist_path.exists():
            try:
                with open(self.wordlist_path) as f:
                    self.wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass
        
        # Always include critical paths
        self.wordlist.extend(self.CRITICAL_PATHS.keys())
        self.wordlist = list(set(self.wordlist))  # Deduplicate
    
    async def scan(self, target: str, session: Optional[aiohttp.ClientSession] = None,
                   max_paths: int = 500) -> List[Vulnerability]:
        """Perform path enumeration scan"""
        vulnerabilities = []
        
        close_session = False
        if session is None:
            connector = aiohttp.TCPConnector(ssl=False, limit=self.max_concurrent)
            session = aiohttp.ClientSession(connector=connector)
            close_session = True
        
        try:
            # Get baseline response for 404 detection
            baseline = await self._get_baseline(target, session)
            
            # Check critical paths first
            critical_vulns = await self._check_critical_paths(target, session, baseline)
            vulnerabilities.extend(critical_vulns)
            
            # Check for directory listing
            listing_vulns = await self._check_directory_listing(target, session)
            vulnerabilities.extend(listing_vulns)
            
            # Enumerate paths from wordlist
            if self.wordlist:
                paths_to_check = self.wordlist[:max_paths]
                enum_vulns = await self._enumerate_paths(target, paths_to_check, session, baseline)
                vulnerabilities.extend(enum_vulns)
            
            # Check for backup files of known pages
            backup_vulns = await self._check_backup_files(target, session, baseline)
            vulnerabilities.extend(backup_vulns)
            
        finally:
            if close_session:
                await session.close()
        
        return vulnerabilities
    
    async def _get_baseline(self, target: str, session: aiohttp.ClientSession) -> Dict:
        """Get baseline 404 response for comparison"""
        baseline = {
            "status": 404,
            "content_length": 0,
            "title": "",
        }
        
        try:
            random_path = urljoin(target, "/nonexistent_webvulnpro_test_12345678")
            headers = {"User-Agent": self.user_agent}
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            async with session.get(random_path, headers=headers, timeout=timeout,
                                   allow_redirects=False) as response:
                baseline["status"] = response.status
                body = await response.text()
                baseline["content_length"] = len(body)
                
                # Extract title
                import re
                title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
                if title_match:
                    baseline["title"] = title_match.group(1).lower()
                    
        except:
            pass
        
        return baseline
    
    def _is_valid_finding(self, status: int, content_length: int, title: str, baseline: Dict) -> bool:
        """Determine if response indicates a valid finding vs soft 404"""
        # Clear positive indicators
        if status in [200, 301, 302, 307, 308]:
            # Check for soft 404 by comparing to baseline
            if baseline["status"] == 200:
                # If baseline is also 200, compare content length
                if abs(content_length - baseline["content_length"]) < 100:
                    return False
                # Check if same title (common for soft 404s)
                if title and baseline["title"] and title.lower() == baseline["title"]:
                    return False
            return True
        
        return False
    
    async def _check_critical_paths(self, target: str, session: aiohttp.ClientSession,
                                     baseline: Dict) -> List[Vulnerability]:
        """Check critical security-sensitive paths"""
        vulnerabilities = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_path(path: str, info: Tuple) -> Optional[Vulnerability]:
            title, cvss, cwe = info
            url = urljoin(target, path)
            
            async with semaphore:
                try:
                    headers = {"User-Agent": self.user_agent}
                    timeout = aiohttp.ClientTimeout(total=self.timeout)
                    
                    async with session.get(url, headers=headers, timeout=timeout,
                                          allow_redirects=False) as response:
                        status = response.status
                        body = await response.text()
                        content_length = len(body)
                        
                        # Extract title
                        import re
                        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
                        page_title = title_match.group(1) if title_match else ""
                        
                        if self._is_valid_finding(status, content_length, page_title, baseline):
                            severity = Severity.CRITICAL if cvss >= 9.0 else (
                                Severity.HIGH if cvss >= 7.0 else (
                                    Severity.MEDIUM if cvss >= 4.0 else (
                                        Severity.LOW if cvss > 0 else Severity.INFO
                                    )
                                )
                            )
                            
                            return Vulnerability(
                                title=title,
                                severity=severity,
                                cvss_score=cvss,
                                description=f"Sensitive path '{path}' is accessible (HTTP {status}).",
                                remediation="Restrict access to this path or remove it from production.",
                                evidence=f"URL: {url}, Status: {status}, Size: {content_length}",
                                category="Sensitive Path Exposure",
                                cwe_id=cwe,
                            )
                except:
                    pass
            return None
        
        # Run checks concurrently
        tasks = [check_path(path, info) for path, info in self.CRITICAL_PATHS.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Vulnerability):
                vulnerabilities.append(result)
        
        return vulnerabilities
    
    async def _check_directory_listing(self, target: str, 
                                        session: aiohttp.ClientSession) -> List[Vulnerability]:
        """Check for directory listing vulnerabilities"""
        vulnerabilities = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_dir(directory: str) -> Optional[Vulnerability]:
            url = urljoin(target, directory)
            
            async with semaphore:
                try:
                    headers = {"User-Agent": self.user_agent}
                    timeout = aiohttp.ClientTimeout(total=self.timeout)
                    
                    async with session.get(url, headers=headers, timeout=timeout,
                                          allow_redirects=True) as response:
                        if response.status == 200:
                            body = await response.text()
                            
                            for pattern in self.DIR_LISTING_PATTERNS:
                                if pattern.lower() in body.lower():
                                    return Vulnerability(
                                        title=f"Directory Listing Enabled: {directory}",
                                        severity=Severity.MEDIUM,
                                        cvss_score=5.3,
                                        description=f"Directory listing is enabled for '{directory}'.",
                                        remediation="Disable directory listing in web server configuration.",
                                        evidence=f"URL: {url}",
                                        category="Misconfiguration",
                                        cwe_id="CWE-548",
                                    )
                except:
                    pass
            return None
        
        tasks = [check_dir(d) for d in self.COMMON_DIRS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Vulnerability):
                vulnerabilities.append(result)
        
        return vulnerabilities
    
    async def _enumerate_paths(self, target: str, paths: List[str],
                                session: aiohttp.ClientSession, baseline: Dict) -> List[Vulnerability]:
        """Enumerate paths from wordlist"""
        vulnerabilities = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        found_paths: Set[str] = set()
        
        async def check_path(path: str) -> Optional[Vulnerability]:
            # Skip already checked critical paths
            if path in self.CRITICAL_PATHS:
                return None
            
            url = urljoin(target, path)
            
            async with semaphore:
                try:
                    headers = {"User-Agent": self.user_agent}
                    timeout = aiohttp.ClientTimeout(total=self.timeout)
                    
                    async with session.get(url, headers=headers, timeout=timeout,
                                          allow_redirects=False) as response:
                        status = response.status
                        body = await response.text()
                        content_length = len(body)
                        
                        import re
                        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
                        page_title = title_match.group(1) if title_match else ""
                        
                        if self._is_valid_finding(status, content_length, page_title, baseline):
                            if path not in found_paths:
                                found_paths.add(path)
                                
                                # Determine severity based on path content
                                severity = Severity.INFO
                                cvss = 2.0
                                
                                if any(s in path.lower() for s in ["admin", "config", "backup", "database"]):
                                    severity = Severity.MEDIUM
                                    cvss = 4.3
                                elif any(s in path.lower() for s in [".php", ".asp", ".jsp"]):
                                    severity = Severity.LOW
                                    cvss = 3.1
                                
                                return Vulnerability(
                                    title=f"Path Discovered: {path}",
                                    severity=severity,
                                    cvss_score=cvss,
                                    description=f"Path '{path}' exists on the server.",
                                    remediation="Review if this path should be publicly accessible.",
                                    evidence=f"URL: {url}, Status: {status}",
                                    category="Path Discovery",
                                )
                except:
                    pass
            return None
        
        # Process in batches
        batch_size = 100
        for i in range(0, len(paths), batch_size):
            batch = paths[i:i + batch_size]
            tasks = [check_path(p) for p in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Vulnerability):
                    vulnerabilities.append(result)
        
        return vulnerabilities
    
    async def _check_backup_files(self, target: str, session: aiohttp.ClientSession,
                                   baseline: Dict) -> List[Vulnerability]:
        """Check for backup files of common pages"""
        vulnerabilities = []
        
        # Common pages that might have backups
        base_pages = ["index.php", "config.php", "database.php", "settings.php",
                      "wp-config.php", "configuration.php", "web.config", ".htaccess"]
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_backup(page: str, ext: str) -> Optional[Vulnerability]:
            backup_path = f"/{page}{ext}"
            url = urljoin(target, backup_path)
            
            async with semaphore:
                try:
                    headers = {"User-Agent": self.user_agent}
                    timeout = aiohttp.ClientTimeout(total=self.timeout)
                    
                    async with session.get(url, headers=headers, timeout=timeout,
                                          allow_redirects=False) as response:
                        status = response.status
                        body = await response.text()
                        content_length = len(body)
                        
                        import re
                        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
                        page_title = title_match.group(1) if title_match else ""
                        
                        if self._is_valid_finding(status, content_length, page_title, baseline):
                            return Vulnerability(
                                title=f"Backup File Exposed: {backup_path}",
                                severity=Severity.HIGH,
                                cvss_score=7.5,
                                description=f"Backup file '{backup_path}' is accessible and may contain sensitive data.",
                                remediation="Remove backup files from production server.",
                                evidence=f"URL: {url}, Status: {status}",
                                category="Backup File Exposure",
                                cwe_id="CWE-530",
                            )
                except:
                    pass
            return None
        
        tasks = []
        for page in base_pages:
            for ext in self.BACKUP_EXTENSIONS[:5]:  # Limit extensions
                tasks.append(check_backup(page, ext))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Vulnerability):
                vulnerabilities.append(result)
        
        return vulnerabilities
