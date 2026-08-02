"""
Core Scanner Orchestrator - Coordinates all scanning modules including deep scanning
"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
import aiohttp

from .models import Vulnerability, ScanResult, ScanProfile, TechnologyFingerprint, Severity
from ..scanners.http_headers import HTTPHeadersScanner
from ..scanners.ssl_checker import SSLChecker
from ..scanners.vuln_patterns import VulnPatternScanner
from ..scanners.path_enum import PathEnumerator


class WebVulnScanner:
    """Main vulnerability scanner orchestrator with deep scanning capabilities"""
    
    def __init__(self, profile: Optional[ScanProfile] = None,
                 signatures_path: Optional[Path] = None,
                 wordlist_path: Optional[Path] = None):
        """
        Initialize the scanner with configuration.
        
        Args:
            profile: Scan profile configuration
            signatures_path: Path to vulnerability signatures JSON
            wordlist_path: Path to path enumeration wordlist
        """
        self.profile = profile or ScanProfile.get_profile("standard")
        self.signatures_path = signatures_path
        self.wordlist_path = wordlist_path
        
        # Initialize standard scanners
        self.header_scanner = HTTPHeadersScanner(
            timeout=self.profile.timeout,
            user_agent=self.profile.user_agent,
        )
        self.ssl_scanner = SSLChecker(timeout=self.profile.timeout)
        self.vuln_scanner = VulnPatternScanner(
            timeout=self.profile.timeout,
            user_agent=self.profile.user_agent,
            signatures_path=signatures_path,
        )
        self.path_scanner = PathEnumerator(
            timeout=min(10, self.profile.timeout),  # Faster timeout for path enum
            user_agent=self.profile.user_agent,
            wordlist_path=wordlist_path,
        )
        
        # Initialize deep scanner if needed
        self.deep_scanner = None
        self._init_deep_scanner()
    
    def _init_deep_scanner(self):
        """Initialize deep scanner if profile enables deep scanning"""
        if self._requires_deep_scanning():
            try:
                from ..scanners.deep_scanner import DeepScanner
                self.deep_scanner = DeepScanner(
                    timeout=self.profile.timeout,
                    user_agent=self.profile.user_agent,
                )
            except ImportError:
                pass
    
    def _requires_deep_scanning(self) -> bool:
        """Check if profile requires deep scanning modules"""
        return any([
            getattr(self.profile, 'scan_subdomains', False),
            getattr(self.profile, 'scan_javascript', False),
            getattr(self.profile, 'scan_cors', False),
            getattr(self.profile, 'scan_cms', False),
            getattr(self.profile, 'scan_waf', False),
            getattr(self.profile, 'scan_api_endpoints', False),
            getattr(self.profile, 'scan_parameters', False),
            getattr(self.profile, 'scan_host_header', False),
            getattr(self.profile, 'scan_request_smuggling', False),
            getattr(self.profile, 'scan_subdomain_takeover', False),
        ])
    
    async def scan_target(self, target: str) -> ScanResult:
        """
        Perform comprehensive scan of a single target.
        
        Args:
            target: URL to scan
            
        Returns:
            ScanResult with all findings
        """
        result = ScanResult(
            target=target,
            start_time=datetime.now(),
        )
        
        # Validate and normalize URL
        normalized = self._normalize_url(target)
        if normalized is None:
            result.error = "Invalid URL format"
            result.end_time = datetime.now()
            return result
        
        scan_target: str = normalized
        
        # Create shared session with optimized settings for Windows compatibility
        connector = aiohttp.TCPConnector(
            ssl=False,  # Allow invalid certs for scanning
            limit=50,
            limit_per_host=10,
            enable_cleanup_closed=True,
            force_close=True,  # Helps with Windows semaphore issues
            ttl_dns_cache=300,  # Cache DNS for 5 minutes
        )
        
        # Explicit timeout settings to avoid Windows semaphore issues
        timeout = aiohttp.ClientTimeout(
            total=self.profile.timeout,
            connect=min(10, self.profile.timeout),  # Connection timeout
            sock_connect=min(10, self.profile.timeout),  # Socket connect timeout
            sock_read=self.profile.timeout,  # Socket read timeout
        )
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Get initial response to verify target with retry
            headers = {"User-Agent": self.profile.user_agent}
            max_retries = 2
            last_error = None
            
            for attempt in range(max_retries + 1):
                try:
                    async with session.get(scan_target, headers=headers,
                                           allow_redirects=self.profile.follow_redirects) as response:
                        result.status_code = response.status
                        last_error = None
                        break
                        
                except asyncio.TimeoutError:
                    last_error = f"Connection timeout after {self.profile.timeout}s"
                    if attempt < max_retries:
                        await asyncio.sleep(1)  # Brief pause before retry
                        continue
                except aiohttp.ClientError as e:
                    error_msg = str(e)
                    # Check for Windows semaphore timeout (transient error)
                    if "semaphore" in error_msg.lower() and attempt < max_retries:
                        await asyncio.sleep(2)  # Longer pause for this error type
                        continue
                    last_error = f"Connection error: {error_msg}"
                except OSError as e:
                    # Handle OS-level socket errors
                    last_error = f"Network error: {str(e)}"
                    if attempt < max_retries:
                        await asyncio.sleep(1)
                        continue
            
            if last_error:
                result.error = last_error
                result.end_time = datetime.now()
                return result
            
            # Run standard scans based on profile
            tasks = []
            
            # HTTP Headers scan
            if self.profile.scan_headers:
                tasks.append(("headers", self._scan_headers(scan_target, session)))
            
            # SSL/TLS scan (only for HTTPS)
            if self.profile.scan_ssl and scan_target.lower().startswith("https"):
                tasks.append(("ssl", self._scan_ssl(scan_target)))
            
            # Vulnerability patterns scan
            if self.profile.scan_vulns:
                tasks.append(("vulns", self._scan_vulns(scan_target, session)))
            
            # Path enumeration scan
            if self.profile.scan_paths:
                tasks.append(("paths", self._scan_paths(scan_target, session)))
            
            # Deep scanning modules
            if self.deep_scanner:
                # CORS check
                if getattr(self.profile, 'scan_cors', False):
                    tasks.append(("cors", self.deep_scanner.check_cors(scan_target, session)))
                
                # WAF detection
                if getattr(self.profile, 'scan_waf', False):
                    tasks.append(("waf", self.deep_scanner.detect_waf(scan_target, session)))
                
                # JavaScript analysis
                if getattr(self.profile, 'scan_javascript', False):
                    tasks.append(("javascript", self.deep_scanner.analyze_javascript(scan_target, session)))
                
                # Host header injection
                if getattr(self.profile, 'scan_host_header', False):
                    tasks.append(("host_header", self.deep_scanner.test_host_header(scan_target, session)))
                
                # Request smuggling
                if getattr(self.profile, 'scan_request_smuggling', False):
                    tasks.append(("request_smuggling", self.deep_scanner.test_request_smuggling(scan_target, session)))
                
                # API endpoints discovery
                if getattr(self.profile, 'scan_api_endpoints', False):
                    tasks.append(("api_endpoints", self.deep_scanner.discover_api_endpoints(scan_target, session)))
                
                # Parameter discovery
                if getattr(self.profile, 'scan_parameters', False):
                    tasks.append(("parameters", self.deep_scanner.discover_parameters(scan_target, session)))
            
            # Run all scans concurrently
            if tasks:
                task_names = [t[0] for t in tasks]
                task_coros = [t[1] for t in tasks]
                scan_results = await asyncio.gather(*task_coros, return_exceptions=True)
                
                for i, scan_result in enumerate(scan_results):
                    task_name = task_names[i]
                    
                    if isinstance(scan_result, Exception):
                        continue
                    
                    if task_name == "vulns":
                        # Vuln scanner returns (vulns, techs)
                        if isinstance(scan_result, tuple):
                            vulns, techs = scan_result
                            result.vulnerabilities.extend(vulns)
                            result.technologies.extend(techs)
                    elif task_name == "waf":
                        # WAF detection returns (name, confidence)
                        if isinstance(scan_result, tuple):
                            waf_name, confidence = scan_result
                            if waf_name:
                                result.vulnerabilities.append(Vulnerability(
                                    title=f"WAF/CDN Detected: {waf_name}",
                                    severity=Severity.INFO,
                                    cvss_score=0.0,
                                    description=f"A Web Application Firewall or CDN was detected: {waf_name} (confidence: {confidence:.0%})",
                                    remediation="N/A - This is informational.",
                                    evidence=f"WAF: {waf_name}\nConfidence: {confidence:.0%}",
                                    category="Information",
                                ))
                    elif task_name == "api_endpoints":
                        # API endpoints returns list of paths
                        if isinstance(scan_result, list) and scan_result:
                            result.vulnerabilities.append(Vulnerability(
                                title=f"API Endpoints Discovered ({len(scan_result)} found)",
                                severity=Severity.INFO,
                                cvss_score=0.0,
                                description=f"Discovered {len(scan_result)} API endpoints.",
                                remediation="Ensure all API endpoints have proper authentication and authorization.",
                                evidence=f"Endpoints: {', '.join(scan_result[:10])}",
                                category="Information",
                            ))
                    elif task_name == "parameters":
                        # Parameters returns list of param names
                        if isinstance(scan_result, list) and scan_result:
                            result.vulnerabilities.append(Vulnerability(
                                title=f"Hidden Parameters Discovered ({len(scan_result)} found)",
                                severity=Severity.INFO,
                                cvss_score=0.0,
                                description=f"Discovered {len(scan_result)} potentially active parameters.",
                                remediation="Test discovered parameters for injection vulnerabilities.",
                                evidence=f"Parameters: {', '.join(scan_result[:10])}",
                                category="Information",
                            ))
                    elif isinstance(scan_result, list):
                        result.vulnerabilities.extend(scan_result)
            
            # CMS detection and scanning
            if self.deep_scanner and getattr(self.profile, 'scan_cms', False):
                cms = await self.deep_scanner.detect_cms(scan_target, session)
                if cms:
                    result.technologies.append(TechnologyFingerprint(
                        name=cms,
                        category="CMS",
                        confidence=0.8,
                    ))
                    cms_vulns = await self.deep_scanner.scan_cms_vulns(scan_target, cms, session)
                    result.vulnerabilities.extend(cms_vulns)
            
            # Subdomain enumeration and takeover check
            if self.deep_scanner and getattr(self.profile, 'scan_subdomains', False):
                parsed = urlparse(scan_target)
                domain = parsed.netloc.split(':')[0]
                if domain.startswith('www.'):
                    domain = domain[4:]
                
                subdomains = await self.deep_scanner.enumerate_subdomains(domain, session)
                if subdomains:
                    result.vulnerabilities.append(Vulnerability(
                        title=f"Subdomains Discovered ({len(subdomains)} found)",
                        severity=Severity.INFO,
                        cvss_score=0.0,
                        description=f"Discovered {len(subdomains)} subdomains.",
                        remediation="Review all subdomains for proper security configuration.",
                        evidence=f"Subdomains: {', '.join(sorted(subdomains)[:20])}",
                        category="Information",
                    ))
                    
                    # Check for subdomain takeover
                    if getattr(self.profile, 'scan_subdomain_takeover', False):
                        takeover_vulns = await self.deep_scanner.check_subdomain_takeover(
                            subdomains[:30], session
                        )
                        result.vulnerabilities.extend(takeover_vulns)
        
        # Sort vulnerabilities by severity
        result.vulnerabilities = sorted(
            result.vulnerabilities,
            key=lambda v: Severity(v.severity).weight if isinstance(v.severity, str) else v.severity.weight,
            reverse=True
        )
        
        # Deduplicate vulnerabilities
        result.vulnerabilities = self._deduplicate_vulns(result.vulnerabilities)
        
        result.end_time = datetime.now()
        return result
    
    async def scan_targets(self, targets: List[str], max_concurrent: int = 10) -> List[ScanResult]:
        """
        Scan multiple targets concurrently.
        
        Args:
            targets: List of URLs to scan
            max_concurrent: Maximum concurrent scans
            
        Returns:
            List of ScanResults
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(target: str) -> ScanResult:
            async with semaphore:
                return await self.scan_target(target)
        
        tasks = [scan_with_semaphore(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error results
        processed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append(ScanResult(
                    target=targets[i],
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    error=str(result),
                ))
            else:
                processed.append(result)
        
        return processed
    
    async def deep_scan_target(self, target: str) -> ScanResult:
        """
        Perform a comprehensive deep scan using all available modules.
        
        Args:
            target: URL to scan
            
        Returns:
            ScanResult with all findings
        """
        # Create a deep scan profile
        deep_profile = ScanProfile.get_profile("deep")
        
        # Store original profile and use deep profile
        original_profile = self.profile
        self.profile = deep_profile
        self._init_deep_scanner()
        
        try:
            result = await self.scan_target(target)
            
            # Run additional deep scanning modules
            if self.deep_scanner:
                connector = aiohttp.TCPConnector(
                    ssl=False,
                    limit=50,
                    limit_per_host=10,
                    enable_cleanup_closed=True,
                    force_close=True,
                    ttl_dns_cache=300,
                )
                timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_connect=10, sock_read=30)
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    # Additional tests
                    additional_vulns = []
                    
                    # Open redirect test
                    open_redirect_vulns = await self.deep_scanner.test_open_redirect(target, session)
                    additional_vulns.extend(open_redirect_vulns)
                    
                    # CRLF injection test
                    crlf_vulns = await self.deep_scanner.test_crlf_injection(target, session)
                    additional_vulns.extend(crlf_vulns)
                    
                    # GraphQL security check
                    graphql_vulns = await self.deep_scanner.check_graphql_security(target, session)
                    additional_vulns.extend(graphql_vulns)
                    
                    # Backup files check
                    backup_vulns = await self.deep_scanner.check_backup_files(target, session)
                    additional_vulns.extend(backup_vulns)
                    
                    # VCS exposure check
                    vcs_vulns = await self.deep_scanner.check_vcs_exposure(target, session)
                    additional_vulns.extend(vcs_vulns)
                    
                    result.vulnerabilities.extend(additional_vulns)
            
            # Resort and deduplicate
            result.vulnerabilities = sorted(
                result.vulnerabilities,
                key=lambda v: Severity(v.severity).weight if isinstance(v.severity, str) else v.severity.weight,
                reverse=True
            )
            result.vulnerabilities = self._deduplicate_vulns(result.vulnerabilities)
            
            return result
            
        finally:
            # Restore original profile
            self.profile = original_profile
            self._init_deep_scanner()
    
    async def _scan_headers(self, target: str, session: aiohttp.ClientSession) -> List[Vulnerability]:
        """Run HTTP headers scan"""
        return await self.header_scanner.scan(target, session)
    
    async def _scan_ssl(self, target: str) -> List[Vulnerability]:
        """Run SSL/TLS scan"""
        return await self.ssl_scanner.scan(target)
    
    async def _scan_vulns(self, target: str, session: aiohttp.ClientSession) -> tuple:
        """Run vulnerability patterns scan"""
        return await self.vuln_scanner.scan(target, session)
    
    async def _scan_paths(self, target: str, session: aiohttp.ClientSession) -> List[Vulnerability]:
        """Run path enumeration scan"""
        return await self.path_scanner.scan(
            target, session, max_paths=self.profile.max_paths
        )
    
    def _normalize_url(self, url: str) -> Optional[str]:
        """Normalize and validate URL"""
        url = url.strip()
        
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return None
            
            # Reconstruct clean URL
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        except Exception:
            return None
    
    def _deduplicate_vulns(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique = []
        
        for vuln in vulns:
            key = (vuln.title, vuln.category)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique


class ScanManager:
    """High-level scan manager for CLI and batch operations"""
    
    def __init__(self):
        self.results: List[ScanResult] = []
    
    def load_targets_from_file(self, filepath: str) -> List[str]:
        """Load target URLs from a file"""
        targets = []
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except Exception as e:
            raise ValueError(f"Error loading targets file: {e}")
        return targets
    
    async def run_scan(self, targets: List[str], profile_name: str = "standard",
                       max_concurrent: int = 10, signatures_path: Optional[str] = None,
                       wordlist_path: Optional[str] = None) -> List[ScanResult]:
        """
        Run scan on targets.
        
        Args:
            targets: List of URLs or path to targets file
            profile_name: Scan profile name
            max_concurrent: Max concurrent scans
            signatures_path: Path to custom signatures
            wordlist_path: Path to custom wordlist
            
        Returns:
            List of ScanResults
        """
        # Handle file input
        if len(targets) == 1 and Path(targets[0]).exists():
            targets = self.load_targets_from_file(targets[0])
        
        if not targets:
            raise ValueError("No targets specified")
        
        # Get profile
        profile = ScanProfile.get_profile(profile_name)
        
        # Create scanner
        scanner = WebVulnScanner(
            profile=profile,
            signatures_path=Path(signatures_path) if signatures_path else None,
            wordlist_path=Path(wordlist_path) if wordlist_path else None,
        )
        
        # Run scans
        self.results = await scanner.scan_targets(targets, max_concurrent)
        
        return self.results
    
    async def run_deep_scan(self, targets: List[str], max_concurrent: int = 5,
                            signatures_path: Optional[str] = None,
                            wordlist_path: Optional[str] = None) -> List[ScanResult]:
        """
        Run deep scan on targets.
        
        Args:
            targets: List of URLs
            max_concurrent: Max concurrent scans (lower for deep scan)
            signatures_path: Path to custom signatures
            wordlist_path: Path to custom wordlist
            
        Returns:
            List of ScanResults
        """
        # Handle file input
        if len(targets) == 1 and Path(targets[0]).exists():
            targets = self.load_targets_from_file(targets[0])
        
        if not targets:
            raise ValueError("No targets specified")
        
        # Get deep profile
        profile = ScanProfile.get_profile("deep")
        
        # Create scanner
        scanner = WebVulnScanner(
            profile=profile,
            signatures_path=Path(signatures_path) if signatures_path else None,
            wordlist_path=Path(wordlist_path) if wordlist_path else None,
        )
        
        # Run deep scans with lower concurrency
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def deep_scan_with_semaphore(target: str) -> ScanResult:
            async with semaphore:
                return await scanner.deep_scan_target(target)
        
        tasks = [deep_scan_with_semaphore(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error results
        processed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append(ScanResult(
                    target=targets[i],
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    error=str(result),
                ))
            else:
                processed.append(result)
        
        self.results = processed
        return self.results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary statistics"""
        total_vulns = 0
        by_severity = {s.value: 0 for s in Severity}
        by_category = {}
        technologies = []
        
        for result in self.results:
            for vuln in result.vulnerabilities:
                total_vulns += 1
                sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
                by_severity[sev] = by_severity.get(sev, 0) + 1
                by_category[vuln.category] = by_category.get(vuln.category, 0) + 1
            
            technologies.extend(result.technologies)
        
        return {
            "targets_scanned": len(self.results),
            "total_vulnerabilities": total_vulns,
            "by_severity": by_severity,
            "by_category": by_category,
            "technologies_detected": len(set(t.name for t in technologies)),
            "failed_scans": len([r for r in self.results if r.error]),
        }
