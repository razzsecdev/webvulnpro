"""
Core data models for WebVulnPro vulnerability scanner.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import json


class Severity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    @property
    def color(self) -> str:
        """Return rich color for severity"""
        colors = {
            "CRITICAL": "red",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "green"
        }
        return colors.get(self.value, "white")
    
    @property
    def weight(self) -> int:
        """Return weight for sorting (higher is more severe)"""
        weights = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1
        }
        return weights.get(self.value, 0)


class TechnologyCategory(str, Enum):
    """Technology categories like Wappalyzer"""
    CMS = "CMS"
    ECOMMERCE = "E-commerce"
    FRAMEWORK = "Framework"
    JAVASCRIPT_FRAMEWORK = "JavaScript Framework"
    JAVASCRIPT_LIBRARY = "JavaScript Library"
    PROGRAMMING_LANGUAGE = "Programming Language"
    WEB_SERVER = "Web Server"
    OPERATING_SYSTEM = "Operating System"
    DATABASE = "Database"
    CACHE = "Cache"
    CDN = "CDN"
    WAF = "WAF"
    SECURITY = "Security"
    HOSTING = "Hosting"
    PAAS = "PaaS"
    ANALYTICS = "Analytics"
    MARKETING = "Marketing"
    TAG_MANAGER = "Tag Manager"
    ADVERTISING = "Advertising"
    FONT = "Font"
    WIDGET = "Widget"
    PAYMENT = "Payment"
    SEO = "SEO"
    EDITOR = "Editor"
    BUILD_TOOL = "Build Tool"
    UI_FRAMEWORK = "UI Framework"
    STATIC_SITE_GEN = "Static Site Generator"
    DOCUMENTATION = "Documentation"
    VIDEO = "Video"
    COMMENT = "Comment"
    LIVE_CHAT = "Live Chat"
    CRM = "CRM"
    MESSAGE_QUEUE = "Message Queue"
    SEARCH = "Search"
    MISCELLANEOUS = "Miscellaneous"
    UNKNOWN = "Unknown"
    
    @property
    def icon(self) -> str:
        """Return emoji icon for category"""
        icons = {
            "CMS": "📝",
            "E-commerce": "🛒",
            "Framework": "🏗️",
            "JavaScript Framework": "⚛️",
            "JavaScript Library": "📚",
            "Programming Language": "💻",
            "Web Server": "🖥️",
            "Operating System": "🖥️",
            "Database": "🗄️",
            "Cache": "⚡",
            "CDN": "🌐",
            "WAF": "🛡️",
            "Security": "🔒",
            "Hosting": "☁️",
            "PaaS": "☁️",
            "Analytics": "📊",
            "Marketing": "📣",
            "Tag Manager": "🏷️",
            "Advertising": "📢",
            "Font": "🔤",
            "Widget": "🧩",
            "Payment": "💳",
            "SEO": "🔍",
            "Editor": "✏️",
            "Build Tool": "🔧",
            "UI Framework": "🎨",
            "Static Site Generator": "📄",
            "Documentation": "📖",
            "Video": "🎬",
            "Comment": "💬",
            "Live Chat": "💬",
            "CRM": "👥",
            "Message Queue": "📨",
            "Search": "🔍",
            "Miscellaneous": "📦",
            "Unknown": "❓",
        }
        return icons.get(self.value, "📦")
    
    @property
    def color(self) -> str:
        """Return color for category"""
        colors = {
            "CMS": "#4CAF50",
            "E-commerce": "#FF9800",
            "Framework": "#2196F3",
            "JavaScript Framework": "#61DAFB",
            "JavaScript Library": "#F7DF1E",
            "Programming Language": "#9C27B0",
            "Web Server": "#607D8B",
            "Operating System": "#795548",
            "Database": "#FF5722",
            "Cache": "#00BCD4",
            "CDN": "#03A9F4",
            "WAF": "#F44336",
            "Security": "#E91E63",
            "Hosting": "#3F51B5",
            "PaaS": "#673AB7",
            "Analytics": "#4CAF50",
            "Marketing": "#FF5722",
            "Tag Manager": "#9E9E9E",
            "Advertising": "#FFC107",
            "Font": "#9E9E9E",
            "Widget": "#00BCD4",
            "Payment": "#4CAF50",
            "SEO": "#8BC34A",
            "Editor": "#FF9800",
            "Build Tool": "#607D8B",
            "UI Framework": "#E91E63",
            "Static Site Generator": "#795548",
            "Documentation": "#9E9E9E",
            "Video": "#F44336",
            "Comment": "#2196F3",
            "Live Chat": "#4CAF50",
            "CRM": "#3F51B5",
            "Message Queue": "#FF5722",
            "Search": "#673AB7",
            "Miscellaneous": "#9E9E9E",
            "Unknown": "#9E9E9E",
        }
        return colors.get(self.value, "#9E9E9E")


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    title: str
    severity: Severity
    cvss_score: float
    description: str
    remediation: str
    evidence: str
    category: str = "General"
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    request: Optional[str] = None
    response: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "title": self.title,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "references": self.references,
            "request": self.request,
            "response": self.response,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Vulnerability":
        """Create from dictionary"""
        severity = data.get("severity", "INFO")
        if isinstance(severity, str):
            severity = Severity(severity)
        return cls(
            title=data["title"],
            severity=severity,
            cvss_score=data.get("cvss_score", 0.0),
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            evidence=data.get("evidence", ""),
            category=data.get("category", "General"),
            cwe_id=data.get("cwe_id"),
            cve_id=data.get("cve_id"),
            references=data.get("references", []),
            request=data.get("request"),
            response=data.get("response"),
        )


@dataclass
class TechnologyFingerprint:
    """Represents detected technology with Wappalyzer-like categorization"""
    name: str
    version: Optional[str] = None
    category: str = "Unknown"
    confidence: float = 0.0
    evidence: str = ""
    website: Optional[str] = None
    cpe: Optional[str] = None  # Common Platform Enumeration
    icon: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "website": self.website,
            "cpe": self.cpe,
        }
    
    @property
    def display_name(self) -> str:
        """Return name with version if available"""
        if self.version:
            return f"{self.name} {self.version}"
        return self.name
    
    @property
    def category_enum(self) -> TechnologyCategory:
        """Return category as enum"""
        try:
            return TechnologyCategory(self.category)
        except ValueError:
            return TechnologyCategory.UNKNOWN


@dataclass
class ScanResult:
    """Complete scan result for a target"""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    technologies: List[TechnologyFingerprint] = field(default_factory=list)
    status_code: Optional[int] = None
    error: Optional[str] = None
    
    @property
    def duration(self) -> float:
        """Scan duration in seconds"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def risk_score(self) -> int:
        """Calculate overall risk score (0-100)"""
        if not self.vulnerabilities:
            return 0
        
        score = 0
        for vuln in self.vulnerabilities:
            if vuln.severity == Severity.CRITICAL:
                score += 25
            elif vuln.severity == Severity.HIGH:
                score += 15
            elif vuln.severity == Severity.MEDIUM:
                score += 8
            elif vuln.severity == Severity.LOW:
                score += 3
            elif vuln.severity == Severity.INFO:
                score += 1
        
        return min(100, score)
    
    def count_by_severity(self) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {s.value: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration,
            "risk_score": self.risk_score,
            "vulnerability_counts": self.count_by_severity(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "technologies": [t.to_dict() for t in self.technologies],
            "status_code": self.status_code,
            "error": self.error,
        }


@dataclass
class ScanProfile:
    """Scan configuration profile"""
    name: str
    description: str
    scan_headers: bool = True
    scan_ssl: bool = True
    scan_paths: bool = True
    scan_vulns: bool = True
    scan_tech: bool = True
    max_paths: int = 500
    timeout: int = 30
    user_agent: str = "WebVulnPro/1.0 (Security Scanner)"
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = False  # Allow scanning sites with bad certs
    
    # Deep scanning options
    scan_subdomains: bool = False
    scan_javascript: bool = False
    scan_cors: bool = False
    scan_cms: bool = False
    scan_waf: bool = False
    scan_api_endpoints: bool = False
    scan_parameters: bool = False
    scan_host_header: bool = False
    scan_request_smuggling: bool = False
    scan_subdomain_takeover: bool = False
    
    # Advanced options
    aggressive_mode: bool = False  # More invasive tests
    crawl_depth: int = 2  # How deep to crawl for JS files
    max_subdomains: int = 100
    param_discovery_limit: int = 100
    concurrent_deep_scans: int = 20
    
    @classmethod
    def get_profile(cls, name: str) -> "ScanProfile":
        """Get predefined scan profile"""
        profiles = {
            "quick": cls(
                name="quick",
                description="Fast scan with essential checks only",
                scan_paths=False,
                scan_vulns=False,
                max_paths=50,
                timeout=10,
            ),
            "standard": cls(
                name="standard",
                description="Balanced scan for most use cases",
                max_paths=200,
                timeout=20,
            ),
            "comprehensive": cls(
                name="comprehensive",
                description="Thorough scan with all checks enabled",
                max_paths=500,
                timeout=30,
                scan_cors=True,
                scan_waf=True,
                scan_javascript=True,
            ),
            "deep": cls(
                name="deep",
                description="Deep scan with advanced vulnerability detection",
                max_paths=1000,
                timeout=45,
                scan_subdomains=True,
                scan_javascript=True,
                scan_cors=True,
                scan_cms=True,
                scan_waf=True,
                scan_api_endpoints=True,
                scan_parameters=True,
                scan_host_header=True,
                scan_request_smuggling=True,
                scan_subdomain_takeover=True,
                aggressive_mode=True,
                crawl_depth=3,
            ),
            "passive": cls(
                name="passive",
                description="Non-intrusive passive analysis only",
                scan_paths=False,
                scan_vulns=False,
                timeout=15,
            ),
            "stealth": cls(
                name="stealth",
                description="Low-profile scan to avoid detection",
                scan_paths=False,
                scan_vulns=True,
                scan_headers=True,
                scan_ssl=True,
                timeout=60,
                max_paths=50,
            ),
            "api": cls(
                name="api",
                description="API-focused vulnerability scanning",
                scan_paths=True,
                scan_vulns=True,
                scan_api_endpoints=True,
                scan_cors=True,
                scan_parameters=True,
                max_paths=300,
                timeout=30,
            ),
            "cms": cls(
                name="cms",
                description="CMS-focused vulnerability scanning",
                scan_paths=True,
                scan_vulns=True,
                scan_cms=True,
                scan_waf=True,
                max_paths=500,
                timeout=30,
            ),
        }
        return profiles.get(name, profiles["standard"])
