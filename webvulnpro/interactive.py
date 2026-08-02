"""
WebVulnPro Interactive Menu - Rich-based TUI for vulnerability scanning
Advanced edition with deep scanning capabilities
"""

import asyncio
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.live import Live
from rich.layout import Layout
from rich import box
from rich.text import Text
from rich.align import Align
from rich.tree import Tree
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.columns import Columns

from .core.models import ScanProfile, ScanResult, Severity
from .core.scanner import WebVulnScanner, ScanManager
from .core.reporter import ReportGenerator

console = Console()

# Package paths
PACKAGE_DIR = Path(__file__).parent
REPORTS_DIR = PACKAGE_DIR / "Reports"
DEFAULT_WORDLIST = PACKAGE_DIR / "wordlists" / "paths.txt"
DEFAULT_SIGNATURES = PACKAGE_DIR / "signatures" / "vuln_signatures.json"

# ASCII Art Banner
BANNER_ASCII = """
[bold blue]╔═══════════════════════════════════════════════════════════════════════╗[/bold blue]
[bold blue]║[/bold blue]  [bold cyan]╦ ╦┌─┐┌┐ ╦  ╦┬ ┬┬  ┌┐┌╔═╗┬─┐┌─┐[/bold cyan]  [bold white]Enterprise Vulnerability Scanner[/bold white]  [bold blue]║[/bold blue]
[bold blue]║[/bold blue]  [bold cyan]║║║├┤ ├┴┐╚╗╔╝│ ││  │││╠═╝├┬┘│ │[/bold cyan]  [dim]v2.0.0 - Advanced Edition[/dim]        [bold blue]║[/bold blue]
[bold blue]║[/bold blue]  [bold cyan]╚╩╝└─┘└─┘ ╚╝ └─┘┴─┘┘└┘╩  ┴└─└─┘[/bold cyan]  [dim]Deep Scanning Enabled[/dim]           [bold blue]║[/bold blue]
[bold blue]╚═══════════════════════════════════════════════════════════════════════╝[/bold blue]
"""


def _clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def _print_banner():
    """Print the WebVulnPro banner"""
    console.print(BANNER_ASCII)


def _print_main_menu():
    """Print the main interactive menu"""
    menu = Table(box=box.DOUBLE_EDGE, show_header=False, expand=True, border_style="cyan")
    menu.add_column("Option", style="bold cyan", width=5, justify="center")
    menu.add_column("Name", style="bold white", width=30)
    menu.add_column("Description", style="dim")
    
    # Scan types
    menu.add_row("[bold yellow]SCAN PROFILES[/bold yellow]", "", "")
    menu.add_row("1", "Quick Scan", "Fast essential checks (headers + SSL)")
    menu.add_row("2", "Standard Scan", "Balanced scanning with path enumeration")
    menu.add_row("3", "Deep Scan", "Comprehensive + all advanced modules")
    menu.add_row("4", "Custom Scan", "Select specific modules to run")
    menu.add_row("5", "Stealth Scan", "Low-profile passive analysis")
    
    menu.add_row("", "", "")
    menu.add_row("[bold yellow]SPECIALIZED SCANS[/bold yellow]", "", "")
    menu.add_row("6", "API Security Scan", "REST/GraphQL endpoint testing")
    menu.add_row("7", "CMS Security Scan", "WordPress/Drupal/Joomla checks")
    menu.add_row("8", "Subdomain Discovery", "Enumerate and test subdomains")
    
    menu.add_row("", "", "")
    menu.add_row("[bold yellow]INDIVIDUAL MODULES[/bold yellow]", "", "")
    menu.add_row("10", "HTTP Headers Analysis", "Security headers deep analysis")
    menu.add_row("11", "SSL/TLS Audit", "Certificate and protocol checks")
    menu.add_row("12", "Path Enumeration", "Discover hidden paths and files")
    menu.add_row("13", "JavaScript Analysis", "Extract secrets and endpoints from JS")
    menu.add_row("14", "CORS Testing", "Cross-origin misconfiguration testing")
    menu.add_row("15", "Technology Detection", "Identify technologies in use")
    
    menu.add_row("", "", "")
    menu.add_row("[bold yellow]ADVANCED TESTS[/bold yellow]", "", "")
    menu.add_row("20", "Open Redirect Test", "Test for open redirect vulnerabilities")
    menu.add_row("21", "Host Header Injection", "Test host header vulnerabilities")
    menu.add_row("22", "CRLF Injection Test", "HTTP response splitting testing")
    menu.add_row("23", "Backup File Discovery", "Find exposed backup files")
    menu.add_row("24", "Git/VCS Exposure", "Check for exposed repositories")
    menu.add_row("25", "WAF Detection", "Identify web application firewalls")
    
    menu.add_row("", "", "")
    menu.add_row("[bold yellow]UTILITIES[/bold yellow]", "", "")
    menu.add_row("30", "View Previous Reports", "Browse saved scan reports")
    menu.add_row("31", "Scan Profiles Info", "View available scan profiles")
    menu.add_row("32", "Export Configuration", "Export current settings")
    
    menu.add_row("", "", "")
    menu.add_row("0", "Exit", "Exit WebVulnPro")
    
    panel = Panel(
        menu,
        title="[bold white]WebVulnPro Interactive Scanner[/bold white]",
        subtitle="[dim]Enter option number to continue[/dim]",
        border_style="blue",
    )
    console.print(panel)


def _print_submenu_header(title: str):
    """Print a submenu header"""
    console.print()
    console.print(Panel(f"[bold cyan]{title}[/bold cyan]", border_style="cyan"))
    console.print()


def _validate_url(url: str) -> Tuple[bool, str]:
    """Validate and normalize URL"""
    url = url.strip()
    
    if not url:
        return False, "URL cannot be empty"
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, "Invalid URL format"
        return True, f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    except Exception:
        return False, "Invalid URL format"


def _validate_domain(domain: str) -> Tuple[bool, str]:
    """Validate domain for subdomain enumeration"""
    domain = domain.strip().lower()
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc
    
    # Remove www. prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Basic domain validation
    if not domain or '/' in domain:
        return False, "Invalid domain format"
    
    if '.' not in domain:
        return False, "Domain must include TLD (e.g., example.com)"
    
    return True, domain


def _get_target_input(prompt_text: str = "Target URL", allow_multiple: bool = False) -> Optional[List[str]]:
    """Get target URL(s) from user with validation"""
    console.print()
    
    if allow_multiple:
        console.print("[dim]Enter target URLs (one per line, empty line to finish):[/dim]")
        targets = []
        while True:
            url = Prompt.ask(f"  [cyan]{len(targets) + 1}[/cyan]", default="")
            if not url:
                if targets:
                    break
                console.print("[yellow]Please enter at least one target[/yellow]")
                continue
            
            valid, result = _validate_url(url)
            if valid:
                targets.append(result)
                console.print(f"    [green]Added:[/green] {result}")
            else:
                console.print(f"    [red]{result}[/red]")
        return targets
    else:
        while True:
            url = Prompt.ask(f"[cyan]{prompt_text}[/cyan]")
            valid, result = _validate_url(url)
            if valid:
                return [result]
            console.print(f"[red]{result}[/red]")


def _get_domain_input() -> Optional[str]:
    """Get domain for subdomain enumeration"""
    console.print()
    while True:
        domain = Prompt.ask("[cyan]Target Domain[/cyan] (e.g., example.com)")
        valid, result = _validate_domain(domain)
        if valid:
            return result
        console.print(f"[red]{result}[/red]")


def _select_report_format() -> str:
    """Let user select report format"""
    console.print()
    console.print("[bold]Select Report Format:[/bold]")
    console.print("  [cyan]1[/cyan] - JSON (machine-readable)")
    console.print("  [cyan]2[/cyan] - HTML (web dashboard)")
    console.print("  [cyan]3[/cyan] - PDF (enterprise report)")
    console.print("  [cyan]4[/cyan] - All formats")
    
    choice = IntPrompt.ask("[cyan]Format[/cyan]", default=1, choices=["1", "2", "3", "4"])
    
    formats = {1: "json", 2: "html", 3: "pdf", 4: "all"}
    return formats.get(choice, "json")


def _select_custom_modules() -> dict:
    """Let user select which modules to run"""
    console.print()
    console.print("[bold]Select Modules to Enable:[/bold]")
    console.print("[dim]Press Enter for default selection[/dim]\n")
    
    modules = {
        # Standard modules
        "scan_headers": ("HTTP Security Headers", True),
        "scan_ssl": ("SSL/TLS Configuration", True),
        "scan_paths": ("Path Enumeration", True),
        "scan_vulns": ("Vulnerability Patterns", True),
        # Deep scanning modules
        "scan_subdomains": ("Subdomain Enumeration", False),
        "scan_javascript": ("JavaScript Analysis", False),
        "scan_cors": ("CORS Misconfiguration", True),
        "scan_cms": ("CMS Vulnerabilities", False),
        "scan_waf": ("WAF Detection", False),
        "scan_api_endpoints": ("API Endpoint Discovery", False),
        "scan_parameters": ("Parameter Discovery", False),
        "scan_host_header": ("Host Header Injection", False),
        "scan_request_smuggling": ("HTTP Request Smuggling", False),
        "scan_subdomain_takeover": ("Subdomain Takeover", False),
    }
    
    selected = {}
    for key, (name, default) in modules.items():
        enabled = Confirm.ask(f"  [cyan]{name}[/cyan]", default=default)
        selected[key] = enabled
    
    return selected


def _select_scan_intensity() -> str:
    """Let user select scan intensity"""
    console.print()
    console.print("[bold]Select Scan Intensity:[/bold]")
    console.print("  [cyan]1[/cyan] - Light (minimal footprint)")
    console.print("  [cyan]2[/cyan] - Normal (balanced)")
    console.print("  [cyan]3[/cyan] - Aggressive (comprehensive)")
    
    choice = IntPrompt.ask("[cyan]Intensity[/cyan]", default=2, choices=["1", "2", "3"])
    
    intensities = {1: "light", 2: "normal", 3: "aggressive"}
    return intensities.get(choice, "normal")


def _create_report_path(target: str, fmt: str) -> Path:
    """Create report path in organized structure"""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Extract domain for folder name
    try:
        parsed = urlparse(target)
        folder_name = parsed.hostname or "unknown"
        folder_name = folder_name.replace(":", "_").replace("/", "_")
    except Exception:
        folder_name = "unknown"
    
    target_folder = REPORTS_DIR / folder_name
    target_folder.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return target_folder / f"report_{timestamp}.{fmt}"


async def _run_scan(targets: List[str], profile: ScanProfile, 
                    report_format: str = "json") -> List[ScanResult]:
    """Execute scan with progress display"""
    
    scanner = WebVulnScanner(
        profile=profile,
        signatures_path=DEFAULT_SIGNATURES if DEFAULT_SIGNATURES.exists() else None,
        wordlist_path=DEFAULT_WORDLIST if DEFAULT_WORDLIST.exists() else None,
    )
    
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(targets))
        
        for target in targets:
            progress.update(task, description=f"[cyan]Scanning {target}...")
            result = await scanner.scan_target(target)
            results.append(result)
            progress.advance(task)
    
    return results


async def _run_deep_scan(targets: List[str], report_format: str = "json") -> List[ScanResult]:
    """Execute deep scan with detailed progress display"""
    
    manager = ScanManager()
    
    console.print()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        expand=True,
    ) as progress:
        overall = progress.add_task("[bold cyan]Deep Scan Progress", total=len(targets))
        current = progress.add_task("[dim]Initializing...", total=100, visible=True)
        
        for target in targets:
            progress.update(current, description=f"[cyan]Deep scanning {target}...", completed=0)
            
            # Simulate progress for different phases
            phases = [
                ("Reconnaissance...", 10),
                ("Headers & SSL analysis...", 20),
                ("Path enumeration...", 35),
                ("Vulnerability patterns...", 50),
                ("JavaScript analysis...", 60),
                ("CORS & header injection...", 70),
                ("API discovery...", 80),
                ("CMS & subdomain checks...", 90),
                ("Finalizing...", 100),
            ]
            
            # Run actual scan
            results = await manager.run_deep_scan([target], max_concurrent=1)
            
            progress.update(current, completed=100)
            progress.advance(overall)
    
    return manager.results


def _print_scan_results(results: List[ScanResult]):
    """Display scan results summary with enhanced formatting"""
    console.print()
    console.print(Panel("[bold]SCAN COMPLETE[/bold]", border_style="green"))
    
    total_vulns = 0
    by_severity = {}
    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "green",
    }
    
    for result in results:
        console.print()
        console.print(f"[bold]Target:[/bold] {result.target}")
        console.print(f"[dim]Duration: {result.duration:.2f}s | Status: {result.status_code or 'N/A'} | Risk Score: {result.risk_score}/100[/dim]")
        
        if result.error:
            console.print(f"[red]Error: {result.error}[/red]")
            continue
        
        for vuln in result.vulnerabilities:
            total_vulns += 1
            sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
            by_severity[sev] = by_severity.get(sev, 0) + 1
    
    # Summary table
    if total_vulns > 0:
        console.print()
        
        # Create summary cards
        summary_cards = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = by_severity.get(sev, 0)
            if count > 0:
                color = severity_colors.get(sev, "white")
                summary_cards.append(Panel(
                    f"[bold {color}]{count}[/bold {color}]",
                    title=f"[{color}]{sev}[/{color}]",
                    border_style=color,
                    width=12,
                ))
        
        if summary_cards:
            console.print(Columns(summary_cards, equal=True, expand=False))
        
        console.print(f"\n[bold]Total Findings:[/bold] {total_vulns}")
        
        # Top findings table
        console.print("\n[bold]Top Findings:[/bold]")
        
        table = Table(box=box.ROUNDED, show_header=True)
        table.add_column("Severity", width=10)
        table.add_column("Finding", width=50)
        table.add_column("Category", width=20)
        
        all_vulns = []
        for result in results:
            for vuln in result.vulnerabilities:
                all_vulns.append(vuln)
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_vulns.sort(key=lambda v: severity_order.get(
            v.severity.value if isinstance(v.severity, Severity) else v.severity, 5
        ))
        
        for vuln in all_vulns[:15]:
            sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
            color = severity_colors.get(sev, "white")
            table.add_row(
                f"[{color}]{sev}[/{color}]",
                vuln.title[:48] + "..." if len(vuln.title) > 48 else vuln.title,
                vuln.category,
            )
        
        console.print(table)
    else:
        console.print("\n[green]No vulnerabilities found![/green]")
    
    # Technologies detected
    all_techs = []
    for result in results:
        all_techs.extend(result.technologies)
    
    if all_techs:
        console.print("\n[bold]Technologies Detected:[/bold]")
        tech_tree = Tree("[cyan]Technologies[/cyan]")
        
        by_category = {}
        for tech in all_techs:
            cat = tech.category or "Other"
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(tech)
        
        for cat, techs in by_category.items():
            cat_branch = tech_tree.add(f"[yellow]{cat}[/yellow]")
            for tech in techs[:5]:
                version = f" v{tech.version}" if tech.version else ""
                cat_branch.add(f"[green]{tech.name}{version}[/green]")
        
        console.print(tech_tree)


def _save_reports(results: List[ScanResult], targets: List[str], report_format: str):
    """Save scan reports in selected format(s)"""
    reporter = ReportGenerator()
    
    formats = ["json", "html", "pdf"] if report_format == "all" else [report_format]
    
    console.print()
    for fmt in formats:
        report_path = _create_report_path(targets[0], fmt)
        saved_path = reporter.save_report(results, str(report_path))
        console.print(f"[green]Report saved:[/green] {saved_path}")


def _view_previous_reports():
    """Browse and display previous scan reports"""
    _clear_screen()
    _print_banner()
    _print_submenu_header("Previous Scan Reports")
    
    if not REPORTS_DIR.exists():
        console.print("[yellow]No reports found. Run a scan first![/yellow]")
        Prompt.ask("\n[dim]Press Enter to continue[/dim]")
        return
    
    # List all target folders
    folders = [f for f in REPORTS_DIR.iterdir() if f.is_dir()]
    
    if not folders:
        console.print("[yellow]No reports found. Run a scan first![/yellow]")
        Prompt.ask("\n[dim]Press Enter to continue[/dim]")
        return
    
    table = Table(title="Available Reports", box=box.ROUNDED)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Target", style="bold")
    table.add_column("Reports", justify="right")
    table.add_column("Latest", style="dim")
    
    for i, folder in enumerate(folders, 1):
        reports = list(folder.glob("*.*"))
        latest = max(reports, key=lambda f: f.stat().st_mtime) if reports else None
        latest_time = datetime.fromtimestamp(latest.stat().st_mtime).strftime("%Y-%m-%d %H:%M") if latest else "N/A"
        
        table.add_row(str(i), folder.name, str(len(reports)), latest_time)
    
    console.print(table)
    console.print("\n[dim]Enter folder number to view reports, or 0 to go back[/dim]")
    
    choice = IntPrompt.ask("[cyan]Select[/cyan]", default=0)
    
    if choice == 0 or choice > len(folders):
        return
    
    # Show reports in selected folder
    folder = folders[choice - 1]
    reports = sorted(folder.glob("*.*"), key=lambda f: f.stat().st_mtime, reverse=True)
    
    console.print(f"\n[bold]Reports for {folder.name}:[/bold]\n")
    
    for i, report in enumerate(reports, 1):
        mtime = datetime.fromtimestamp(report.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        size = report.stat().st_size / 1024
        console.print(f"  [cyan]{i}[/cyan] - {report.name} ({size:.1f} KB) - {mtime}")
    
    Prompt.ask("\n[dim]Press Enter to continue[/dim]")


def _view_scan_profiles():
    """Display available scan profiles"""
    _clear_screen()
    _print_banner()
    _print_submenu_header("Available Scan Profiles")
    
    profiles = ["quick", "standard", "comprehensive", "deep", "passive", "stealth", "api", "cms"]
    
    for profile_name in profiles:
        profile = ScanProfile.get_profile(profile_name)
        
        # Create profile card
        features = []
        if profile.scan_headers:
            features.append("[green]+[/green] HTTP Headers")
        if profile.scan_ssl:
            features.append("[green]+[/green] SSL/TLS")
        if profile.scan_paths:
            features.append("[green]+[/green] Path Enumeration")
        if profile.scan_vulns:
            features.append("[green]+[/green] Vulnerability Patterns")
        if getattr(profile, 'scan_subdomains', False):
            features.append("[cyan]+[/cyan] Subdomain Enumeration")
        if getattr(profile, 'scan_javascript', False):
            features.append("[cyan]+[/cyan] JavaScript Analysis")
        if getattr(profile, 'scan_cors', False):
            features.append("[cyan]+[/cyan] CORS Testing")
        if getattr(profile, 'scan_cms', False):
            features.append("[cyan]+[/cyan] CMS Scanning")
        if getattr(profile, 'scan_waf', False):
            features.append("[cyan]+[/cyan] WAF Detection")
        if getattr(profile, 'scan_api_endpoints', False):
            features.append("[cyan]+[/cyan] API Discovery")
        
        features_text = " | ".join(features[:6])
        if len(features) > 6:
            features_text += f" + {len(features) - 6} more"
        
        console.print(Panel(
            f"[dim]{profile.description}[/dim]\n\n{features_text}\n\n[dim]Timeout: {profile.timeout}s | Max Paths: {profile.max_paths}[/dim]",
            title=f"[bold cyan]{profile_name.upper()}[/bold cyan]",
            border_style="blue",
        ))
        console.print()
    
    Prompt.ask("\n[dim]Press Enter to continue[/dim]")


# Scan handlers

async def _handle_quick_scan():
    """Handle quick scan option"""
    _print_submenu_header("Quick Scan")
    
    targets = _get_target_input()
    if not targets:
        return
    
    report_format = _select_report_format()
    
    profile = ScanProfile.get_profile("quick")
    
    console.print("\n[bold]Starting Quick Scan...[/bold]\n")
    results = await _run_scan(targets, profile, report_format)
    
    _print_scan_results(results)
    _save_reports(results, targets, report_format)


async def _handle_standard_scan():
    """Handle standard scan option"""
    _print_submenu_header("Standard Scan")
    
    targets = _get_target_input(allow_multiple=True)
    if not targets:
        return
    
    report_format = _select_report_format()
    
    profile = ScanProfile.get_profile("standard")
    
    console.print("\n[bold]Starting Standard Scan...[/bold]\n")
    results = await _run_scan(targets, profile, report_format)
    
    _print_scan_results(results)
    _save_reports(results, targets, report_format)


async def _handle_deep_scan():
    """Handle deep scan option"""
    _print_submenu_header("Deep Scan - Comprehensive Analysis")
    
    console.print("[yellow]Deep scan performs extensive testing including:[/yellow]")
    console.print("  - All standard vulnerability checks")
    console.print("  - Subdomain enumeration and takeover detection")
    console.print("  - JavaScript secret extraction")
    console.print("  - CORS misconfiguration testing")
    console.print("  - Host header injection testing")
    console.print("  - API endpoint discovery")
    console.print("  - CMS-specific vulnerability checks")
    console.print("  - Backup file discovery")
    console.print("  - VCS exposure detection")
    console.print("\n[dim]This scan may take several minutes per target.[/dim]")
    
    if not Confirm.ask("\n[cyan]Continue with deep scan?[/cyan]", default=True):
        return
    
    targets = _get_target_input(allow_multiple=True)
    if not targets:
        return
    
    report_format = _select_report_format()
    
    console.print("\n[bold]Starting Deep Scan...[/bold]")
    console.print("[dim]This may take a while...[/dim]\n")
    
    results = await _run_deep_scan(targets, report_format)
    
    _print_scan_results(results)
    _save_reports(results, targets, report_format)


async def _handle_custom_scan():
    """Handle custom scan option"""
    _print_submenu_header("Custom Scan Configuration")
    
    targets = _get_target_input(allow_multiple=True)
    if not targets:
        return
    
    modules = _select_custom_modules()
    report_format = _select_report_format()
    
    # Create custom profile from selections
    profile = ScanProfile(
        name="custom",
        description="Custom scan configuration",
        **modules
    )
    
    console.print("\n[bold]Starting Custom Scan...[/bold]\n")
    results = await _run_scan(targets, profile, report_format)
    
    _print_scan_results(results)
    _save_reports(results, targets, report_format)


async def _handle_stealth_scan():
    """Handle stealth scan option"""
    _print_submenu_header("Stealth Scan - Low Profile")
    
    console.print("[yellow]Stealth scan minimizes detection by:[/yellow]")
    console.print("  - Slower request rates")
    console.print("  - No path enumeration")
    console.print("  - Passive analysis only")
    console.print()
    
    targets = _get_target_input()
    if not targets:
        return
    
    report_format = _select_report_format()
    
    profile = ScanProfile.get_profile("stealth")
    
    console.print("\n[bold]Starting Stealth Scan...[/bold]\n")
    results = await _run_scan(targets, profile, report_format)
    
    _print_scan_results(results)
    _save_reports(results, targets, report_format)


async def _handle_api_scan():
    """Handle API security scan"""
    _print_submenu_header("API Security Scan")
    
    console.print("[yellow]API security scan includes:[/yellow]")
    console.print("  - REST API endpoint discovery")
    console.print("  - GraphQL introspection testing")
    console.print("  - CORS policy analysis")
    console.print("  - Parameter discovery")
    console.print("  - Authentication testing")
    console.print()
    
    targets = _get_target_input()
    if not targets:
        return
    
    report_format = _select_report_format()
    
    profile = ScanProfile.get_profile("api")
    
    console.print("\n[bold]Starting API Security Scan...[/bold]\n")
    results = await _run_scan(targets, profile, report_format)
    
    _print_scan_results(results)
    _save_reports(results, targets, report_format)


async def _handle_cms_scan():
    """Handle CMS security scan"""
    _print_submenu_header("CMS Security Scan")
    
    console.print("[yellow]CMS security scan detects and tests:[/yellow]")
    console.print("  - WordPress vulnerabilities")
    console.print("  - Drupal vulnerabilities")
    console.print("  - Joomla vulnerabilities")
    console.print("  - Laravel/Django frameworks")
    console.print("  - Plugin/theme vulnerabilities")
    console.print("  - Configuration exposure")
    console.print()
    
    targets = _get_target_input()
    if not targets:
        return
    
    report_format = _select_report_format()
    
    profile = ScanProfile.get_profile("cms")
    
    console.print("\n[bold]Starting CMS Security Scan...[/bold]\n")
    results = await _run_scan(targets, profile, report_format)
    
    _print_scan_results(results)
    _save_reports(results, targets, report_format)


async def _handle_subdomain_scan():
    """Handle subdomain enumeration"""
    _print_submenu_header("Subdomain Discovery & Analysis")
    
    console.print("[yellow]Subdomain enumeration includes:[/yellow]")
    console.print("  - DNS brute-force")
    console.print("  - Certificate Transparency logs")
    console.print("  - Subdomain permutations")
    console.print("  - Takeover vulnerability detection")
    console.print()
    
    domain = _get_domain_input()
    if not domain:
        return
    
    try:
        from .scanners.deep_scanner import DeepScanner
        scanner = DeepScanner()
        
        console.print(f"\n[bold]Enumerating Subdomains for {domain}...[/bold]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Discovering subdomains...", total=None)
            subdomains = await scanner.enumerate_subdomains(domain)
        
        if subdomains:
            console.print(f"\n[bold green]Found {len(subdomains)} subdomains:[/bold green]\n")
            
            # Display as tree
            tree = Tree(f"[cyan]{domain}[/cyan]")
            for sub in sorted(subdomains)[:50]:
                tree.add(f"[green]{sub}[/green]")
            
            if len(subdomains) > 50:
                tree.add(f"[dim]... and {len(subdomains) - 50} more[/dim]")
            
            console.print(tree)
            
            # Check for takeover
            if Confirm.ask("\n[cyan]Check for subdomain takeover vulnerabilities?[/cyan]", default=True):
                with console.status("[cyan]Checking for takeover vulnerabilities..."):
                    takeover_vulns = await scanner.check_subdomain_takeover(subdomains[:30])
                
                if takeover_vulns:
                    console.print(f"\n[bold red]Found {len(takeover_vulns)} potential takeover vulnerabilities![/bold red]")
                    for vuln in takeover_vulns:
                        console.print(f"  [red]![/red] {vuln.title}")
                else:
                    console.print("\n[green]No subdomain takeover vulnerabilities found.[/green]")
        else:
            console.print("[yellow]No subdomains discovered[/yellow]")
            
    except ImportError:
        console.print("[yellow]Deep scanner module not available.[/yellow]")


async def _handle_headers_scan():
    """Handle headers-only scan"""
    _print_submenu_header("HTTP Security Headers Analysis")
    
    from .scanners.http_headers import HTTPHeadersScanner
    
    targets = _get_target_input()
    if not targets:
        return
    
    target = targets[0]
    scanner = HTTPHeadersScanner()
    
    console.print("\n[bold]Analyzing HTTP Headers...[/bold]\n")
    
    with console.status("[cyan]Analyzing headers..."):
        vulns = await scanner.scan(target)
    
    if vulns:
        table = Table(title="HTTP Headers Findings", box=box.ROUNDED)
        table.add_column("Severity", width=10)
        table.add_column("Issue", width=45)
        table.add_column("CVSS", width=6)
        
        severity_colors = {
            "CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow",
            "LOW": "blue", "INFO": "green",
        }
        
        for vuln in vulns:
            sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
            color = severity_colors.get(sev, "white")
            table.add_row(f"[{color}]{sev}[/{color}]", vuln.title, f"{vuln.cvss_score:.1f}")
        
        console.print(table)
    else:
        console.print("[green]No HTTP header issues found![/green]")


async def _handle_ssl_scan():
    """Handle SSL-only scan"""
    _print_submenu_header("SSL/TLS Security Audit")
    
    from .scanners.ssl_checker import SSLChecker
    
    targets = _get_target_input("Target URL (HTTPS)")
    if not targets:
        return
    
    target = targets[0]
    if not target.startswith("https://"):
        target = target.replace("http://", "https://")
    
    scanner = SSLChecker()
    
    console.print("\n[bold]Analyzing SSL/TLS Configuration...[/bold]\n")
    
    with console.status("[cyan]Checking SSL/TLS..."):
        vulns = await scanner.scan(target)
    
    if vulns:
        table = Table(title="SSL/TLS Findings", box=box.ROUNDED)
        table.add_column("Severity", width=10)
        table.add_column("Issue", width=45)
        table.add_column("CVSS", width=6)
        
        severity_colors = {
            "CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow",
            "LOW": "blue", "INFO": "green",
        }
        
        for vuln in vulns:
            sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
            color = severity_colors.get(sev, "white")
            table.add_row(f"[{color}]{sev}[/{color}]", vuln.title, f"{vuln.cvss_score:.1f}")
        
        console.print(table)
    else:
        console.print("[green]No SSL/TLS issues found![/green]")


async def _handle_path_scan():
    """Handle path enumeration scan"""
    _print_submenu_header("Path & Directory Enumeration")
    
    from .scanners.path_enum import PathEnumerator
    
    targets = _get_target_input()
    if not targets:
        return
    
    target = targets[0]
    max_paths = IntPrompt.ask("[cyan]Maximum paths to check[/cyan]", default=500)
    
    scanner = PathEnumerator(wordlist_path=DEFAULT_WORDLIST if DEFAULT_WORDLIST.exists() else None)
    
    console.print("\n[bold]Enumerating Paths...[/bold]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"[cyan]Checking paths (max {max_paths})...", total=None)
        vulns = await scanner.scan(target, max_paths=max_paths)
    
    if vulns:
        table = Table(title="Path Enumeration Findings", box=box.ROUNDED)
        table.add_column("Severity", width=10)
        table.add_column("Path", width=55)
        
        severity_colors = {
            "CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow",
            "LOW": "blue", "INFO": "green",
        }
        
        for vuln in vulns:
            sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
            color = severity_colors.get(sev, "white")
            table.add_row(f"[{color}]{sev}[/{color}]", vuln.title)
        
        console.print(table)
        console.print(f"\n[bold]Found {len(vulns)} interesting paths[/bold]")
    else:
        console.print("[green]No interesting paths found![/green]")


async def _handle_javascript_analysis():
    """Handle JavaScript analysis"""
    _print_submenu_header("JavaScript Security Analysis")
    
    console.print("[yellow]JavaScript analysis includes:[/yellow]")
    console.print("  - Secret/API key extraction")
    console.print("  - Endpoint discovery")
    console.print("  - DOM XSS sink detection")
    console.print()
    
    targets = _get_target_input()
    if not targets:
        return
    
    target = targets[0]
    
    try:
        from .scanners.deep_scanner import DeepScanner
        scanner = DeepScanner()
        
        console.print("\n[bold]Analyzing JavaScript Files...[/bold]\n")
        
        with console.status("[cyan]Extracting and analyzing JavaScript..."):
            vulns = await scanner.analyze_javascript(target)
        
        if vulns:
            table = Table(title="JavaScript Analysis Findings", box=box.ROUNDED)
            table.add_column("Severity", width=10)
            table.add_column("Finding", width=55)
            
            severity_colors = {
                "CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow",
                "LOW": "blue", "INFO": "green",
            }
            
            for vuln in vulns:
                sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
                color = severity_colors.get(sev, "white")
                table.add_row(f"[{color}]{sev}[/{color}]", vuln.title)
            
            console.print(table)
        else:
            console.print("[green]No issues found in JavaScript files![/green]")
            
    except ImportError:
        console.print("[yellow]Deep scanner module not available.[/yellow]")


async def _handle_cors_test():
    """Handle CORS testing"""
    _print_submenu_header("CORS Misconfiguration Testing")
    
    targets = _get_target_input()
    if not targets:
        return
    
    target = targets[0]
    
    try:
        from .scanners.deep_scanner import DeepScanner
        scanner = DeepScanner()
        
        console.print("\n[bold]Testing CORS Configuration...[/bold]\n")
        
        with console.status("[cyan]Testing CORS policies..."):
            vulns = await scanner.check_cors(target)
        
        if vulns:
            for vuln in vulns:
                sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
                console.print(Panel(
                    f"[bold]{vuln.title}[/bold]\n\n{vuln.description}\n\n[dim]Evidence:[/dim]\n{vuln.evidence}",
                    title=f"[red]{sev}[/red]",
                    border_style="red",
                ))
        else:
            console.print("[green]No CORS misconfigurations found![/green]")
            
    except ImportError:
        console.print("[yellow]Deep scanner module not available.[/yellow]")


async def _handle_tech_detection():
    """Handle technology detection"""
    _print_submenu_header("Technology Detection")
    
    targets = _get_target_input()
    if not targets:
        return
    
    target = targets[0]
    
    from .scanners.vuln_patterns import VulnPatternScanner
    scanner = VulnPatternScanner(
        signatures_path=DEFAULT_SIGNATURES if DEFAULT_SIGNATURES.exists() else None
    )
    
    console.print("\n[bold]Detecting Technologies...[/bold]\n")
    
    with console.status("[cyan]Analyzing target..."):
        vulns, techs = await scanner.scan(target)
    
    if techs:
        table = Table(title="Detected Technologies", box=box.ROUNDED)
        table.add_column("Technology", style="bold cyan")
        table.add_column("Version")
        table.add_column("Category")
        table.add_column("Confidence", justify="right")
        
        for tech in techs:
            version = tech.version or "Unknown"
            confidence = f"{tech.confidence:.0%}" if tech.confidence else "N/A"
            table.add_row(tech.name, version, tech.category, confidence)
        
        console.print(table)
    else:
        console.print("[yellow]No technologies detected[/yellow]")


async def _handle_open_redirect_test():
    """Handle open redirect testing"""
    _print_submenu_header("Open Redirect Vulnerability Test")
    
    targets = _get_target_input()
    if not targets:
        return
    
    target = targets[0]
    
    try:
        from .scanners.deep_scanner import DeepScanner
        scanner = DeepScanner()
        
        console.print("\n[bold]Testing for Open Redirect...[/bold]\n")
        
        with console.status("[cyan]Testing redirect parameters..."):
            vulns = await scanner.test_open_redirect(target)
        
        if vulns:
            for vuln in vulns:
                console.print(Panel(
                    f"{vuln.description}\n\n[dim]Evidence:[/dim]\n{vuln.evidence}\n\n[dim]Remediation:[/dim]\n{vuln.remediation}",
                    title=f"[red]{vuln.title}[/red]",
                    border_style="red",
                ))
        else:
            console.print("[green]No open redirect vulnerabilities found![/green]")
            
    except ImportError:
        console.print("[yellow]Deep scanner module not available.[/yellow]")


async def _handle_host_header_test():
    """Handle host header injection testing"""
    _print_submenu_header("Host Header Injection Test")
    
    targets = _get_target_input()
    if not targets:
        return
    
    target = targets[0]
    
    try:
        from .scanners.deep_scanner import DeepScanner
        scanner = DeepScanner()
        
        console.print("\n[bold]Testing Host Header Injection...[/bold]\n")
        
        with console.status("[cyan]Testing host header..."):
            vulns = await scanner.test_host_header(target)
        
        if vulns:
            for vuln in vulns:
                console.print(Panel(
                    f"{vuln.description}\n\n[dim]Evidence:[/dim]\n{vuln.evidence}",
                    title=f"[red]{vuln.title}[/red]",
                    border_style="red",
                ))
        else:
            console.print("[green]No host header injection vulnerabilities found![/green]")
            
    except ImportError:
        console.print("[yellow]Deep scanner module not available.[/yellow]")


async def _handle_crlf_test():
    """Handle CRLF injection testing"""
    _print_submenu_header("CRLF Injection Test")
    
    targets = _get_target_input()
    if not targets:
        return
    
    target = targets[0]
    
    try:
        from .scanners.deep_scanner import DeepScanner
        scanner = DeepScanner()
        
        console.print("\n[bold]Testing CRLF Injection...[/bold]\n")
        
        with console.status("[cyan]Testing for CRLF injection..."):
            vulns = await scanner.test_crlf_injection(target)
        
        if vulns:
            for vuln in vulns:
                console.print(Panel(
                    f"{vuln.description}\n\n[dim]Evidence:[/dim]\n{vuln.evidence}",
                    title=f"[red]{vuln.title}[/red]",
                    border_style="red",
                ))
        else:
            console.print("[green]No CRLF injection vulnerabilities found![/green]")
            
    except ImportError:
        console.print("[yellow]Deep scanner module not available.[/yellow]")


async def _handle_backup_discovery():
    """Handle backup file discovery"""
    _print_submenu_header("Backup File Discovery")
    
    targets = _get_target_input()
    if not targets:
        return
    
    target = targets[0]
    
    try:
        from .scanners.deep_scanner import DeepScanner
        scanner = DeepScanner()
        
        console.print("\n[bold]Searching for Backup Files...[/bold]\n")
        
        with console.status("[cyan]Scanning for backup files..."):
            vulns = await scanner.check_backup_files(target)
        
        if vulns:
            for vuln in vulns:
                sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
                console.print(Panel(
                    f"{vuln.description}\n\n[dim]Evidence:[/dim]\n{vuln.evidence}",
                    title=f"[{vuln.severity.color if hasattr(vuln.severity, 'color') else 'red'}]{vuln.title}[/]",
                    border_style="yellow",
                ))
        else:
            console.print("[green]No exposed backup files found![/green]")
            
    except ImportError:
        console.print("[yellow]Deep scanner module not available.[/yellow]")


async def _handle_vcs_exposure():
    """Handle VCS exposure detection"""
    _print_submenu_header("Git/VCS Exposure Detection")
    
    targets = _get_target_input()
    if not targets:
        return
    
    target = targets[0]
    
    try:
        from .scanners.deep_scanner import DeepScanner
        scanner = DeepScanner()
        
        console.print("\n[bold]Checking for VCS Exposure...[/bold]\n")
        
        with console.status("[cyan]Scanning for exposed repositories..."):
            vulns = await scanner.check_vcs_exposure(target)
        
        if vulns:
            for vuln in vulns:
                console.print(Panel(
                    f"{vuln.description}\n\n[dim]Evidence:[/dim]\n{vuln.evidence}\n\n[dim]Remediation:[/dim]\n{vuln.remediation}",
                    title=f"[red]{vuln.title}[/red]",
                    border_style="red",
                ))
        else:
            console.print("[green]No exposed VCS repositories found![/green]")
            
    except ImportError:
        console.print("[yellow]Deep scanner module not available.[/yellow]")


async def _handle_waf_detection():
    """Handle WAF detection"""
    _print_submenu_header("WAF/CDN Detection")
    
    targets = _get_target_input()
    if not targets:
        return
    
    target = targets[0]
    
    try:
        from .scanners.deep_scanner import DeepScanner
        scanner = DeepScanner()
        
        console.print("\n[bold]Detecting WAF/CDN...[/bold]\n")
        
        with console.status("[cyan]Analyzing responses..."):
            waf_name, confidence = await scanner.detect_waf(target)
        
        if waf_name:
            console.print(Panel(
                f"[bold]Detected:[/bold] {waf_name}\n[bold]Confidence:[/bold] {confidence:.0%}",
                title="[cyan]WAF/CDN Detected[/cyan]",
                border_style="cyan",
            ))
        else:
            console.print("[yellow]No WAF/CDN detected[/yellow]")
            
    except ImportError:
        console.print("[yellow]Deep scanner module not available.[/yellow]")


def run_interactive_menu():
    """Main entry point for interactive mode"""
    
    while True:
        try:
            _clear_screen()
            _print_banner()
            _print_main_menu()
            
            choice = Prompt.ask("\n[bold cyan]Enter choice[/bold cyan]", default="0")
            
            # Handle menu selection
            if choice == "0":
                console.print("\n[bold blue]Thank you for using WebVulnPro. Goodbye![/bold blue]")
                break
            
            # Scan profiles
            elif choice == "1":
                asyncio.run(_handle_quick_scan())
            elif choice == "2":
                asyncio.run(_handle_standard_scan())
            elif choice == "3":
                asyncio.run(_handle_deep_scan())
            elif choice == "4":
                asyncio.run(_handle_custom_scan())
            elif choice == "5":
                asyncio.run(_handle_stealth_scan())
            
            # Specialized scans
            elif choice == "6":
                asyncio.run(_handle_api_scan())
            elif choice == "7":
                asyncio.run(_handle_cms_scan())
            elif choice == "8":
                asyncio.run(_handle_subdomain_scan())
            
            # Individual modules
            elif choice == "10":
                asyncio.run(_handle_headers_scan())
            elif choice == "11":
                asyncio.run(_handle_ssl_scan())
            elif choice == "12":
                asyncio.run(_handle_path_scan())
            elif choice == "13":
                asyncio.run(_handle_javascript_analysis())
            elif choice == "14":
                asyncio.run(_handle_cors_test())
            elif choice == "15":
                asyncio.run(_handle_tech_detection())
            
            # Advanced tests
            elif choice == "20":
                asyncio.run(_handle_open_redirect_test())
            elif choice == "21":
                asyncio.run(_handle_host_header_test())
            elif choice == "22":
                asyncio.run(_handle_crlf_test())
            elif choice == "23":
                asyncio.run(_handle_backup_discovery())
            elif choice == "24":
                asyncio.run(_handle_vcs_exposure())
            elif choice == "25":
                asyncio.run(_handle_waf_detection())
            
            # Utilities
            elif choice == "30":
                _view_previous_reports()
            elif choice == "31":
                _view_scan_profiles()
            elif choice == "32":
                console.print("[yellow]Configuration export coming soon![/yellow]")
            
            else:
                console.print("[red]Invalid option. Please try again.[/red]")
            
            # Pause before returning to menu
            if choice != "0":
                console.print()
                Prompt.ask("[dim]Press Enter to continue[/dim]")
                
        except KeyboardInterrupt:
            console.print("\n\n[yellow]Interrupted. Returning to menu...[/yellow]")
            continue
        except Exception as e:
            console.print(f"\n[red]Error: {str(e)}[/red]")
            Prompt.ask("[dim]Press Enter to continue[/dim]")


if __name__ == "__main__":
    run_interactive_menu()
