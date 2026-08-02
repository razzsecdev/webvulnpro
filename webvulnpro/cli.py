"""
WebVulnPro CLI - Command-line interface for vulnerability scanning
"""

import asyncio
import re
import sys
from pathlib import Path
from typing import List, Optional
from datetime import datetime
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich import box

from .core.models import ScanProfile, Severity
from .core.scanner import WebVulnScanner, ScanManager
from .core.reporter import ReportGenerator

# Initialize CLI app
app = typer.Typer(
    name="webvulnpro",
    help="WebVulnPro - Enterprise Web Vulnerability Assessment Tool",
    add_completion=False,
    invoke_without_command=True,
)

console = Console()

# Get package directory for default paths
PACKAGE_DIR = Path(__file__).parent
DEFAULT_WORDLIST = PACKAGE_DIR / "wordlists" / "paths.txt"
DEFAULT_SIGNATURES = PACKAGE_DIR / "signatures" / "vuln_signatures.json"
REPORTS_DIR = PACKAGE_DIR / "Reports"


def _get_target_folder_name(target: str) -> str:
    """
    Extract domain/IP from target URL for folder naming.
    Sanitizes the name to be filesystem-safe.
    """
    try:
        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.path
        
        # Remove port if present
        if hostname:
            hostname = hostname.split(':')[0]
        
        # Sanitize for filesystem (remove invalid chars)
        safe_name = re.sub(r'[<>:"/\\|?*]', '_', hostname)
        safe_name = safe_name.strip('. ')
        
        return safe_name or "unknown_target"
    except Exception:
        return "unknown_target"


def _create_report_path(targets: List[str], output_filename: str) -> Path:
    """
    Create the report path in Reports/<target_folder>/ structure.
    Creates the folder if it doesn't exist.
    """
    # Ensure Reports directory exists
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Get folder name from first target (or "multiple_targets" if many)
    if len(targets) == 1:
        folder_name = _get_target_folder_name(targets[0])
    else:
        # For multiple targets, use timestamp-based folder
        folder_name = f"multi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Create target-specific folder
    target_folder = REPORTS_DIR / folder_name
    target_folder.mkdir(parents=True, exist_ok=True)
    
    # Add timestamp to filename to avoid overwrites
    output_path = Path(output_filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    new_filename = f"{output_path.stem}_{timestamp}{output_path.suffix}"
    
    return target_folder / new_filename


def version_callback(value: bool):
    if value:
        console.print("[bold blue]WebVulnPro[/bold blue] v1.0.0")
        console.print("Enterprise Web Vulnerability Assessment Tool")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None, "--version", "-v",
        callback=version_callback,
        help="Show version and exit"
    ),
):
    """WebVulnPro - Enterprise Web Vulnerability Assessment Tool
    
    Run without arguments to start interactive mode.
    """
    # If no command is provided, run interactive mode
    if ctx.invoked_subcommand is None:
        from .interactive import run_interactive_menu
        run_interactive_menu()


@app.command()
def interactive():
    """
    Start the interactive menu interface.
    
    This is the default mode when running webvulnpro without arguments.
    
    Example:
        webvulnpro interactive
        webvulnpro  # Same as above
    """
    from .interactive import run_interactive_menu
    run_interactive_menu()


@app.command()
def scan(
    targets: List[str] = typer.Argument(
        ...,
        help="Target URL(s) or path to file containing URLs"
    ),
    output: str = typer.Option(
        "report.json",
        "--output", "-o",
        help="Output report file (supports .json, .html, .pdf)"
    ),
    profile: str = typer.Option(
        "standard",
        "--profile", "-p",
        help="Scan profile: quick, standard, comprehensive, deep, passive, stealth, api, cms"
    ),
    threads: int = typer.Option(
        20,
        "--threads", "-t",
        help="Number of concurrent scans"
    ),
    wordlist: Optional[str] = typer.Option(
        None,
        "--wordlist", "-w",
        help="Custom wordlist for path enumeration"
    ),
    signatures: Optional[str] = typer.Option(
        None,
        "--signatures", "-s",
        help="Custom vulnerability signatures file"
    ),
    no_paths: bool = typer.Option(
        False,
        "--no-paths",
        help="Skip path enumeration"
    ),
    no_ssl: bool = typer.Option(
        False,
        "--no-ssl",
        help="Skip SSL/TLS checks"
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Minimal output"
    ),
):
    """
    Perform comprehensive vulnerability scan on target(s).
    
    Examples:
        webvulnpro scan https://example.com
        webvulnpro scan https://example.com --output report.pdf
        webvulnpro scan targets.txt --profile comprehensive --threads 50
    """
    try:
        # Resolve targets
        target_list = _resolve_targets(targets)
        
        if not target_list:
            console.print("[red]Error:[/red] No valid targets specified")
            raise typer.Exit(1)
        
        if not quiet:
            _print_banner()
            console.print(f"\n[bold]Scanning {len(target_list)} target(s)[/bold]")
            console.print(f"Profile: [cyan]{profile}[/cyan] | Threads: [cyan]{threads}[/cyan]")
            console.print()
        
        # Get scan profile and customize
        scan_profile = ScanProfile.get_profile(profile)
        if no_paths:
            scan_profile.scan_paths = False
        if no_ssl:
            scan_profile.scan_ssl = False
        
        # Resolve paths
        wordlist_path = Path(wordlist) if wordlist else DEFAULT_WORDLIST
        signatures_path = Path(signatures) if signatures else DEFAULT_SIGNATURES
        
        # Create scanner
        scanner = WebVulnScanner(
            profile=scan_profile,
            signatures_path=signatures_path if signatures_path.exists() else None,
            wordlist_path=wordlist_path if wordlist_path.exists() else None,
        )
        
        # Run scan with progress
        results = asyncio.run(_run_scan_with_progress(
            scanner, target_list, threads, quiet
        ))
        
        # Print results summary
        if not quiet:
            _print_results_summary(results)
        
        # Generate report in Reports/<target>/ folder
        report_path = _create_report_path(target_list, output)
        reporter = ReportGenerator()
        output_path = reporter.save_report(results, str(report_path), target_list[0] if len(target_list) == 1 else None)
        
        console.print(f"\n[green]Report saved to:[/green] {output_path}")
        
        # Exit with code based on findings
        critical_count = sum(
            1 for r in results for v in r.vulnerabilities 
            if (v.severity.value if isinstance(v.severity, Severity) else v.severity) == "CRITICAL"
        )
        high_count = sum(
            1 for r in results for v in r.vulnerabilities 
            if (v.severity.value if isinstance(v.severity, Severity) else v.severity) == "HIGH"
        )
        
        if critical_count > 0:
            raise typer.Exit(2)
        elif high_count > 0:
            raise typer.Exit(1)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise typer.Exit(1)


@app.command()
def headers(
    target: str = typer.Argument(..., help="Target URL"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file (optional)"
    ),
):
    """
    Scan HTTP security headers only.
    
    Example:
        webvulnpro headers https://example.com
    """
    from .scanners.http_headers import HTTPHeadersScanner
    
    _print_banner()
    console.print(f"\n[bold]HTTP Headers Scan:[/bold] {target}\n")
    
    scanner = HTTPHeadersScanner()
    
    with console.status("[bold green]Scanning headers..."):
        results = asyncio.run(scanner.scan(target))
    
    if results:
        _print_vulnerability_table(results, "HTTP Headers Findings")
        
        if output:
            # Save to Reports/<target>/ folder
            report_path = _create_report_path([target], output)
            reporter = ReportGenerator()
            from .core.models import ScanResult
            scan_result = ScanResult(
                target=target,
                start_time=datetime.now(),
                end_time=datetime.now(),
                vulnerabilities=results,
            )
            saved_path = reporter.save_report([scan_result], str(report_path))
            console.print(f"\n[green]Report saved to:[/green] {saved_path}")
    else:
        console.print("[green]No security header issues found![/green]")


@app.command()
def ssl(
    target: str = typer.Argument(..., help="Target URL (HTTPS)"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file (optional)"
    ),
):
    """
    Scan SSL/TLS configuration only.
    
    Example:
        webvulnpro ssl https://example.com
    """
    from .scanners.ssl_checker import SSLChecker
    
    if not target.lower().startswith("https"):
        console.print("[yellow]Warning:[/yellow] Target should use HTTPS for SSL scan")
        target = target.replace("http://", "https://")
    
    _print_banner()
    console.print(f"\n[bold]SSL/TLS Scan:[/bold] {target}\n")
    
    scanner = SSLChecker()
    
    with console.status("[bold green]Analyzing SSL/TLS..."):
        results = asyncio.run(scanner.scan(target))
    
    if results:
        _print_vulnerability_table(results, "SSL/TLS Findings")
        
        if output:
            # Save to Reports/<target>/ folder
            report_path = _create_report_path([target], output)
            reporter = ReportGenerator()
            from .core.models import ScanResult
            scan_result = ScanResult(
                target=target,
                start_time=datetime.now(),
                end_time=datetime.now(),
                vulnerabilities=results,
            )
            saved_path = reporter.save_report([scan_result], str(report_path))
            console.print(f"\n[green]Report saved to:[/green] {saved_path}")
    else:
        console.print("[green]No SSL/TLS issues found![/green]")


@app.command()
def paths(
    target: str = typer.Argument(..., help="Target URL"),
    wordlist: Optional[str] = typer.Option(
        None, "--wordlist", "-w",
        help="Custom wordlist file"
    ),
    max_paths: int = typer.Option(
        500, "--max", "-m",
        help="Maximum paths to check"
    ),
    threads: int = typer.Option(
        20, "--threads", "-t",
        help="Concurrent requests"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file (optional)"
    ),
):
    """
    Enumerate paths and directories.
    
    Example:
        webvulnpro paths https://example.com --wordlist custom.txt
    """
    from .scanners.path_enum import PathEnumerator
    
    _print_banner()
    console.print(f"\n[bold]Path Enumeration:[/bold] {target}\n")
    
    wordlist_path = Path(wordlist) if wordlist else DEFAULT_WORDLIST
    
    scanner = PathEnumerator(
        wordlist_path=wordlist_path if wordlist_path.exists() else None,
        max_concurrent=threads,
    )
    
    with console.status(f"[bold green]Enumerating paths (max {max_paths})..."):
        results = asyncio.run(scanner.scan(target, max_paths=max_paths))
    
    if results:
        _print_vulnerability_table(results, "Path Enumeration Findings")
        
        if output:
            # Save to Reports/<target>/ folder
            report_path = _create_report_path([target], output)
            reporter = ReportGenerator()
            from .core.models import ScanResult
            scan_result = ScanResult(
                target=target,
                start_time=datetime.now(),
                end_time=datetime.now(),
                vulnerabilities=results,
            )
            saved_path = reporter.save_report([scan_result], str(report_path))
            console.print(f"\n[green]Report saved to:[/green] {saved_path}")
    else:
        console.print("[green]No interesting paths found![/green]")


@app.command()
def deep(
    targets: List[str] = typer.Argument(
        ...,
        help="Target URL(s) or path to file containing URLs"
    ),
    output: str = typer.Option(
        "deep_report.json",
        "--output", "-o",
        help="Output report file (supports .json, .html, .pdf)"
    ),
    threads: int = typer.Option(
        5,
        "--threads", "-t",
        help="Number of concurrent scans (lower for deep scan)"
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Minimal output"
    ),
):
    """
    Perform comprehensive deep scan with all advanced modules.
    
    This includes subdomain enumeration, JavaScript analysis, CORS testing,
    CMS vulnerability scanning, and more.
    
    Examples:
        webvulnpro deep https://example.com
        webvulnpro deep https://example.com --output deep_report.pdf
    """
    try:
        # Resolve targets
        target_list = _resolve_targets(targets)
        
        if not target_list:
            console.print("[red]Error:[/red] No valid targets specified")
            raise typer.Exit(1)
        
        if not quiet:
            _print_banner()
            console.print(f"\n[bold]Deep Scanning {len(target_list)} target(s)[/bold]")
            console.print("[dim]This may take several minutes per target...[/dim]")
            console.print()
        
        # Create scan manager and run deep scan
        manager = ScanManager()
        results = asyncio.run(manager.run_deep_scan(
            target_list, max_concurrent=threads
        ))
        
        # Print results summary
        if not quiet:
            _print_results_summary(results)
        
        # Generate report
        report_path = _create_report_path(target_list, output)
        reporter = ReportGenerator()
        output_path = reporter.save_report(results, str(report_path), target_list[0] if len(target_list) == 1 else None)
        
        console.print(f"\n[green]Report saved to:[/green] {output_path}")
        
        # Exit with code based on findings
        critical_count = sum(
            1 for r in results for v in r.vulnerabilities 
            if (v.severity.value if isinstance(v.severity, Severity) else v.severity) == "CRITICAL"
        )
        high_count = sum(
            1 for r in results for v in r.vulnerabilities 
            if (v.severity.value if isinstance(v.severity, Severity) else v.severity) == "HIGH"
        )
        
        if critical_count > 0:
            raise typer.Exit(2)
        elif high_count > 0:
            raise typer.Exit(1)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise typer.Exit(1)


@app.command()
def profiles():
    """List available scan profiles."""
    _print_banner()
    
    table = Table(title="Available Scan Profiles", box=box.ROUNDED)
    table.add_column("Profile", style="cyan")
    table.add_column("Description")
    table.add_column("Headers", justify="center")
    table.add_column("SSL", justify="center")
    table.add_column("Paths", justify="center")
    table.add_column("Deep", justify="center")
    
    for name in ["quick", "standard", "comprehensive", "deep", "passive", "stealth", "api", "cms"]:
        p = ScanProfile.get_profile(name)
        has_deep = any([
            getattr(p, 'scan_subdomains', False),
            getattr(p, 'scan_javascript', False),
            getattr(p, 'scan_cors', False),
        ])
        table.add_row(
            name,
            p.description,
            "[green]+[/green]" if p.scan_headers else "[red]-[/red]",
            "[green]+[/green]" if p.scan_ssl else "[red]-[/red]",
            "[green]+[/green]" if p.scan_paths else "[red]-[/red]",
            "[green]+[/green]" if has_deep else "[red]-[/red]",
        )
    
    console.print(table)
    console.print("\n[dim]Use --profile <name> with scan command to use a specific profile[/dim]")


def _print_banner():
    """Print WebVulnPro banner"""
    banner = """
[bold blue]╦ ╦┌─┐┌┐ ╦  ╦┬ ┬┬  ┌┐┌╔═╗┬─┐┌─┐[/bold blue]
[bold blue]║║║├┤ ├┴┐╚╗╔╝│ ││  │││╠═╝├┬┘│ │[/bold blue]
[bold blue]╚╩╝└─┘└─┘ ╚╝ └─┘┴─┘┘└┘╩  ┴└─└─┘[/bold blue]
[dim]Enterprise Web Vulnerability Scanner v1.0.0[/dim]
"""
    console.print(banner)


def _resolve_targets(targets: List[str]) -> List[str]:
    """Resolve target list (handles files)"""
    resolved = []
    
    for target in targets:
        path = Path(target)
        if path.exists() and path.is_file():
            # Read targets from file
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        resolved.append(line)
        else:
            resolved.append(target)
    
    return resolved


async def _run_scan_with_progress(scanner: WebVulnScanner, targets: List[str], 
                                   max_concurrent: int, quiet: bool):
    """Run scan with progress display"""
    semaphore = asyncio.Semaphore(max_concurrent)
    results = []
    
    async def scan_target(target: str, progress, task_id):
        async with semaphore:
            result = await scanner.scan_target(target)
            progress.update(task_id, advance=1)
            return result
    
    if quiet:
        tasks = [scanner.scan_target(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task(
                "[cyan]Scanning targets...", 
                total=len(targets)
            )
            
            tasks = [scan_target(t, progress, task_id) for t in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter out exceptions
    valid_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            from .core.models import ScanResult
            valid_results.append(ScanResult(
                target=targets[i],
                start_time=datetime.now(),
                end_time=datetime.now(),
                error=str(result),
            ))
        else:
            valid_results.append(result)
    
    return valid_results


def _print_results_summary(results):
    """Print scan results summary"""
    console.print("\n" + "=" * 60)
    console.print("[bold]SCAN RESULTS SUMMARY[/bold]")
    console.print("=" * 60)
    
    total_vulns = 0
    by_severity = {}
    
    for result in results:
        for vuln in result.vulnerabilities:
            total_vulns += 1
            sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
            by_severity[sev] = by_severity.get(sev, 0) + 1
    
    # Severity table
    table = Table(box=box.SIMPLE)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    
    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange1", 
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "green",
    }
    
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_severity.get(sev, 0)
        if count > 0:
            table.add_row(f"[{severity_colors[sev]}]{sev}[/{severity_colors[sev]}]", str(count))
    
    console.print(table)
    console.print(f"\n[bold]Total Findings:[/bold] {total_vulns}")
    
    # Risk score
    total_risk = sum(r.risk_score for r in results)
    avg_risk = total_risk // len(results) if results else 0
    
    risk_color = "green" if avg_risk < 25 else "yellow" if avg_risk < 50 else "orange1" if avg_risk < 75 else "red"
    console.print(f"[bold]Risk Score:[/bold] [{risk_color}]{avg_risk}/100[/{risk_color}]")
    
    # Top findings
    if total_vulns > 0:
        console.print("\n[bold]Top Findings:[/bold]")
        
        all_vulns = []
        for result in results:
            for vuln in result.vulnerabilities:
                all_vulns.append((result.target, vuln))
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_vulns.sort(key=lambda x: severity_order.get(
            x[1].severity.value if isinstance(x[1].severity, Severity) else x[1].severity, 5
        ))
        
        for target, vuln in all_vulns[:10]:
            sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
            color = severity_colors.get(sev, "white")
            console.print(f"  [{color}][{sev}][/{color}] {vuln.title}")


def _print_vulnerability_table(vulns, title: str):
    """Print vulnerability table"""
    table = Table(title=title, box=box.ROUNDED)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Title", width=40)
    table.add_column("CVSS", justify="right", width=6)
    table.add_column("Category", width=20)
    
    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange1",
        "MEDIUM": "yellow", 
        "LOW": "blue",
        "INFO": "green",
    }
    
    for vuln in vulns:
        sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
        color = severity_colors.get(sev, "white")
        table.add_row(
            f"[{color}]{sev}[/{color}]",
            vuln.title[:38] + ".." if len(vuln.title) > 40 else vuln.title,
            f"{vuln.cvss_score:.1f}",
            vuln.category,
        )
    
    console.print(table)


# Entry point for direct execution
def cli_main():
    """Main entry point for CLI"""
    app()


if __name__ == "__main__":
    cli_main()
