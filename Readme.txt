================================================================================
                              WEBVULNPRO
              Enterprise Web Vulnerability Assessment Tool
                            Advanced Edition
================================================================================

  Version 2.0.0  |  Python 3.9+  |  License: MIT  |  150+ Checks

A production-ready, standalone CLI tool for comprehensive web vulnerability
scanning and professional reporting. WebVulnPro performs 150+ real security
checks including OWASP Top 10 detection, deep scanning modules, security
header analysis, SSL/TLS assessment, and advanced vulnerability detection.


--------------------------------------------------------------------------------
FEATURES
--------------------------------------------------------------------------------

CORE SCANNING
  * 150+ Real Vulnerability Checks - No simulations, actual security testing
  * OWASP Top 10 Coverage - XSS, SQLi, Open Redirect, CSRF detection
  * Security Headers Analysis - 25+ HTTP header security checks
  * SSL/TLS Assessment - Certificate validity, protocol versions, cipher
    strength
  * Path Enumeration - 500+ paths for sensitive file/directory discovery
  * Technology Fingerprinting - CMS, frameworks, WAFs, server detection

ADVANCED DEEP SCANNING
  * Subdomain Enumeration - DNS brute-force and Certificate Transparency logs
  * JavaScript Analysis - Secret/API key extraction, endpoint discovery,
    DOM XSS detection
  * CORS Misconfiguration - Cross-origin policy testing
  * Host Header Injection - Header manipulation vulnerability testing
  * CRLF Injection - HTTP response splitting detection
  * Subdomain Takeover - Dangling DNS and unclaimed resource detection
  * CMS Vulnerability Scanning - WordPress, Drupal, Joomla, Laravel, Django
  * Backup File Discovery - Exposed configuration and backup files
  * Git/VCS Exposure - Repository and version control exposure
  * WAF/CDN Detection - Identify security appliances
  * GraphQL Security - Introspection and verbose error testing
  * API Endpoint Discovery - REST/GraphQL endpoint enumeration

OUTPUT & INTERFACE
  * Interactive Mode - Rich TUI with menu-driven scanning
  * Professional Reports - PDF, JSON, and HTML output formats
  * Organized Report Storage - Reports saved in Reports/<target>/ structure
  * High Performance - Async architecture supporting 1000+ targets
  * Safe Scanning - Non-destructive, passive analysis


--------------------------------------------------------------------------------
INSTALLATION
--------------------------------------------------------------------------------

  # Clone the repository
  git clone https://github.com/razzsecdev/webvulnpro.git
  cd webvulnpro

  # Install with pip (editable mode for development)
  pip install -e .

  # Or install dependencies directly
  pip install -r requirements.txt


--------------------------------------------------------------------------------
QUICK START
--------------------------------------------------------------------------------

  # Launch interactive mode (recommended for beginners)
  python -m webvulnpro

  # Single target scan
  python -m webvulnpro scan https://example.com

  # Scan with PDF report
  python -m webvulnpro scan https://example.com --output report.pdf

  # Deep scan with all advanced modules
  python -m webvulnpro deep https://example.com --output deep_report.pdf

  # Multiple targets from file
  python -m webvulnpro scan targets.txt --profile comprehensive --threads 50

  # Specific scans
  python webvulnpro headers https://example.com
  python webvulnpro ssl https://example.com
  python webvulnpro paths https://example.com --wordlist custom.txt


--------------------------------------------------------------------------------
CLI COMMANDS
--------------------------------------------------------------------------------

INTERACTIVE MODE

  # Launch interactive TUI (default when no command provided)
  python -m webvulnpro
  webvulnpro -m interactive

  The interactive mode provides a menu-driven interface with options for:
    - Quick, Standard, Deep, Custom, and Stealth scans
    - Specialized scans (API Security, CMS Security, Subdomain Discovery)
    - Individual modules (Headers, SSL, Paths, JavaScript Analysis,
      CORS Testing)
    - Advanced tests (Open Redirect, Host Header Injection, CRLF,
      Backup Files, VCS Exposure)
    - Report viewing and management

FULL SCAN

  python -m webvulnpro scan <targets> [OPTIONS]

  Arguments:
    targets           Target URL(s) or path to file with URLs

  Options:
    -o, --output      Output file (supports .json, .html, .pdf)
    -p, --profile     Scan profile: quick, standard, comprehensive, deep,
                       passive, stealth, api, cms
    -t, --threads     Concurrent scans (default: 20)
    -w, --wordlist    Custom wordlist for path enumeration
    -s, --signatures  Custom vulnerability signatures file
    --no-paths        Skip path enumeration
    --no-ssl          Skip SSL/TLS checks
    -q, --quiet       Minimal output

DEEP SCAN

  python -m webvulnpro deep <targets> [OPTIONS]

  Arguments:
    targets           Target URL(s) or path to file with URLs

  Options:
    -o, --output      Output file (supports .json, .html, .pdf)
    -t, --threads     Concurrent scans (default: 5, lower for thorough
                       testing)
    -q, --quiet       Minimal output

  Deep scan includes all standard checks plus:
    - Subdomain enumeration and takeover detection
    - JavaScript secret extraction
    - CORS misconfiguration testing
    - Host header injection testing
    - API endpoint discovery
    - CMS-specific vulnerability checks
    - Backup file discovery
    - VCS exposure detection

HTTP HEADERS SCAN

  python -m webvulnpro headers https://example.com
  python -m webvulnpro headers https://example.com --output headers.json

SSL/TLS SCAN

  python -m webvulnpro ssl https://example.com
  python -m webvulnpro ssl https://example.com --output ssl-report.pdf

PATH ENUMERATION

  python -m webvulnpro paths https://example.com
  python -m webvulnpro paths https://example.com --wordlist custom.txt --max 1000

LIST PROFILES

  python -m webvulnpro profiles


--------------------------------------------------------------------------------
SCAN PROFILES
--------------------------------------------------------------------------------

  Profile          Description                Headers  SSL  Paths  Vulns  Deep
  ---------------  -------------------------  -------  ---  -----  -----  -------
  quick            Fast essential checks         Y      Y     -      -       -
  standard         Balanced scanning             Y      Y     Y      Y       -
  comprehensive    Full thorough scan             Y      Y     Y      Y       -
  deep             All modules + advanced         Y      Y     Y      Y       Y
  passive          Non-intrusive only             Y      Y     -      -       -
  stealth          Low-profile passive            Y      Y     -      -       -
  api              REST/GraphQL testing           Y      Y     Y      Y     Partial
  cms              CMS vulnerability scan         Y      Y     Y      Y     Partial


--------------------------------------------------------------------------------
VULNERABILITY COVERAGE
--------------------------------------------------------------------------------

HTTP SECURITY HEADERS (25+ CHECKS)
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy
  - Cross-Origin-Embedder-Policy
  - Cross-Origin-Opener-Policy
  - Cross-Origin-Resource-Policy
  - Cookie Security (Secure, HttpOnly, SameSite)
  - Information Disclosure Headers

OWASP TOP 10 DETECTION
  1. XSS Reflection - 50+ payloads for reflected XSS testing
  2. SQL Injection - Error-based detection for MySQL, PostgreSQL, MSSQL,
     Oracle, SQLite
  3. Open Redirect - Parameter-based redirect vulnerability testing
  4. CSRF - Token absence detection in forms
  5. Sensitive Data Exposure - API keys, credentials, private keys

SSL/TLS ASSESSMENT
  - Certificate expiry and validity
  - Hostname verification
  - Self-signed certificate detection
  - TLS protocol version checks (TLS 1.0/1.1 deprecation)
  - Cipher suite strength analysis
  - Key size validation

PATH ENUMERATION
  - Git/SVN repository exposure
  - Environment files (.env, config.php)
  - Backup files (.bak, .old, ~)
  - Admin panels
  - Debug endpoints
  - API documentation
  - 500+ paths in default wordlist

TECHNOLOGY FINGERPRINTING
  - CMS: WordPress, Drupal, Joomla, Magento, Shopify
  - Frameworks: Laravel, Django, Rails, ASP.NET, Spring, Express.js
  - WAF/CDN: Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, Sucuri, Fastly
  - Servers: Apache, Nginx, IIS


--------------------------------------------------------------------------------
DEEP SCANNING MODULES
--------------------------------------------------------------------------------

SUBDOMAIN ENUMERATION
  - DNS brute-force with 500+ common subdomain prefixes
  - Certificate Transparency (CT) log lookup via crt.sh
  - Subdomain permutation generation
  - Subdomain takeover vulnerability detection

JAVASCRIPT ANALYSIS
  - Secret and API key extraction (AWS, Google, Stripe, etc.)
  - Endpoint discovery from fetch/axios calls
  - DOM-based XSS sink and source detection
  - JWT token exposure detection

CORS TESTING
  - Wildcard origin testing
  - Origin reflection with credentials
  - Null origin exploitation
  - Subdomain-based CORS bypasses

CMS VULNERABILITY SCANNING
  Specialized checks for:
  - WordPress: User enumeration, XML-RPC, debug logs, config backups
  - Drupal: Version disclosure, settings exposure
  - Joomla: Admin panel, configuration backups
  - Laravel: .env exposure, Telescope, Debugbar
  - Django: Debug mode, admin panel exposure


--------------------------------------------------------------------------------
OUTPUT FORMATS
--------------------------------------------------------------------------------

JSON REPORT

  {
    "report_info": {
      "generator": "WebVulnPro",
      "version": "2.0.0",
      "generated_at": "2026-01-27T20:24:00"
    },
    "summary": {
      "targets_scanned": 1,
      "total_vulnerabilities": 15,
      "by_severity": {
        "CRITICAL": 2,
        "HIGH": 5,
        "MEDIUM": 4,
        "LOW": 3,
        "INFO": 1
      }
    },
    "scan_results": [...]
  }

PDF REPORT

  Professional enterprise-grade PDF with:
    - Executive summary
    - Risk score visualization
    - Findings table by severity
    - Detailed remediation guidance
    - Technology inventory

HTML REPORT

  Interactive dashboard-style report with:
    - Severity distribution charts
    - Filterable findings table
    - Technology badges
    - Detailed finding cards


--------------------------------------------------------------------------------
PROGRAMMATIC USAGE
--------------------------------------------------------------------------------

  import asyncio
  from webvulnpro.core.scanner import WebVulnScanner, ScanManager
  from webvulnpro.core.models import ScanProfile
  from webvulnpro.core.reporter import ReportGenerator

  async def scan_target():
      # Standard scan with profile
      profile = ScanProfile.get_profile("comprehensive")
      scanner = WebVulnScanner(profile=profile)

      # Scan target
      result = await scanner.scan_target("https://example.com")

      # Print findings
      for vuln in result.vulnerabilities:
          print(f"[{vuln.severity}] {vuln.title}")

      # Generate report
      reporter = ReportGenerator()
      reporter.save_report([result], "report.pdf")

  async def deep_scan_target():
      # Deep scan with all advanced modules
      manager = ScanManager()
      results = await manager.run_deep_scan(["https://example.com"])

      # Access metadata (subdomains, endpoints, etc.)
      for result in results:
          print(f"Target: {result.target}")
          print(f"Vulnerabilities: {len(result.vulnerabilities)}")
          print(f"Technologies: {[t.name for t in result.technologies]}")

  asyncio.run(scan_target())


--------------------------------------------------------------------------------
CUSTOM WORDLISTS
--------------------------------------------------------------------------------

  Create custom wordlists for path enumeration:

  # custom-paths.txt
  /admin/
  /api/v1/
  /backup/
  /.env
  /.git/config

  Use with:

  python -m webvulnpro paths https://example.com --wordlist custom-paths.txt


--------------------------------------------------------------------------------
CUSTOM SIGNATURES
--------------------------------------------------------------------------------

  Extend vulnerability detection with custom signatures:

  {
    "sql_errors": {
      "CustomDB": [
        "CustomDB.*Error",
        "custom_db_exception"
      ]
    }
  }

  Use with:

  python -m webvulnpro scan https://example.com --signatures custom-sigs.json


--------------------------------------------------------------------------------
EXIT CODES
--------------------------------------------------------------------------------

  Code   Meaning
  ----   -------------------------------------
  0      Success, no critical/high findings
  1      High severity findings detected
  2      Critical severity findings detected
  130    Interrupted by user (Ctrl+C)


--------------------------------------------------------------------------------
TEST TARGETS
--------------------------------------------------------------------------------

  Validate against these intentionally vulnerable targets:

  python -m webvulnpro scan https://scanme.nmap.org
  python -m webvulnpro scan http://testphp.vulnweb.com
  python -m webvulnpro scan https://demo.testfire.net


--------------------------------------------------------------------------------
PROJECT STRUCTURE
--------------------------------------------------------------------------------

  webvulnpro/
  |-- webvulnpro/
  |   |-- __init__.py
  |   |-- __main__.py
  |   |-- main.py
  |   |-- cli.py                  # Command-line interface
  |   |-- interactive.py          # Interactive TUI mode
  |   |-- core/
  |   |   |-- __init__.py
  |   |   |-- models.py           # Data models and scan profiles
  |   |   |-- scanner.py          # Main scanner and ScanManager
  |   |   |-- reporter.py         # Report generation (PDF/HTML/JSON)
  |   |-- scanners/
  |   |   |-- __init__.py
  |   |   |-- http_headers.py     # HTTP security headers scanner
  |   |   |-- ssl_checker.py      # SSL/TLS configuration scanner
  |   |   |-- vuln_patterns.py    # Vulnerability pattern detection
  |   |   |-- path_enum.py        # Path enumeration scanner
  |   |   |-- deep_scanner.py     # Advanced deep scanning modules
  |   |-- signatures/
  |   |   |-- vuln_signatures.json
  |   |   |-- technologies.json
  |   |-- wordlists/
  |   |   |-- paths.txt           # Path enumeration wordlist
  |   |   |-- xss_payloads.txt    # XSS testing payloads
  |   |   |-- subdomains.txt      # Subdomain enumeration wordlist
  |   |   |-- parameters.txt      # Parameter discovery wordlist
  |   |-- Reports/                # Organized scan reports
  |       |-- <target>/
  |           |-- report_<timestamp>.<format>
  |-- tests/
  |-- requirements.txt
  |-- setup.py
  |-- pyproject.toml
  |-- README.md


--------------------------------------------------------------------------------
REQUIREMENTS
--------------------------------------------------------------------------------

  - Python 3.9+
  - aiohttp
  - typer
  - rich
  - reportlab


--------------------------------------------------------------------------------
CONTRIBUTING
--------------------------------------------------------------------------------

  1. Fork the repository
  2. Create a feature branch
  3. Make your changes
  4. Run tests: pytest
  5. Submit a pull request


--------------------------------------------------------------------------------
LICENSE
--------------------------------------------------------------------------------

  MIT License - see LICENSE file for details.


--------------------------------------------------------------------------------
DISCLAIMER
--------------------------------------------------------------------------------

  This tool is for authorized security testing only. Always obtain proper
  authorization before scanning any systems. The authors are not responsible
  for misuse of this tool.


--------------------------------------------------------------------------------
SUPPORT
--------------------------------------------------------------------------------

  - Issues:        https://github.com/razzsecdev/webvulnpro/issues
  - Documentation: https://github.com/razzsecdev/webvulnpro/wiki


================================================================================
                 WebVulnPro v2.0.0
   Enterprise-grade web vulnerability assessment made simple.
================================================================================