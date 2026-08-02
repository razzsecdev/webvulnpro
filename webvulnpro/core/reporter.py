"""
Report Generator - PDF, JSON, and HTML report generation
Enhanced with categorized technology detection display
"""

import json
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import List, Dict, Any, Optional
import html

from .models import Vulnerability, ScanResult, Severity, TechnologyFingerprint, TechnologyCategory


class ReportGenerator:
    """Generate professional vulnerability reports in multiple formats"""
    
    SEVERITY_COLORS = {
        "CRITICAL": "#dc3545",  # Red
        "HIGH": "#fd7e14",      # Orange
        "MEDIUM": "#ffc107",    # Yellow
        "LOW": "#17a2b8",       # Blue
        "INFO": "#28a745",      # Green
    }
    
    SEVERITY_ICONS = {
        "CRITICAL": "!!!",
        "HIGH": "!!",
        "MEDIUM": "!",
        "LOW": "~",
        "INFO": "i",
    }
    
    # Category colors for technology badges
    CATEGORY_COLORS = {
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
        "Font": "#795548",
        "Widget": "#00BCD4",
        "Payment": "#4CAF50",
        "SEO": "#8BC34A",
        "UI Framework": "#E91E63",
        "Static Site Generator": "#795548",
        "Live Chat": "#4CAF50",
        "Comment": "#2196F3",
        "Video": "#F44336",
        "Search": "#673AB7",
        "Build Tool": "#607D8B",
        "Miscellaneous": "#9E9E9E",
        "Unknown": "#9E9E9E",
    }
    
    # Category icons
    CATEGORY_ICONS = {
        "CMS": "📝",
        "E-commerce": "🛒",
        "Framework": "🏗️",
        "JavaScript Framework": "⚛️",
        "JavaScript Library": "📚",
        "Programming Language": "💻",
        "Web Server": "🖥️",
        "Operating System": "💿",
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
        "UI Framework": "🎨",
        "Static Site Generator": "📄",
        "Live Chat": "💬",
        "Comment": "💬",
        "Video": "🎬",
        "Search": "🔍",
        "Build Tool": "🔧",
        "Miscellaneous": "📦",
        "Unknown": "❓",
    }
    
    def __init__(self):
        self.generated_at = datetime.now()
    
    def generate_json(self, results: List[ScanResult], 
                      pretty: bool = True) -> str:
        """
        Generate JSON report.
        
        Args:
            results: List of ScanResults
            pretty: Pretty print JSON
            
        Returns:
            JSON string
        """
        report = {
            "report_info": {
                "generator": "WebVulnPro",
                "version": "2.0.0",
                "generated_at": self.generated_at.isoformat(),
                "format": "JSON",
            },
            "summary": self._generate_summary(results),
            "scan_results": [r.to_dict() for r in results],
        }
        
        if pretty:
            return json.dumps(report, indent=2, default=str)
        return json.dumps(report, default=str)
    
    def generate_html(self, results: List[ScanResult]) -> str:
        """
        Generate HTML report with dashboard-style layout.
        
        Args:
            results: List of ScanResults
            
        Returns:
            HTML string
        """
        summary = self._generate_summary(results)
        
        # Build HTML
        html_parts = [self._html_header()]
        
        # Executive Summary
        html_parts.append(self._html_executive_summary(summary))
        
        # Findings Summary Chart
        html_parts.append(self._html_severity_chart(summary))
        
        # Technologies Detected (Enhanced)
        all_techs = []
        for result in results:
            all_techs.extend(result.technologies)
        if all_techs:
            html_parts.append(self._html_technologies_categorized(all_techs))
        
        # Detailed Findings
        html_parts.append(self._html_findings_table(results))
        
        # Footer
        html_parts.append(self._html_footer())
        
        return "\n".join(html_parts)
    
    def generate_pdf(self, results: List[ScanResult], 
                     target_name: Optional[str] = None) -> bytes:
        """
        Generate PDF report with enhanced technology section.
        
        Args:
            results: List of ScanResults
            target_name: Optional target name for title
            
        Returns:
            PDF bytes
        """
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            # Fallback: return HTML as PDF-compatible format
            html_content = self.generate_html(results)
            return html_content.encode('utf-8')
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.5*inch,
            leftMargin=0.5*inch,
            topMargin=0.5*inch,
            bottomMargin=0.5*inch,
        )
        
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1a1a2e'),
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#16213e'),
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontSize=11,
            spaceAfter=8,
            spaceBefore=12,
            textColor=colors.HexColor('#0f3460'),
        )
        
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=6,
        )
        
        small_style = ParagraphStyle(
            'SmallText',
            parent=styles['Normal'],
            fontSize=8,
            spaceAfter=4,
        )
        
        elements = []
        summary = self._generate_summary(results)
        
        # Title
        title = "WebVulnPro Security Assessment Report"
        elements.append(Paragraph(title, title_style))
        
        if target_name:
            elements.append(Paragraph(f"Target: {target_name}", styles['Normal']))
        
        elements.append(Paragraph(
            f"Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            styles['Normal']
        ))
        elements.append(Spacer(1, 20))
        
        # Executive Summary
        elements.append(Paragraph("Executive Summary", heading_style))
        
        summary_data = [
            ["Targets Scanned", str(summary['targets_scanned'])],
            ["Total Vulnerabilities", str(summary['total_vulnerabilities'])],
            ["Critical", str(summary['by_severity'].get('CRITICAL', 0))],
            ["High", str(summary['by_severity'].get('HIGH', 0))],
            ["Medium", str(summary['by_severity'].get('MEDIUM', 0))],
            ["Low", str(summary['by_severity'].get('LOW', 0))],
            ["Informational", str(summary['by_severity'].get('INFO', 0))],
            ["Overall Risk Score", f"{summary['risk_score']}/100"],
        ]
        
        summary_table = Table(summary_data, colWidths=[2.5*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))
        
        # Technologies Detected Section (Enhanced)
        all_techs = []
        for result in results:
            all_techs.extend(result.technologies)
        
        if all_techs:
            elements.append(Paragraph("Technologies Detected", heading_style))
            
            # Group technologies by category
            grouped = self._group_technologies(all_techs)
            
            for category, techs in grouped.items():
                # Category header with icon
                icon = self.CATEGORY_ICONS.get(category, "📦")
                elements.append(Paragraph(f"{icon} {category}", subheading_style))
                
                # Create technology table for this category
                tech_data = [["Technology", "Version", "Confidence"]]
                for tech in techs:
                    version = tech.version if tech.version else "-"
                    confidence = f"{int(tech.confidence * 100)}%"
                    tech_data.append([tech.name, version, confidence])
                
                tech_table = Table(tech_data, colWidths=[3*inch, 1.5*inch, 1*inch])
                tech_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e9ecef')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
                ]))
                elements.append(tech_table)
                elements.append(Spacer(1, 10))
            
            elements.append(Spacer(1, 10))
        
        # Severity color mapping for PDF
        severity_colors = {
            'CRITICAL': colors.HexColor('#dc3545'),
            'HIGH': colors.HexColor('#fd7e14'),
            'MEDIUM': colors.HexColor('#ffc107'),
            'LOW': colors.HexColor('#17a2b8'),
            'INFO': colors.HexColor('#28a745'),
        }
        
        # Findings by target
        for result in results:
            if not result.vulnerabilities:
                continue
                
            elements.append(Paragraph(f"Target: {result.target}", heading_style))
            
            if result.error:
                elements.append(Paragraph(f"Error: {result.error}", body_style))
                continue
            
            # Findings table
            findings_data = [["Severity", "Title", "CVSS", "Category"]]
            
            for vuln in result.vulnerabilities:
                sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
                findings_data.append([
                    sev,
                    vuln.title[:50] + "..." if len(vuln.title) > 50 else vuln.title,
                    str(vuln.cvss_score),
                    vuln.category,
                ])
            
            if len(findings_data) > 1:
                findings_table = Table(
                    findings_data,
                    colWidths=[0.8*inch, 3.5*inch, 0.6*inch, 1.5*inch]
                )
                
                table_style = [
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#343a40')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]
                
                # Color-code severity cells
                for i, row in enumerate(findings_data[1:], 1):
                    sev = row[0]
                    if sev in severity_colors:
                        table_style.append(
                            ('TEXTCOLOR', (0, i), (0, i), severity_colors[sev])
                        )
                
                findings_table.setStyle(TableStyle(table_style))
                elements.append(findings_table)
            
            elements.append(Spacer(1, 15))
        
        # Detailed Findings
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Findings", heading_style))
        
        for result in results:
            for vuln in result.vulnerabilities:
                sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
                
                # Finding header
                elements.append(Paragraph(
                    f"<b>[{sev}]</b> {html.escape(vuln.title)}",
                    body_style
                ))
                
                elements.append(Paragraph(
                    f"<b>CVSS Score:</b> {vuln.cvss_score} | "
                    f"<b>Category:</b> {vuln.category}"
                    + (f" | <b>CWE:</b> {vuln.cwe_id}" if vuln.cwe_id else ""),
                    body_style
                ))
                
                elements.append(Paragraph(
                    f"<b>Description:</b> {html.escape(vuln.description)}",
                    body_style
                ))
                
                elements.append(Paragraph(
                    f"<b>Remediation:</b> {html.escape(vuln.remediation)}",
                    body_style
                ))
                
                elements.append(Paragraph(
                    f"<b>Evidence:</b> {html.escape(vuln.evidence[:200])}",
                    body_style
                ))
                
                elements.append(Spacer(1, 10))
        
        # Build PDF
        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        return pdf_bytes
    
    def _group_technologies(self, techs: List[TechnologyFingerprint]) -> Dict[str, List[TechnologyFingerprint]]:
        """Group technologies by category"""
        grouped: Dict[str, List[TechnologyFingerprint]] = {}
        seen: Dict[str, TechnologyFingerprint] = {}
        
        # Deduplicate and keep highest confidence
        for tech in techs:
            if tech.name not in seen or tech.confidence > seen[tech.name].confidence:
                seen[tech.name] = tech
        
        # Group by category
        for tech in seen.values():
            category = tech.category if tech.category else "Unknown"
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(tech)
        
        # Sort technologies within each category by confidence
        for category in grouped:
            grouped[category].sort(key=lambda t: t.confidence, reverse=True)
        
        # Define category order
        category_order = [
            "CMS", "E-commerce", "Framework", "JavaScript Framework", 
            "JavaScript Library", "UI Framework", "Programming Language",
            "Web Server", "Operating System", "Database", "Cache",
            "CDN", "WAF", "Security", "Hosting", "PaaS",
            "Analytics", "Tag Manager", "Font", "Payment", "SEO",
            "Live Chat", "Comment", "Video", "Search", "Build Tool",
            "Static Site Generator", "Miscellaneous", "Unknown"
        ]
        
        # Return in ordered format
        ordered: Dict[str, List[TechnologyFingerprint]] = {}
        for cat in category_order:
            if cat in grouped:
                ordered[cat] = grouped[cat]
        
        # Add any remaining categories
        for cat in grouped:
            if cat not in ordered:
                ordered[cat] = grouped[cat]
        
        return ordered
    
    def _generate_summary(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Generate summary statistics"""
        total_vulns = 0
        by_severity = {s.value: 0 for s in Severity}
        by_category = {}
        all_techs = []
        total_risk = 0
        
        for result in results:
            total_risk += result.risk_score
            for vuln in result.vulnerabilities:
                total_vulns += 1
                sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
                by_severity[sev] = by_severity.get(sev, 0) + 1
                by_category[vuln.category] = by_category.get(vuln.category, 0) + 1
            all_techs.extend(result.technologies)
        
        avg_risk = total_risk // len(results) if results else 0
        
        # Group technologies by category for summary
        tech_by_category: Dict[str, List[str]] = {}
        for tech in all_techs:
            cat = tech.category if tech.category else "Unknown"
            if cat not in tech_by_category:
                tech_by_category[cat] = []
            display_name = tech.display_name if hasattr(tech, 'display_name') else (
                f"{tech.name} {tech.version}" if tech.version else tech.name
            )
            if display_name not in tech_by_category[cat]:
                tech_by_category[cat].append(display_name)
        
        return {
            "targets_scanned": len(results),
            "total_vulnerabilities": total_vulns,
            "by_severity": by_severity,
            "by_category": by_category,
            "risk_score": avg_risk,
            "technologies": list(set(t.name for t in all_techs)),
            "technologies_by_category": tech_by_category,
            "generated_at": self.generated_at.isoformat(),
        }
    
    def _html_header(self) -> str:
        """Generate HTML header with styles"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebVulnPro Security Assessment Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f4f4f9;
            color: #1a1a2e;
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        h1 { color: #1a1a2e; margin-bottom: 10px; }
        h2 { color: #16213e; margin-bottom: 15px; border-bottom: 2px solid #e94560; padding-bottom: 10px; }
        h3 { color: #0f3460; margin: 15px 0 10px; font-size: 1.1em; }
        .header { text-align: center; padding: 30px 0; }
        .header p { color: #666; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card.critical { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }
        .stat-card.high { background: linear-gradient(135deg, #fd7e14 0%, #e8650a 100%); }
        .stat-card.medium { background: linear-gradient(135deg, #ffc107 0%, #d4a106 100%); color: #333; }
        .stat-card.low { background: linear-gradient(135deg, #17a2b8 0%, #117a8b 100%); }
        .stat-card.info { background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%); }
        .stat-card .number { font-size: 2.5em; font-weight: bold; }
        .stat-card .label { font-size: 0.9em; opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #343a40; color: white; }
        tr:hover { background: #f5f5f5; }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        .severity-CRITICAL { background: #dc3545; }
        .severity-HIGH { background: #fd7e14; }
        .severity-MEDIUM { background: #ffc107; color: #333; }
        .severity-LOW { background: #17a2b8; }
        .severity-INFO { background: #28a745; }
        
        /* Technology Styles */
        .tech-category {
            margin-bottom: 20px;
        }
        .tech-category-header {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 15px;
            background: #f8f9fa;
            border-radius: 6px;
            margin-bottom: 10px;
            cursor: pointer;
        }
        .tech-category-header:hover {
            background: #e9ecef;
        }
        .tech-category-icon {
            font-size: 1.2em;
        }
        .tech-category-name {
            font-weight: 600;
            color: #333;
        }
        .tech-category-count {
            background: #6c757d;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            margin-left: auto;
        }
        .tech-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            padding: 0 10px;
        }
        .tech-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: #e9ecef;
            border-radius: 6px;
            font-size: 0.9em;
            border-left: 3px solid #6c757d;
        }
        .tech-badge .tech-name {
            font-weight: 500;
        }
        .tech-badge .tech-version {
            color: #495057;
            font-size: 0.85em;
            background: rgba(0,0,0,0.1);
            padding: 1px 6px;
            border-radius: 3px;
        }
        .tech-badge .tech-confidence {
            font-size: 0.75em;
            color: #6c757d;
        }
        
        /* Category-specific colors */
        .tech-badge.cat-cms { border-left-color: #4CAF50; background: #E8F5E9; }
        .tech-badge.cat-ecommerce { border-left-color: #FF9800; background: #FFF3E0; }
        .tech-badge.cat-framework { border-left-color: #2196F3; background: #E3F2FD; }
        .tech-badge.cat-js-framework { border-left-color: #61DAFB; background: #E1F5FE; }
        .tech-badge.cat-js-library { border-left-color: #F7DF1E; background: #FFFDE7; }
        .tech-badge.cat-language { border-left-color: #9C27B0; background: #F3E5F5; }
        .tech-badge.cat-webserver { border-left-color: #607D8B; background: #ECEFF1; }
        .tech-badge.cat-os { border-left-color: #795548; background: #EFEBE9; }
        .tech-badge.cat-database { border-left-color: #FF5722; background: #FBE9E7; }
        .tech-badge.cat-cache { border-left-color: #00BCD4; background: #E0F7FA; }
        .tech-badge.cat-cdn { border-left-color: #03A9F4; background: #E1F5FE; }
        .tech-badge.cat-waf { border-left-color: #F44336; background: #FFEBEE; }
        .tech-badge.cat-security { border-left-color: #E91E63; background: #FCE4EC; }
        .tech-badge.cat-hosting { border-left-color: #3F51B5; background: #E8EAF6; }
        .tech-badge.cat-analytics { border-left-color: #4CAF50; background: #E8F5E9; }
        .tech-badge.cat-font { border-left-color: #795548; background: #EFEBE9; }
        .tech-badge.cat-payment { border-left-color: #4CAF50; background: #E8F5E9; }
        .tech-badge.cat-seo { border-left-color: #8BC34A; background: #F1F8E9; }
        .tech-badge.cat-ui { border-left-color: #E91E63; background: #FCE4EC; }
        .tech-badge.cat-chat { border-left-color: #4CAF50; background: #E8F5E9; }
        .tech-badge.cat-video { border-left-color: #F44336; background: #FFEBEE; }
        .tech-badge.cat-search { border-left-color: #673AB7; background: #EDE7F6; }
        .tech-badge.cat-build { border-left-color: #607D8B; background: #ECEFF1; }
        
        .finding-card {
            border-left: 4px solid #ccc;
            padding: 15px;
            margin: 10px 0;
            background: #fafafa;
        }
        .finding-card.CRITICAL { border-left-color: #dc3545; }
        .finding-card.HIGH { border-left-color: #fd7e14; }
        .finding-card.MEDIUM { border-left-color: #ffc107; }
        .finding-card.LOW { border-left-color: #17a2b8; }
        .finding-card.INFO { border-left-color: #28a745; }
        .risk-score {
            font-size: 3em;
            font-weight: bold;
            text-align: center;
            padding: 20px;
        }
        .risk-low { color: #28a745; }
        .risk-medium { color: #ffc107; }
        .risk-high { color: #fd7e14; }
        .risk-critical { color: #dc3545; }
        .evidence { 
            background: #f8f9fa; 
            padding: 10px; 
            border-radius: 4px; 
            font-family: monospace; 
            font-size: 0.85em;
            overflow-x: auto;
        }
        footer { text-align: center; padding: 20px; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WebVulnPro Security Assessment Report</h1>
            <p>Generated: ''' + self.generated_at.strftime('%Y-%m-%d %H:%M:%S') + '''</p>
        </div>
'''
    
    def _html_executive_summary(self, summary: Dict[str, Any]) -> str:
        """Generate executive summary section"""
        risk = summary['risk_score']
        risk_class = 'low' if risk < 25 else 'medium' if risk < 50 else 'high' if risk < 75 else 'critical'
        
        return f'''
        <div class="card">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="number">{summary['targets_scanned']}</div>
                    <div class="label">Targets Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="number">{summary['total_vulnerabilities']}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="stat-card critical">
                    <div class="number">{summary['by_severity'].get('CRITICAL', 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="number">{summary['by_severity'].get('HIGH', 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="number">{summary['by_severity'].get('MEDIUM', 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="number">{summary['by_severity'].get('LOW', 0)}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="number">{summary['by_severity'].get('INFO', 0)}</div>
                    <div class="label">Info</div>
                </div>
            </div>
            <div class="risk-score risk-{risk_class}">
                Risk Score: {risk}/100
            </div>
        </div>
'''
    
    def _html_severity_chart(self, summary: Dict[str, Any]) -> str:
        """Generate severity distribution chart"""
        by_cat = summary.get('by_category', {})
        if not by_cat:
            return ""
        
        rows = ""
        for cat, count in sorted(by_cat.items(), key=lambda x: x[1], reverse=True):
            rows += f"<tr><td>{html.escape(cat)}</td><td>{count}</td></tr>"
        
        return f'''
        <div class="card">
            <h2>Findings by Category</h2>
            <table>
                <thead><tr><th>Category</th><th>Count</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
'''
    
    def _html_technologies_categorized(self, techs: List[TechnologyFingerprint]) -> str:
        """Generate categorized technologies section like Wappalyzer"""
        grouped = self._group_technologies(techs)
        
        if not grouped:
            return ""
        
        sections = []
        
        for category, tech_list in grouped.items():
            icon = self.CATEGORY_ICONS.get(category, "📦")
            cat_class = self._get_category_class(category)
            
            tech_badges = ""
            for tech in tech_list:
                version_html = f'<span class="tech-version">{html.escape(tech.version)}</span>' if tech.version else ''
                confidence = int(tech.confidence * 100)
                confidence_html = f'<span class="tech-confidence">{confidence}%</span>' if confidence < 100 else ''
                
                tech_badges += f'''
                    <div class="tech-badge {cat_class}">
                        <span class="tech-name">{html.escape(tech.name)}</span>
                        {version_html}
                        {confidence_html}
                    </div>
                '''
            
            sections.append(f'''
                <div class="tech-category">
                    <div class="tech-category-header">
                        <span class="tech-category-icon">{icon}</span>
                        <span class="tech-category-name">{html.escape(category)}</span>
                        <span class="tech-category-count">{len(tech_list)}</span>
                    </div>
                    <div class="tech-list">
                        {tech_badges}
                    </div>
                </div>
            ''')
        
        return f'''
        <div class="card">
            <h2>Technologies Detected</h2>
            {''.join(sections)}
        </div>
'''
    
    def _get_category_class(self, category: str) -> str:
        """Get CSS class for category"""
        cat_map = {
            "CMS": "cat-cms",
            "E-commerce": "cat-ecommerce",
            "Framework": "cat-framework",
            "JavaScript Framework": "cat-js-framework",
            "JavaScript Library": "cat-js-library",
            "Programming Language": "cat-language",
            "Web Server": "cat-webserver",
            "Operating System": "cat-os",
            "Database": "cat-database",
            "Cache": "cat-cache",
            "CDN": "cat-cdn",
            "WAF": "cat-waf",
            "Security": "cat-security",
            "Hosting": "cat-hosting",
            "PaaS": "cat-hosting",
            "Analytics": "cat-analytics",
            "Tag Manager": "cat-analytics",
            "Font": "cat-font",
            "Payment": "cat-payment",
            "SEO": "cat-seo",
            "UI Framework": "cat-ui",
            "Live Chat": "cat-chat",
            "Comment": "cat-chat",
            "Video": "cat-video",
            "Search": "cat-search",
            "Build Tool": "cat-build",
            "Static Site Generator": "cat-build",
        }
        return cat_map.get(category, "")
    
    def _html_findings_table(self, results: List[ScanResult]) -> str:
        """Generate detailed findings table"""
        sections = []
        
        for result in results:
            if not result.vulnerabilities:
                continue
            
            rows = ""
            for vuln in result.vulnerabilities:
                sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
                cwe = vuln.cwe_id or "N/A"
                
                rows += f'''
                <tr>
                    <td><span class="severity-badge severity-{sev}">{sev}</span></td>
                    <td>{html.escape(vuln.title)}</td>
                    <td>{vuln.cvss_score}</td>
                    <td>{html.escape(vuln.category)}</td>
                    <td>{html.escape(cwe)}</td>
                </tr>
'''
            
            sections.append(f'''
        <div class="card">
            <h2>Target: {html.escape(result.target)}</h2>
            <p>Status: {result.status_code or 'N/A'} | Duration: {result.duration:.2f}s | 
               Findings: {len(result.vulnerabilities)}</p>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>CVSS</th>
                        <th>Category</th>
                        <th>CWE</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
''')
        
        # Detailed findings
        details = ['<div class="card"><h2>Detailed Findings</h2>']
        
        for result in results:
            for vuln in result.vulnerabilities:
                sev = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
                details.append(f'''
                <div class="finding-card {sev}">
                    <h3><span class="severity-badge severity-{sev}">{sev}</span> {html.escape(vuln.title)}</h3>
                    <p><strong>CVSS:</strong> {vuln.cvss_score} | 
                       <strong>Category:</strong> {html.escape(vuln.category)}
                       {f' | <strong>CWE:</strong> {vuln.cwe_id}' if vuln.cwe_id else ''}</p>
                    <p><strong>Description:</strong> {html.escape(vuln.description)}</p>
                    <p><strong>Remediation:</strong> {html.escape(vuln.remediation)}</p>
                    <p><strong>Evidence:</strong></p>
                    <div class="evidence">{html.escape(vuln.evidence[:500])}</div>
                </div>
''')
        
        details.append('</div>')
        
        return "\n".join(sections) + "\n".join(details)
    
    def _html_footer(self) -> str:
        """Generate HTML footer"""
        return '''
        <footer>
            <p>Report generated by WebVulnPro v2.0.0</p>
            <p>This report contains sensitive security information. Handle according to your organization's policies.</p>
        </footer>
    </div>
</body>
</html>
'''
    
    def save_report(self, results: List[ScanResult], output_path: str,
                    target_name: Optional[str] = None) -> str:
        """
        Save report to file in appropriate format.
        
        Args:
            results: List of ScanResults
            output_path: Output file path
            target_name: Optional target name for title
            
        Returns:
            Path to saved file
        """
        path = Path(output_path)
        suffix = path.suffix.lower()
        
        if suffix == '.json':
            content = self.generate_json(results)
            path.write_text(content, encoding='utf-8')
        elif suffix == '.html':
            content = self.generate_html(results)
            path.write_text(content, encoding='utf-8')
        elif suffix == '.pdf':
            content = self.generate_pdf(results, target_name)
            path.write_bytes(content)
        else:
            # Default to JSON
            content = self.generate_json(results)
            path = path.with_suffix('.json')
            path.write_text(content, encoding='utf-8')
        
        return str(path)
