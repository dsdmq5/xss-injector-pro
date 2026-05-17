"""
Report Generator
Generates comprehensive vulnerability reports in HTML, JSON, and PDF formats.
"""

import json
from datetime import datetime
from typing import Dict


class Reporter:
    """Generates vulnerability reports in multiple formats"""

    def __init__(self, results: Dict, config):
        self.results = results
        self.config = config

    def generate_html_report(self, filename: str) -> str:
        """Generate HTML report"""
        output_file = f"{filename}.html"

        html_content = self._generate_html_content()

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return output_file

    def generate_json_report(self, filename: str) -> str:
        """Generate JSON report"""
        output_file = f"{filename}.json"

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)

        return output_file

    def generate_pdf_report(self, filename: str) -> str | None:
        """Generate PDF report (requires weasyprint)"""
        try:
            from weasyprint import HTML

            html_content = self._generate_html_content()
            output_file = f"{filename}.pdf"
            HTML(string=html_content).write_pdf(output_file)

            return output_file
        except ImportError:
            print("[WARNING] WeasyPrint not installed. PDF generation skipped.")
            print("          Install with: pip install weasyprint")
            return None

    def _generate_html_content(self) -> str:
        """Generate HTML report content"""
        vulnerabilities = self.results['vulnerabilities']
        stats = self.results['stats']

        # Severity counts
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Generate vulnerability rows
        vuln_rows = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'Medium')
            severity_class = f"severity-{severity.lower()}"
            confidence = vuln.get('confidence_score', '')
            conf_label = vuln.get('confidence_label', '')
            conf_display = f"{confidence}% ({conf_label})" if confidence else "N/A"

            vuln_rows += f"""
            <tr>
                <td>{i}</td>
                <td><span class="badge {severity_class}">{severity}</span></td>
                <td><code>{vuln['type']}</code></td>
                <td class="url-cell">{self._escape_html(vuln.get('url', 'N/A'))}</td>
                <td><code>{self._escape_html(vuln.get('parameter', 'N/A'))}</code></td>
                <td><code class="payload-cell">{self._escape_html(vuln.get('payload', '')[:100])}</code></td>
                <td>{vuln.get('detection_method', 'N/A')}</td>
                <td>{conf_display}</td>
            </tr>
            """

        if not vuln_rows:
            vuln_rows = '<tr><td colspan="8" class="text-center">No vulnerabilities found</td></tr>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Scan Report - {self._escape_html(self.results['target'])}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6; color: #333; background: #f5f5f5; padding: 20px;
        }}
        .container {{
            max-width: 1400px; margin: 0 auto; background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1); border-radius: 10px; overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 40px; text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ font-size: 1.2em; opacity: 0.9; }}
        .content {{ padding: 40px; }}
        .summary {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px; margin-bottom: 40px;
        }}
        .summary-card {{
            background: #f8f9fa; padding: 20px; border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .summary-card h3 {{ color: #666; font-size: 0.9em; text-transform: uppercase; margin-bottom: 10px; }}
        .summary-card .value {{ font-size: 2em; font-weight: bold; color: #333; }}
        .severity-summary {{ display: flex; gap: 15px; margin-bottom: 30px; flex-wrap: wrap; }}
        .severity-box {{
            padding: 15px 25px; border-radius: 8px; color: white;
            font-weight: bold; flex: 1; min-width: 120px; text-align: center;
        }}
        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #fd7e14; }}
        .severity-medium {{ background: #ffc107; color: #333; }}
        .severity-low {{ background: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: white; }}
        thead {{ background: #667eea; color: white; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ font-weight: 600; text-transform: uppercase; font-size: 0.85em; }}
        tbody tr:hover {{ background: #f8f9fa; }}
        .badge {{
            display: inline-block; padding: 4px 12px; border-radius: 20px;
            font-size: 0.85em; font-weight: bold; text-transform: uppercase;
        }}
        .badge.severity-critical {{ background: #dc3545; color: white; }}
        .badge.severity-high {{ background: #fd7e14; color: white; }}
        .badge.severity-medium {{ background: #ffc107; color: #333; }}
        .badge.severity-low {{ background: #28a745; color: white; }}
        code {{
            background: #f8f9fa; padding: 2px 6px; border-radius: 3px;
            font-family: 'Courier New', monospace; font-size: 0.9em;
        }}
        .url-cell {{ max-width: 300px; word-break: break-all; font-size: 0.9em; }}
        .payload-cell {{ max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }}
        .text-center {{ text-align: center; }}
        .footer {{ background: #f8f9fa; padding: 20px 40px; text-align: center; color: #666; font-size: 0.9em; }}
        .section-title {{ font-size: 1.8em; margin: 30px 0 20px 0; color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        .info-section {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .info-row {{ display: flex; padding: 8px 0; border-bottom: 1px solid #ddd; }}
        .info-row:last-child {{ border-bottom: none; }}
        .info-label {{ font-weight: bold; width: 200px; color: #666; }}
        .info-value {{ flex: 1; }}
        @media print {{ body {{ background: white; padding: 0; }} .container {{ box-shadow: none; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XSS Vulnerability Scan Report</h1>
            <div class="subtitle">Comprehensive Security Assessment</div>
        </div>
        <div class="content">
            <div class="info-section">
                <div class="info-row">
                    <div class="info-label">Target URL:</div>
                    <div class="info-value"><strong>{self._escape_html(self.results['target'])}</strong></div>
                </div>
                <div class="info-row">
                    <div class="info-label">Scan Mode:</div>
                    <div class="info-value">{self.results['scan_mode'].upper()}</div>
                </div>
                <div class="info-row">
                    <div class="info-label">Scan Date:</div>
                    <div class="info-value">{stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')}</div>
                </div>
                <div class="info-row">
                    <div class="info-label">Duration:</div>
                    <div class="info-value">{stats['scan_duration']}</div>
                </div>
                <div class="info-row">
                    <div class="info-label">Payload Level:</div>
                    <div class="info-value">{self.results['config']['payload_level'].title()}</div>
                </div>
            </div>

            <h2 class="section-title">Executive Summary</h2>
            <div class="summary">
                <div class="summary-card">
                    <h3>URLs Scanned</h3>
                    <div class="value">{stats['urls_scanned']}</div>
                </div>
                <div class="summary-card">
                    <h3>Forms Tested</h3>
                    <div class="value">{stats['forms_tested']}</div>
                </div>
                <div class="summary-card">
                    <h3>Parameters Tested</h3>
                    <div class="value">{stats['parameters_tested']}</div>
                </div>
                <div class="summary-card" style="border-left-color: #dc3545;">
                    <h3>Vulnerabilities Found</h3>
                    <div class="value" style="color: #dc3545;">{stats['vulnerabilities_found']}</div>
                </div>
            </div>

            <h2 class="section-title">Vulnerability Breakdown by Severity</h2>
            <div class="severity-summary">
                <div class="severity-box severity-critical">
                    <div>CRITICAL</div>
                    <div style="font-size: 1.5em; margin-top: 5px;">{severity_counts['Critical']}</div>
                </div>
                <div class="severity-box severity-high">
                    <div>HIGH</div>
                    <div style="font-size: 1.5em; margin-top: 5px;">{severity_counts['High']}</div>
                </div>
                <div class="severity-box severity-medium">
                    <div>MEDIUM</div>
                    <div style="font-size: 1.5em; margin-top: 5px;">{severity_counts['Medium']}</div>
                </div>
                <div class="severity-box severity-low">
                    <div>LOW</div>
                    <div style="font-size: 1.5em; margin-top: 5px;">{severity_counts['Low']}</div>
                </div>
            </div>

            <h2 class="section-title">Detailed Vulnerability Report</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>URL</th>
                        <th>Parameter</th>
                        <th>Payload</th>
                        <th>Detection Method</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {vuln_rows}
                </tbody>
            </table>
        </div>
        <div class="footer">
            <p>Generated by XSS Vulnerability Scanner v1.0.0</p>
            <p>Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p style="margin-top: 10px; color: #999;">
                This report contains sensitive security information. Handle with care.
            </p>
        </div>
    </div>
</body>
</html>"""

        return html

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
