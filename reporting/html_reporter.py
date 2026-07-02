#!/usr/bin/env python3
"""FORENSIX HTML Reporter - Generate professional HTML forensic reports."""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class HTMLReporter:
    """
    Professional HTML Report Generator.
    
    Creates detailed forensic investigation reports
    with embedded evidence, tables, and statistics.
    """
    
    CSS_STYLE = """
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #fff;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            background: #1a1a2e;
            color: #fff;
            padding: 40px;
            text-align: center;
            border-bottom: 4px solid #e94560;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header .subtitle {
            color: #aaa;
            font-size: 1.1em;
        }
        .content {
            padding: 40px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #1a1a2e;
            border-bottom: 3px solid #e94560;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.5em;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .info-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
        }
        .info-card .label {
            color: #666;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .info-card .value {
            color: #1a1a2e;
            font-size: 1.3em;
            font-weight: bold;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th {
            background: #1a1a2e;
            color: #fff;
            padding: 12px 15px;
            text-align: left;
            font-weight: 500;
        }
        td {
            padding: 10px 15px;
            border-bottom: 1px solid #eee;
        }
        tr:hover {
            background: #f8f9fa;
        }
        tr:nth-child(even) {
            background: #fcfcfc;
        }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 500;
        }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .badge-info { background: #d1ecf1; color: #0c5460; }
        .evidence-item {
            background: #f8f9fa;
            border-left: 4px solid #e94560;
            padding: 15px;
            margin: 10px 0;
            border-radius: 0 8px 8px 0;
        }
        .evidence-item .hash {
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #666;
            word-break: break-all;
        }
        .footer {
            background: #1a1a2e;
            color: #aaa;
            padding: 30px;
            text-align: center;
            font-size: 0.9em;
        }
        @media print {
            body { background: #fff; }
            .container { box-shadow: none; }
        }
    </style>
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self._report_data: Dict[str, Any] = {}
    
    def set_case_info(self, case_id: str, investigator: str,
                      organization: str = "", description: str = ""):
        """Set case information."""
        self._report_data["case"] = {
            "case_id": case_id,
            "investigator": investigator,
            "organization": organization,
            "description": description,
            "generated_at": datetime.now().isoformat()
        }
    
    def add_evidence_section(self, evidence: List[Dict]):
        """Add evidence list to report."""
        self._report_data["evidence"] = evidence
    
    def add_analysis_section(self, analysis: Dict):
        """Add analysis results to report."""
        self._report_data["analysis"] = analysis
    
    def add_timeline_section(self, timeline: List[Dict]):
        """Add timeline events to report."""
        self._report_data["timeline"] = timeline
    
    def add_statistics(self, statistics: Dict):
        """Add statistics to report."""
        self._report_data["statistics"] = statistics
    
    def generate(self, output_file: str) -> str:
        """Generate HTML report."""
        html = self._build_html()
        
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        self.logger.info(f"HTML report generated: {output_file}")
        print(f"[+] HTML report: {output_file}")
        return output_file
    
    def _build_html(self) -> str:
        """Build complete HTML document."""
        case = self._report_data.get("case", {})
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Report - {case.get('case_id', 'N/A')}</title>
    {self.CSS_STYLE}
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Digital Forensics Report</h1>
            <p class="subtitle">FORENSIX Platform | Generated: {case.get('generated_at', datetime.now().isoformat())}</p>
        </div>
        <div class="content">
            {self._build_case_section()}
            {self._build_statistics_section()}
            {self._build_evidence_section()}
            {self._build_analysis_section()}
            {self._build_timeline_section()}
        </div>
        <div class="footer">
            <p>Generated by FORENSIX v1.0.0 | Author: raffelsfuxk</p>
            <p>This report is confidential and intended for authorized personnel only.</p>
        </div>
    </div>
</body>
</html>"""
        return html
    
    def _build_case_section(self) -> str:
        case = self._report_data.get("case", {})
        
        return f"""
            <div class="section">
                <h2>Case Information</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <div class="label">Case ID</div>
                        <div class="value">{case.get('case_id', 'N/A')}</div>
                    </div>
                    <div class="info-card">
                        <div class="label">Investigator</div>
                        <div class="value">{case.get('investigator', 'N/A')}</div>
                    </div>
                    <div class="info-card">
                        <div class="label">Organization</div>
                        <div class="value">{case.get('organization', 'N/A')}</div>
                    </div>
                    <div class="info-card">
                        <div class="label">Generated</div>
                        <div class="value">{case.get('generated_at', 'N/A')[:19]}</div>
                    </div>
                </div>
                <p><strong>Description:</strong> {case.get('description', 'No description provided.')}</p>
            </div>"""
    
    def _build_statistics_section(self) -> str:
        stats = self._report_data.get("statistics", {})
        if not stats:
            return ""
        
        rows = ""
        for key, value in stats.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    rows += f"""
                    <tr>
                        <td>{key} - {sub_key}</td>
                        <td>{sub_value}</td>
                    </tr>"""
            else:
                rows += f"""
                <tr>
                    <td>{key}</td>
                    <td>{value}</td>
                </tr>"""
        
        return f"""
            <div class="section">
                <h2>Statistics</h2>
                <table>
                    <tr><th>Metric</th><th>Value</th></tr>
                    {rows}
                </table>
            </div>"""
    
    def _build_evidence_section(self) -> str:
        evidence = self._report_data.get("evidence", [])
        if not evidence:
            return ""
        
        items = ""
        for i, ev in enumerate(evidence[:50]):
            if isinstance(ev, dict):
                name = ev.get('file_path', ev.get('file', f'Item {i+1}'))
                size = ev.get('size', ev.get('file_size', 'N/A'))
                sha256 = ev.get('sha256', ev.get('sha256_hash', 'N/A'))
                
                items += f"""
                <div class="evidence-item">
                    <strong>{os.path.basename(str(name))}</strong><br>
                    <span>Path: {name}</span><br>
                    <span>Size: {size} bytes</span><br>
                    <span class="hash">SHA256: {sha256}</span>
                </div>"""
        
        return f"""
            <div class="section">
                <h2>Evidence Items ({len(evidence)} total)</h2>
                {items}
            </div>"""
    
    def _build_analysis_section(self) -> str:
        analysis = self._report_data.get("analysis", {})
        if not analysis:
            return ""
        
        sections = ""
        for key, value in analysis.items():
            if isinstance(value, list):
                rows = ""
                for item in value[:20]:
                    if isinstance(item, dict):
                        row_data = " | ".join(f"{k}: {v}" for k, v in list(item.items())[:3])
                        rows += f"<tr><td colspan='2'>{row_data}</td></tr>"
                sections += f"""
                <h3>{key.replace('_', ' ').title()} ({len(value)} items)</h3>
                <table>
                    <tr><th>Details</th></tr>
                    {rows}
                </table>"""
            elif isinstance(value, dict):
                rows = ""
                for k, v in value.items():
                    rows += f"<tr><td>{k}</td><td>{v}</td></tr>"
                sections += f"""
                <h3>{key.replace('_', ' ').title()}</h3>
                <table>
                    <tr><th>Metric</th><th>Value</th></tr>
                    {rows}
                </table>"""
        
        return f"""
            <div class="section">
                <h2>Analysis Results</h2>
                {sections}
            </div>"""
    
    def _build_timeline_section(self) -> str:
        timeline = self._report_data.get("timeline", [])
        if not timeline:
            return ""
        
        rows = ""
        for event in timeline[:30]:
            ts = event.get('timestamp', 'N/A')[:19] if event.get('timestamp') else 'N/A'
            etype = event.get('type', 'N/A')
            desc = event.get('description', event.get('path', 'N/A'))
            
            badge_class = "badge-info"
            if "MODIFIED" in str(etype) or "CREATED" in str(etype):
                badge_class = "badge-warning"
            elif "ACCESS" in str(etype):
                badge_class = "badge-success"
            elif "DELETED" in str(etype):
                badge_class = "badge-danger"
            
            rows += f"""
            <tr>
                <td>{ts}</td>
                <td><span class="badge {badge_class}">{etype}</span></td>
                <td>{str(desc)[:80]}</td>
            </tr>"""
        
        return f"""
            <div class="section">
                <h2>Timeline ({len(timeline)} events)</h2>
                <table>
                    <tr><th>Timestamp</th><th>Type</th><th>Description</th></tr>
                    {rows}
                </table>
            </div>"""
