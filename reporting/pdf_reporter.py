#!/usr/bin/env python3
"""HyperTraceX PDF Reporter - Generate professional PDF forensic reports."""

import os
from datetime import datetime
from typing import Dict, List, Optional, Any

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False


class PDFReporter:
    """
    Professional PDF Report Generator.
    
    Creates court-ready forensic reports with:
        - Case information header
        - Evidence tables
        - Chain of custody logs
        - Hash verification records
        - Digital signature blocks
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self._report_data: Dict[str, Any] = {}
        
        if not FPDF_AVAILABLE:
            self.logger.warning("fpdf not installed. Install: pip install fpdf")
    
    def set_case_info(self, case_id: str, investigator: str,
                      organization: str = "", description: str = ""):
        """Set case information for report."""
        self._report_data["case"] = {
            "case_id": case_id,
            "investigator": investigator,
            "organization": organization,
            "description": description,
            "generated_at": datetime.now().isoformat()
        }
    
    def add_evidence(self, evidence: List[Dict]):
        """Add evidence list to report."""
        self._report_data["evidence"] = evidence
    
    def add_custody_log(self, custody_entries: List[Dict]):
        """Add chain of custody entries."""
        self._report_data["custody"] = custody_entries
    
    def add_statistics(self, statistics: Dict):
        """Add statistics to report."""
        self._report_data["statistics"] = statistics
    
    def generate(self, output_file: str) -> Optional[str]:
        """
        Generate PDF report.
        
        Args:
            output_file: Output PDF file path
        
        Returns:
            Path to generated PDF or None
        """
        if not FPDF_AVAILABLE:
            print("[!] fpdf not installed. Install: pip install fpdf")
            return None
        
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # Cover page
        self._add_cover_page(pdf)
        
        # Case information
        self._add_case_section(pdf)
        
        # Evidence section
        self._add_evidence_section(pdf)
        
        # Chain of custody
        self._add_custody_section(pdf)
        
        # Statistics
        self._add_statistics_section(pdf)
        
        # Signature block
        self._add_signature_block(pdf)
        
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)
        pdf.output(output_file)
        
        self.logger.info(f"PDF report generated: {output_file}")
        print(f"[+] PDF report: {output_file}")
        return output_file
    
    def _add_cover_page(self, pdf: FPDF):
        """Add cover page."""
        pdf.add_page()
        
        # Title
        pdf.set_font("Helvetica", "B", 28)
        pdf.ln(60)
        pdf.cell(0, 15, "DIGITAL FORENSICS", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 15, "INVESTIGATION REPORT", align="C", new_x="LMARGIN", new_y="NEXT")
        
        pdf.ln(20)
        pdf.set_font("Helvetica", "", 14)
        pdf.cell(0, 10, "HyperTraceX Platform v1.0.0", align="C", new_x="LMARGIN", new_y="NEXT")
        
        case = self._report_data.get("case", {})
        pdf.ln(10)
        pdf.set_font("Helvetica", "", 12)
        pdf.cell(0, 8, f"Case ID: {case.get('case_id', 'N/A')}", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Date: {case.get('generated_at', datetime.now().isoformat())[:19]}", align="C", new_x="LMARGIN", new_y="NEXT")
        
        pdf.ln(30)
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 8, "CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY", align="C", new_x="LMARGIN", new_y="NEXT")
    
    def _add_case_section(self, pdf: FPDF):
        """Add case information section."""
        pdf.add_page()
        
        case = self._report_data.get("case", {})
        
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, "1. CASE INFORMATION", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        pdf.set_draw_color(0, 0, 0)
        pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
        pdf.ln(5)
        
        info_items = [
            ("Case ID", case.get("case_id", "N/A")),
            ("Investigator", case.get("investigator", "N/A")),
            ("Organization", case.get("organization", "N/A")),
            ("Report Generated", case.get("generated_at", "N/A")[:19]),
            ("Description", case.get("description", "No description")),
        ]
        
        pdf.set_font("Helvetica", "", 11)
        for label, value in info_items:
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(50, 8, f"{label}:", new_x="RIGHT", new_y="LAST")
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(0, 8, str(value), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
    
    def _add_evidence_section(self, pdf: FPDF):
        """Add evidence section."""
        evidence = self._report_data.get("evidence", [])
        if not evidence:
            return
        
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, "2. EVIDENCE INVENTORY", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
        pdf.ln(8)
        
        # Table header
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(50, 50, 50)
        pdf.set_text_color(255, 255, 255)
        
        col_widths = [60, 30, 25, 75]
        headers = ["File Name", "Size (bytes)", "Status", "SHA256 Hash"]
        
        for i, (header, width) in enumerate(zip(headers, col_widths)):
            pdf.cell(width, 8, header, border=1, fill=True, 
                    align="C" if i > 0 else "L")
        pdf.ln()
        
        # Table rows
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 8)
        
        for ev in evidence[:30]:
            name = os.path.basename(str(ev.get("file_path", ev.get("file", "N/A"))))[:35]
            size = str(ev.get("size", ev.get("file_size", "N/A")))
            status = "Acquired"
            sha = str(ev.get("sha256", ev.get("sha256_hash", "N/A")))[:40]
            
            if len(evidence) % 2 == 0:
                pdf.set_fill_color(245, 245, 245)
                fill = True
            else:
                fill = False
            
            pdf.cell(col_widths[0], 7, name, border=1, fill=fill)
            pdf.cell(col_widths[1], 7, size, border=1, align="R", fill=fill)
            pdf.cell(col_widths[2], 7, status, border=1, align="C", fill=fill)
            pdf.cell(col_widths[3], 7, sha, border=1, fill=fill)
            pdf.ln()
        
        pdf.ln(5)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, f"Total evidence items: {len(evidence)}", new_x="LMARGIN", new_y="NEXT")
    
    def _add_custody_section(self, pdf: FPDF):
        """Add chain of custody section."""
        custody = self._report_data.get("custody", [])
        if not custody:
            return
        
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, "3. CHAIN OF CUSTODY", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
        pdf.ln(8)
        
        pdf.set_font("Helvetica", "", 10)
        
        for i, entry in enumerate(custody[:20]):
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, f"Entry #{i+1} - {entry.get('action', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 6, f"  Timestamp: {entry.get('timestamp', 'N/A')[:19]}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 6, f"  Handler: {entry.get('handler', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 6, f"  Location: {entry.get('location', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
            if entry.get("notes"):
                pdf.cell(0, 6, f"  Notes: {entry['notes']}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)
    
    def _add_statistics_section(self, pdf: FPDF):
        """Add statistics section."""
        stats = self._report_data.get("statistics", {})
        if not stats:
            return
        
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, "4. INVESTIGATION STATISTICS", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
        pdf.ln(8)
        
        pdf.set_font("Helvetica", "", 11)
        
        for key, value in stats.items():
            if isinstance(value, dict):
                pdf.set_font("Helvetica", "B", 11)
                pdf.cell(0, 8, f"{key}:", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 10)
                for sub_key, sub_value in value.items():
                    pdf.cell(10, 7, "")
                    pdf.cell(0, 7, f"{sub_key}: {sub_value}", new_x="LMARGIN", new_y="NEXT")
            else:
                pdf.set_font("Helvetica", "B", 11)
                pdf.cell(80, 7, f"{key}:", new_x="RIGHT", new_y="LAST")
                pdf.set_font("Helvetica", "", 11)
                pdf.cell(0, 7, str(value), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
    
    def _add_signature_block(self, pdf: FPDF):
        """Add investigator signature block."""
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, "5. INVESTIGATOR CERTIFICATION", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
        pdf.ln(15)
        
        pdf.set_font("Helvetica", "", 11)
        certification_text = (
            "I hereby certify that the information contained in this report "
            "is accurate and complete to the best of my knowledge. The evidence "
            "was collected, preserved, and analyzed following established "
            "forensic procedures and maintaining chain of custody throughout "
            "the investigation."
        )
        
        pdf.multi_cell(0, 7, certification_text)
        
        pdf.ln(20)
        case = self._report_data.get("case", {})
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, f"Investigator: {case.get('investigator', '____________________')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Date: {datetime.now().strftime('%Y-%m-%d')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Organization: {case.get('organization', '____________________')}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.ln(30)
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "Generated by HyperTraceX v1.0.0 - Enterprise Digital Forensics Platform", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, "This report is confidential and intended for authorized recipients only.", align="C", new_x="LMARGIN", new_y="NEXT")
