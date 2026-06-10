#!/usr/bin/env python3
"""FORENSIX Document Analyzer - AI-powered document classification and analysis."""

import os
import re
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class DocumentAnalyzer:
    """
    AI-Powered Document Analysis for Digital Forensics.
    
    Features:
        - Document type classification
        - Sensitive content detection
        - Financial data extraction
        - Personal information detection (PII)
        - Credit card / SSN pattern detection
        - Email address extraction
        - Phone number extraction
        - Document metadata analysis
    """
    
    # PII detection patterns
    PII_PATTERNS = {
        "credit_card": [
            r'\b(?:\d[ -]*?){13,16}\b',  # Credit card numbers
        ],
        "ssn": [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN format
        ],
        "email": [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        ],
        "phone": [
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            r'\b\(\d{3}\)\s?\d{3}[-.]?\d{4}\b',
        ],
        "ip_address": [
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        ],
        "url": [
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*',
        ],
        "passport": [
            r'\b[A-Z]{1,2}\d{6,8}\b',  # Generic passport format
        ],
        "driving_license": [
            r'\b[A-Z]{1,2}-\d{4,8}\b',  # Generic DL format
        ]
    }
    
    # Financial patterns
    FINANCIAL_PATTERNS = [
        r'\$\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?',
        r'\b(?:invoice|payment|transfer|deposit|withdraw|balance)\b',
        r'\b(?:account|routing)\s*(?:number|#|no)\b',
        r'\bSWIFT:\s*[A-Z0-9]{8,11}\b',
        r'\bIBAN:\s*[A-Z0-9]{15,34}\b',
    ]
    
    # Document categories based on content keywords
    DOCUMENT_CATEGORIES = {
        "financial": [
            "invoice", "receipt", "payment", "tax", "salary", "payroll",
            "bank statement", "account", "transaction", "wire transfer",
            "balance sheet", "income", "expense", "revenue", "profit"
        ],
        "legal": [
            "contract", "agreement", "lawsuit", "attorney", "court",
            "legal", "plaintiff", "defendant", "settlement", "compliance",
            "regulation", "statute", "law", "judge", "verdict"
        ],
        "medical": [
            "patient", "diagnosis", "treatment", "prescription", "doctor",
            "hospital", "medical", "health", "surgery", "medication",
            "clinical", "therapy", "physician", "nurse", "laboratory"
        ],
        "identity": [
            "passport", "driver license", "birth certificate", "social security",
            "identification", "ID card", "citizenship", "visa", "permit"
        ],
        "technical": [
            "source code", "algorithm", "database", "server", "configuration",
            "API", "framework", "repository", "deployment", "backup",
            "log file", "error", "debug", "compile", "version"
        ],
        "corporate": [
            "confidential", "internal", "proprietary", "board meeting",
            "shareholder", "merger", "acquisition", "strategy", "roadmap",
            "quarterly", "annual report", "executive", "stakeholder"
        ]
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.analysis_results: List[Dict] = []
        self.pii_findings: Dict[str, List[Dict]] = defaultdict(list)
    
    def analyze_file(self, filepath: str) -> Optional[Dict]:
        """
        Analyze a single document for forensic artifacts.
        
        Args:
            filepath: Path to document
        
        Returns:
            Analysis result dict
        """
        if not os.path.exists(filepath):
            return None
        
        if not self._is_text_file(filepath):
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not content.strip():
                return None
            
            result = {
                "file": filepath,
                "filename": os.path.basename(filepath),
                "size": os.path.getsize(filepath),
                "lines": content.count('\n'),
                "words": len(content.split()),
                "category": "unknown",
                "pii_detected": [],
                "financial_data": [],
                "sensitive_score": 0,
                "analyzed_at": datetime.now().isoformat()
            }
            
            # Classify document
            result["category"] = self._classify_document(content.lower())
            
            # Detect PII
            pii = self._detect_pii(content)
            result["pii_detected"] = pii
            if pii:
                self.pii_findings[filepath] = pii
            
            # Detect financial data
            financial = self._detect_financial(content)
            result["financial_data"] = financial
            
            # Calculate sensitivity score
            result["sensitive_score"] = self._calculate_sensitivity(result)
            
            return result
            
        except Exception as e:
            self.logger.debug(f"Document analysis error for {filepath}: {e}")
            return None
    
    def analyze_directory(self, directory: str, recursive: bool = True) -> List[Dict]:
        """
        Analyze all documents in a directory.
        
        Args:
            directory: Directory path
            recursive: Scan subdirectories
        
        Returns:
            List of analysis results
        """
        results = []
        
        if not os.path.exists(directory):
            self.logger.error(f"Directory not found: {directory}")
            return results
        
        print(f"\n[*] Analyzing documents in: {directory}")
        count = 0
        pii_count = 0
        
        text_extensions = ['.txt', '.csv', '.log', '.xml', '.json', '.html', 
                          '.md', '.py', '.sh', '.conf', '.cfg', '.ini', '.yaml', '.yml']
        
        try:
            if recursive:
                for dirpath, _, filenames in os.walk(directory):
                    for filename in filenames:
                        if os.path.splitext(filename)[1].lower() in text_extensions:
                            filepath = os.path.join(dirpath, filename)
                            result = self.analyze_file(filepath)
                            if result:
                                results.append(result)
                                count += 1
                                if result.get("pii_detected"):
                                    pii_count += 1
                                
                                if count % 200 == 0:
                                    print(f"  Analyzed {count} documents...")
            else:
                for filename in os.listdir(directory):
                    if os.path.splitext(filename)[1].lower() in text_extensions:
                        filepath = os.path.join(directory, filename)
                        result = self.analyze_file(filepath)
                        if result:
                            results.append(result)
                            count += 1
            
            print(f"\n[+] Analysis complete: {count} documents")
            print(f"    Documents with PII: {pii_count}")
            
        except Exception as e:
            self.logger.error(f"Document analysis failed: {e}")
        
        self.analysis_results = results
        return results
    
    def _is_text_file(self, filepath: str) -> bool:
        """Check if file is likely a text file."""
        text_extensions = ['.txt', '.csv', '.log', '.xml', '.json', '.html',
                          '.md', '.py', '.sh', '.conf', '.cfg', '.ini', '.yaml', '.yml']
        return os.path.splitext(filepath)[1].lower() in text_extensions
    
    def _classify_document(self, content_lower: str) -> str:
        """Classify document based on content keywords."""
        scores = {}
        
        for category, keywords in self.DOCUMENT_CATEGORIES.items():
            score = 0
            for keyword in keywords:
                if keyword in content_lower:
                    score += 1
            scores[category] = score
        
        if scores:
            best_category = max(scores, key=scores.get)
            if scores[best_category] > 0:
                return best_category
        
        return "general"
    
    def _detect_pii(self, content: str) -> List[Dict]:
        """Detect personally identifiable information."""
        findings = []
        
        for pii_type, patterns in self.PII_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches[:10]:  # Limit per type
                    findings.append({
                        "type": pii_type,
                        "value": match[:50],  # Truncate long matches
                        "pattern": pattern
                    })
        
        return findings
    
    def _detect_financial(self, content: str) -> List[str]:
        """Detect financial data patterns."""
        findings = []
        
        for pattern in self.FINANCIAL_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            findings.extend(matches[:5])
        
        return findings[:20]
    
    def _calculate_sensitivity(self, result: Dict) -> int:
        """Calculate document sensitivity score (0-100)."""
        score = 0
        
        # PII points
        pii_types = set(p["type"] for p in result.get("pii_detected", []))
        score += len(pii_types) * 15
        
        # Financial data
        if result.get("financial_data"):
            score += 20
        
        # Category-based scoring
        high_sensitivity_categories = ["financial", "legal", "medical", "identity"]
        if result.get("category") in high_sensitivity_categories:
            score += 20
        
        return min(score, 100)
    
    def get_sensitive_documents(self, min_score: int = 50) -> List[Dict]:
        """Get documents with high sensitivity scores."""
        return [r for r in self.analysis_results if r.get("sensitive_score", 0) >= min_score]
    
    def get_documents_with_pii(self) -> List[Dict]:
        """Get all documents containing PII."""
        return [r for r in self.analysis_results if r.get("pii_detected")]
    
    def search_documents(self, keyword: str) -> List[Dict]:
        """Search analyzed documents by keyword."""
        keyword_lower = keyword.lower()
        results = []
        
        for doc in self.analysis_results:
            if keyword_lower in doc.get("filename", "").lower():
                results.append(doc)
            elif keyword_lower in doc.get("category", "").lower():
                results.append(doc)
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get document analysis statistics."""
        if not self.analysis_results:
            return {"total_documents": 0}
        
        categories = defaultdict(int)
        total_pii = 0
        high_sensitivity = 0
        
        for doc in self.analysis_results:
            categories[doc.get("category", "unknown")] += 1
            if doc.get("pii_detected"):
                total_pii += 1
            if doc.get("sensitive_score", 0) >= 50:
                high_sensitivity += 1
        
        return {
            "total_documents": len(self.analysis_results),
            "documents_with_pii": total_pii,
            "high_sensitivity_docs": high_sensitivity,
            "categories": dict(categories),
            "pii_types_found": {
                pii_type: len(findings)
                for pii_type, findings in self.pii_findings.items()
                if findings
            }
        }
    
    def display_report(self):
        """Display document analysis report."""
        stats = self.get_statistics()
        
        print(f"\n[Document Analysis Report]")
        print(f"{'='*60}")
        print(f"  Total Documents:      {stats['total_documents']}")
        print(f"  With PII:             {stats['documents_with_pii']}")
        print(f"  High Sensitivity:     {stats['high_sensitivity_docs']}")
        
        if stats.get("categories"):
            print(f"\n  Categories:")
            for cat, count in sorted(stats["categories"].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {cat:<20} {count}")
        
        sensitive_docs = self.get_sensitive_documents(70)
        if sensitive_docs:
            print(f"\n  [Highly Sensitive Documents]")
            for doc in sensitive_docs[:10]:
                print(f"    {os.path.basename(doc['file'])}")
                for pii in doc.get("pii_detected", [])[:3]:
                    print(f"      - {pii['type']}: {pii['value'][:30]}")
        
        print(f"{'='*60}\n")
    
    def export_report(self, output_file: str):
        """Export analysis report to JSON."""
        data = {
            "generated_at": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "results": self.analysis_results,
            "pii_findings": {k: v for k, v in self.pii_findings.items()}
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4, default=str)
        
        print(f"[+] Document analysis report exported: {output_file}")
    
    def clear(self):
        """Clear all analysis results."""
        self.analysis_results.clear()
        self.pii_findings.clear()
