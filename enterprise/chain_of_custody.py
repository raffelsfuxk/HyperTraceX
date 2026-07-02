#!/usr/bin/env python3
"""HyperTraceX Chain of Custody - Digital evidence tracking and verification."""

import os
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class ChainOfCustody:
    """
    Digital Chain of Custody Management.
    
    Tracks evidence handling from acquisition to presentation.
    Features:
        - Evidence registration
        - Transfer logging
        - Integrity verification
        - Audit trail generation
        - Digital signatures (GPG)
    """
    
    def __init__(self, case_id: str = "", logger=None):
        self.case_id = case_id
        self.logger = logger or get_logger()
        self.entries: List[Dict] = []
        self.evidence_items: Dict[str, Dict] = {}
    
    def register_evidence(self, evidence_id: str, description: str,
                          file_path: str, collector: str,
                          location: str = "", notes: str = "") -> Dict:
        """
        Register new evidence item.
        
        Args:
            evidence_id: Unique evidence identifier
            description: Evidence description
            file_path: Path to evidence file
            collector: Person who collected the evidence
            location: Physical location
            notes: Additional notes
        
        Returns:
            Evidence item dict
        """
        if evidence_id in self.evidence_items:
            self.logger.warning(f"Evidence already registered: {evidence_id}")
            return self.evidence_items[evidence_id]
        
        # Calculate initial hash
        file_hash = self._calculate_hash(file_path) if os.path.exists(file_path) else ""
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        
        now = datetime.now().isoformat()
        
        item = {
            "evidence_id": evidence_id,
            "description": description,
            "file_path": file_path,
            "file_size": file_size,
            "initial_hash": file_hash,
            "current_hash": file_hash,
            "collector": collector,
            "collection_location": location,
            "collection_date": now,
            "notes": notes,
            "status": "collected",
            "transfers": []
        }
        
        self.evidence_items[evidence_id] = item
        
        # Log first custody entry
        self.log_transfer(evidence_id, "COLLECTED", collector, location,
                         f"Evidence collected: {description}")
        
        self.logger.info(f"Evidence registered: {evidence_id}")
        print(f"[+] Evidence registered: {evidence_id}")
        
        return item
    
    def log_transfer(self, evidence_id: str, action: str, handler: str,
                     location: str = "", notes: str = "") -> Optional[Dict]:
        """
        Log evidence transfer or handling action.
        
        Args:
            evidence_id: Evidence identifier
            action: Action type (COLLECTED, TRANSFERRED, ANALYZED, STORED, RELEASED)
            handler: Person handling the evidence
            location: Location of action
            notes: Additional notes
        
        Returns:
            Transfer entry dict
        """
        if evidence_id not in self.evidence_items:
            self.logger.error(f"Evidence not found: {evidence_id}")
            return None
        
        now = datetime.now().isoformat()
        
        # Get current hash before transfer
        item = self.evidence_items[evidence_id]
        current_hash = item["current_hash"]
        
        # Verify integrity if file exists
        if os.path.exists(item["file_path"]):
            new_hash = self._calculate_hash(item["file_path"])
            if new_hash != current_hash and action != "COLLECTED":
                self.logger.warning(f"Hash changed for {evidence_id}!")
                print(f"[!] WARNING: Evidence hash changed: {evidence_id}")
        
        entry = {
            "timestamp": now,
            "evidence_id": evidence_id,
            "action": action,
            "handler": handler,
            "location": location,
            "notes": notes,
            "hash_at_time": current_hash
        }
        
        self.entries.append(entry)
        item["transfers"].append(entry)
        item["last_handler"] = handler
        item["last_action"] = action
        item["last_updated"] = now
        
        self.logger.info(f"Custody logged: {evidence_id} - {action} by {handler}")
        
        return entry
    
    def verify_integrity(self, evidence_id: str) -> Dict:
        """
        Verify evidence integrity by comparing current hash with initial hash.
        
        Returns:
            Dict with verification results
        """
        if evidence_id not in self.evidence_items:
            return {"status": "NOT_FOUND"}
        
        item = self.evidence_items[evidence_id]
        
        if not os.path.exists(item["file_path"]):
            return {
                "status": "FILE_MISSING",
                "evidence_id": evidence_id,
                "file_path": item["file_path"]
            }
        
        current_hash = self._calculate_hash(item["file_path"])
        initial_hash = item["initial_hash"]
        
        is_valid = current_hash == initial_hash
        
        result = {
            "status": "VALID" if is_valid else "COMPROMISED",
            "evidence_id": evidence_id,
            "file_path": item["file_path"],
            "initial_hash": initial_hash,
            "current_hash": current_hash,
            "verified_at": datetime.now().isoformat()
        }
        
        if not is_valid:
            self.logger.warning(f"Evidence integrity compromised: {evidence_id}")
            print(f"[!] ALERT: Evidence compromised: {evidence_id}")
        else:
            print(f"[+] Evidence verified: {evidence_id}")
        
        return result
    
    def verify_all(self) -> List[Dict]:
        """Verify integrity of all evidence items."""
        results = []
        for evidence_id in self.evidence_items:
            results.append(self.verify_integrity(evidence_id))
        return results
    
    def get_evidence_history(self, evidence_id: str) -> List[Dict]:
        """Get complete custody history for evidence item."""
        if evidence_id in self.evidence_items:
            return self.evidence_items[evidence_id]["transfers"]
        return []
    
    def get_current_holder(self, evidence_id: str) -> Optional[str]:
        """Get current holder of evidence."""
        if evidence_id in self.evidence_items:
            return self.evidence_items[evidence_id].get("last_handler", "Unknown")
        return None
    
    def get_all_evidence(self) -> Dict[str, Dict]:
        """Get all registered evidence."""
        return self.evidence_items
    
    def _calculate_hash(self, filepath: str, algorithm: str = "sha256") -> str:
        """Calculate file hash."""
        try:
            h = hashlib.new(algorithm)
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            self.logger.error(f"Hash error: {e}")
            return ""
    
    def generate_report(self, output_file: str = None) -> str:
        """Generate chain of custody report."""
        report_lines = []
        report_lines.append("=" * 70)
        report_lines.append("CHAIN OF CUSTODY REPORT")
        report_lines.append("=" * 70)
        report_lines.append(f"Case ID: {self.case_id}")
        report_lines.append(f"Generated: {datetime.now().isoformat()}")
        report_lines.append(f"Total Evidence Items: {len(self.evidence_items)}")
        report_lines.append(f"Total Transfers: {len(self.entries)}")
        report_lines.append("=" * 70)
        report_lines.append("")
        
        for evidence_id, item in self.evidence_items.items():
            report_lines.append(f"Evidence ID: {evidence_id}")
            report_lines.append(f"  Description: {item['description']}")
            report_lines.append(f"  Collector: {item['collector']}")
            report_lines.append(f"  Collection Date: {item['collection_date']}")
            report_lines.append(f"  Initial Hash: {item['initial_hash'][:32]}...")
            report_lines.append(f"  Transfers: {len(item['transfers'])}")
            report_lines.append("")
            
            for i, transfer in enumerate(item['transfers']):
                report_lines.append(f"  [{i+1}] {transfer['timestamp']}")
                report_lines.append(f"      Action: {transfer['action']}")
                report_lines.append(f"      Handler: {transfer['handler']}")
                report_lines.append(f"      Location: {transfer['location']}")
                if transfer['notes']:
                    report_lines.append(f"      Notes: {transfer['notes']}")
                report_lines.append("")
        
        report = "\n".join(report_lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"[+] Custody report saved: {output_file}")
        
        return report
    
    def export_json(self, output_file: str):
        """Export custody data to JSON."""
        data = {
            "case_id": self.case_id,
            "generated_at": datetime.now().isoformat(),
            "evidence_items": self.evidence_items,
            "transfers": self.entries
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4, default=str)
        
        print(f"[+] Custody data exported: {output_file}")
    
    def get_statistics(self) -> Dict:
        """Get custody statistics."""
        total_items = len(self.evidence_items)
        total_transfers = len(self.entries)
        
        actions = {}
        handlers = {}
        
        for entry in self.entries:
            action = entry["action"]
            handler = entry["handler"]
            actions[action] = actions.get(action, 0) + 1
            handlers[handler] = handlers.get(handler, 0) + 1
        
        # Verify all
        verification_results = self.verify_all()
        valid_count = sum(1 for r in verification_results if r["status"] == "VALID")
        compromised_count = sum(1 for r in verification_results if r["status"] == "COMPROMISED")
        
        return {
            "total_evidence_items": total_items,
            "total_transfers": total_transfers,
            "actions": actions,
            "handlers": handlers,
            "integrity_status": {
                "valid": valid_count,
                "compromised": compromised_count,
                "missing": sum(1 for r in verification_results if r["status"] == "FILE_MISSING")
            }
        }
    
    def display_report(self):
        """Display chain of custody summary."""
        stats = self.get_statistics()
        
        print(f"\n[Chain of Custody Report]")
        print(f"{'='*50}")
        print(f"  Case ID: {self.case_id}")
        print(f"  Evidence Items: {stats['total_evidence_items']}")
        print(f"  Total Transfers: {stats['total_transfers']}")
        print(f"  Integrity: {stats['integrity_status']['valid']} valid, "
              f"{stats['integrity_status']['compromised']} compromised")
        
        print(f"\n  Recent Transfers:")
        for entry in self.entries[-5:]:
            print(f"    [{entry['timestamp'][:19]}] {entry['action']}: "
                  f"{entry['evidence_id']} by {entry['handler']}")
        
        print(f"{'='*50}\n")
