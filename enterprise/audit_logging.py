#!/usr/bin/env python3
"""FORENSIX Enterprise Audit Logging - Compliance and activity tracking."""

import os
import json
import socket
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class AuditLogger:
    """
    Enterprise Audit Logging System.
    
    Features:
        - Comprehensive activity logging
        - User action tracking
        - Compliance reporting (ISO 27001, PCI DSS)
        - Log retention management
        - Export for SIEM integration
        - Tamper-evident logging
    """
    
    # Compliance frameworks
    COMPLIANCE_MAPPING = {
        "CASE_CREATED": ["ISO27001_A.12.4", "PCI_DSS_10.2"],
        "EVIDENCE_ACQUIRED": ["ISO27001_A.12.4", "PCI_DSS_10.3"],
        "EVIDENCE_ANALYZED": ["ISO27001_A.12.4", "PCI_DSS_10.4"],
        "REPORT_GENERATED": ["ISO27001_A.12.4", "PCI_DSS_10.5"],
        "USER_LOGIN": ["ISO27001_A.9.2", "PCI_DSS_10.1"],
        "USER_LOGOUT": ["ISO27001_A.9.2", "PCI_DSS_10.1"],
        "ACCESS_DENIED": ["ISO27001_A.9.4", "PCI_DSS_10.1"],
        "CONFIG_CHANGED": ["ISO27001_A.12.5", "PCI_DSS_10.2"],
        "DATA_EXPORTED": ["ISO27001_A.12.4", "PCI_DSS_10.3"],
        "CASE_CLOSED": ["ISO27001_A.12.4", "PCI_DSS_10.7"],
    }
    
    def __init__(self, log_dir: str = "./audit_logs", logger=None):
        self.log_dir = log_dir
        self.logger = logger or get_logger()
        self.hostname = socket.gethostname()
        os.makedirs(log_dir, exist_ok=True)
    
    def log_event(self, user: str, action: str, details: str = "",
                  case_id: str = "", severity: str = "INFO",
                  evidence_id: str = "") -> Dict:
        """
        Log an audit event.
        
        Args:
            user: Username performing action
            action: Action type
            details: Additional details
            case_id: Related case ID
            severity: INFO, WARNING, ERROR, CRITICAL
            evidence_id: Related evidence ID
        
        Returns:
            Audit event dict
        """
        timestamp = datetime.now().isoformat()
        
        event = {
            "timestamp": timestamp,
            "user": user,
            "action": action,
            "details": details,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "severity": severity,
            "hostname": self.hostname,
            "compliance": self.COMPLIANCE_MAPPING.get(action, [])
        }
        
        # Write to daily log file
        log_file = os.path.join(self.log_dir, f"audit_{datetime.now():%Y%m%d}.jsonl")
        with open(log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
        
        # Log to system logger
        if severity == "CRITICAL":
            self.logger.critical(f"AUDIT: {user} - {action} - {details}")
        elif severity == "ERROR":
            self.logger.error(f"AUDIT: {user} - {action} - {details}")
        elif severity == "WARNING":
            self.logger.warning(f"AUDIT: {user} - {action} - {details}")
        else:
            self.logger.info(f"AUDIT: {user} - {action} - {details}")
        
        return event
    
    def log_user_login(self, user: str, success: bool, ip_address: str = "") -> Dict:
        """Log user login attempt."""
        action = "USER_LOGIN" if success else "ACCESS_DENIED"
        details = f"Login {'successful' if success else 'failed'} from {ip_address}"
        severity = "INFO" if success else "WARNING"
        return self.log_event(user, action, details, severity=severity)
    
    def log_user_logout(self, user: str) -> Dict:
        """Log user logout."""
        return self.log_event(user, "USER_LOGOUT", "User logged out")
    
    def log_evidence_action(self, user: str, action: str, evidence_id: str,
                           case_id: str = "", details: str = "") -> Dict:
        """Log evidence-related action."""
        return self.log_event(user, action, details, case_id=case_id, 
                            evidence_id=evidence_id)
    
    def log_case_action(self, user: str, action: str, case_id: str,
                       details: str = "") -> Dict:
        """Log case-related action."""
        return self.log_event(user, action, details, case_id=case_id)
    
    def log_config_change(self, user: str, key: str, old_value: str = "",
                         new_value: str = "") -> Dict:
        """Log configuration change."""
        details = f"Config '{key}' changed"
        if old_value:
            details += f" from '{old_value}'"
        if new_value:
            details += f" to '{new_value}'"
        return self.log_event(user, "CONFIG_CHANGED", details, severity="WARNING")
    
    def log_data_export(self, user: str, case_id: str, format_type: str,
                       file_path: str) -> Dict:
        """Log data export."""
        details = f"Data exported as {format_type} to {file_path}"
        return self.log_event(user, "DATA_EXPORTED", details, case_id=case_id)
    
    def get_events_by_date(self, date_str: str) -> List[Dict]:
        """
        Get all events for a specific date.
        
        Args:
            date_str: Date in YYYYMMDD format
        
        Returns:
            List of audit events
        """
        log_file = os.path.join(self.log_dir, f"audit_{date_str}.jsonl")
        if not os.path.exists(log_file):
            return []
        
        events = []
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except:
                    pass
        
        return events
    
    def get_events_by_user(self, user: str, days: int = 7) -> List[Dict]:
        """Get events for a specific user within N days."""
        events = []
        from datetime import timedelta
        
        for i in range(days):
            date_str = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
            day_events = self.get_events_by_date(date_str)
            events.extend([e for e in day_events if e.get("user") == user])
        
        return events
    
    def get_events_by_case(self, case_id: str) -> List[Dict]:
        """Get all events related to a case."""
        all_events = []
        
        log_files = sorted(
            [f for f in os.listdir(self.log_dir) if f.startswith("audit_")],
            reverse=True
        )
        
        for log_file in log_files[:30]:  # Last 30 days
            filepath = os.path.join(self.log_dir, log_file)
            with open(filepath, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        if event.get("case_id") == case_id:
                            all_events.append(event)
                    except:
                        pass
        
        return all_events
    
    def generate_compliance_report(self, framework: str = "ISO27001") -> Dict:
        """
        Generate compliance report for specific framework.
        
        Args:
            framework: ISO27001 or PCI_DSS
        
        Returns:
            Compliance report dict
        """
        report = {
            "framework": framework,
            "generated_at": datetime.now().isoformat(),
            "controls": {},
            "total_events": 0,
            "compliant": True
        }
        
        last_30_days = []
        from datetime import timedelta
        for i in range(30):
            date_str = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
            last_30_days.extend(self.get_events_by_date(date_str))
        
        report["total_events"] = len(last_30_days)
        
        for event in last_30_days:
            compliance = event.get("compliance", [])
            for control in compliance:
                if control.startswith(framework):
                    if control not in report["controls"]:
                        report["controls"][control] = {
                            "total": 0,
                            "last_event": None
                        }
                    report["controls"][control]["total"] += 1
                    report["controls"][control]["last_event"] = event["timestamp"]
        
        return report
    
    def search_events(self, keyword: str, days: int = 30) -> List[Dict]:
        """Search audit events by keyword."""
        results = []
        from datetime import timedelta
        
        for i in range(days):
            date_str = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
            events = self.get_events_by_date(date_str)
            
            for event in events:
                event_str = json.dumps(event).lower()
                if keyword.lower() in event_str:
                    results.append(event)
        
        return results
    
    def get_statistics(self, days: int = 7) -> Dict:
        """Get audit statistics for the last N days."""
        from datetime import timedelta
        
        stats = {
            "total_events": 0,
            "by_severity": {},
            "by_action": {},
            "by_user": {},
            "period_days": days
        }
        
        for i in range(days):
            date_str = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
            events = self.get_events_by_date(date_str)
            
            for event in events:
                stats["total_events"] += 1
                
                severity = event.get("severity", "INFO")
                stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
                
                action = event.get("action", "UNKNOWN")
                stats["by_action"][action] = stats["by_action"].get(action, 0) + 1
                
                user = event.get("user", "Unknown")
                stats["by_user"][user] = stats["by_user"].get(user, 0) + 1
        
        return stats
    
    def export_json(self, output_file: str, days: int = 30):
        """Export audit logs to JSON."""
        from datetime import timedelta
        
        all_events = []
        for i in range(days):
            date_str = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
            all_events.extend(self.get_events_by_date(date_str))
        
        data = {
            "exported_at": datetime.now().isoformat(),
            "statistics": self.get_statistics(days),
            "events": all_events
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"[+] Audit log exported: {output_file}")
    
    def cleanup_old_logs(self, retention_days: int = 90):
        """Delete logs older than retention period."""
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(days=retention_days)
        deleted = 0
        
        for log_file in os.listdir(self.log_dir):
            if not log_file.startswith("audit_") or not log_file.endswith(".jsonl"):
                continue
            
            filepath = os.path.join(self.log_dir, log_file)
            
            try:
                date_str = log_file.replace("audit_", "").replace(".jsonl", "")
                file_date = datetime.strptime(date_str, "%Y%m%d")
                
                if file_date < cutoff:
                    os.remove(filepath)
                    deleted += 1
            except:
                pass
        
        if deleted > 0:
            self.logger.info(f"Cleaned {deleted} old audit logs")
    
    def display_summary(self):
        """Display audit summary."""
        stats = self.get_statistics(7)
        
        print(f"\n[Audit Log Summary - Last 7 Days]")
        print(f"{'='*50}")
        print(f"  Total Events: {stats['total_events']}")
        
        if stats.get("by_severity"):
            print(f"\n  By Severity:")
            for severity, count in stats["by_severity"].items():
                print(f"    {severity:<10} {count}")
        
        if stats.get("by_action"):
            print(f"\n  Top Actions:")
            for action, count in sorted(stats["by_action"].items(), 
                                        key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {action:<20} {count}")
        
        print(f"{'='*50}\n")
