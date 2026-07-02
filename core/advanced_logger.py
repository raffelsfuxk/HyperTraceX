#!/usr/bin/env python3
"""HyperTraceX Advanced Logger - Enterprise-grade logging with analytics."""

import os
import sys
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict
from logging.handlers import RotatingFileHandler, SysLogHandler

try:
    from core.logger import get_logger, setup_logging
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)
    def setup_logging(*args, **kwargs):
        return get_logger()


class AdvancedLogger:
    """
    Advanced Logging System with Analytics.
    
    Features:
        - Structured JSON logging
        - Log level filtering
        - Performance metrics
        - Log aggregation
        - Real-time log streaming
        - Audit trail compliance
        - Log retention management
    """
    
    def __init__(self, log_dir: str = "./logs", logger=None):
        self.log_dir = log_dir
        self.logger = logger or get_logger()
        self.metrics: Dict[str, List] = defaultdict(list)
        self._start_time = time.time()
        self._lock = threading.Lock()
        
        os.makedirs(log_dir, exist_ok=True)
    
    def log_event(self, event_type: str, message: str, 
                  level: str = "INFO", metadata: Dict = None,
                  case_id: str = "", user: str = "system") -> Dict:
        """Log a structured event."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "level": level,
            "message": message,
            "user": user,
            "case_id": case_id,
            "metadata": metadata or {},
            "uptime_seconds": time.time() - self._start_time
        }
        
        with self._lock:
            self.metrics[event_type].append(event)
            
            log_file = os.path.join(self.log_dir, f"tracex_{datetime.now():%Y%m%d}.jsonl")
            with open(log_file, 'a') as f:
                f.write(json.dumps(event) + '\n')
        
        log_func = {
            "DEBUG": self.logger.debug,
            "INFO": self.logger.info,
            "WARNING": self.logger.warning,
            "ERROR": self.logger.error,
            "CRITICAL": self.logger.critical
        }.get(level, self.logger.info)
        
        log_func(f"[{event_type}] {message}")
        
        return event
    
    def log_performance(self, operation: str, duration_seconds: float,
                        success: bool = True, details: str = ""):
        """Log performance metric."""
        metric = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "duration_seconds": round(duration_seconds, 4),
            "success": success,
            "details": details
        }
        
        with self._lock:
            self.metrics["performance"].append(metric)
        
        if duration_seconds > 10.0:
            self.logger.warning(f"Slow operation: {operation} ({duration_seconds:.2f}s)")
        elif duration_seconds > 60.0:
            self.logger.error(f"Very slow operation: {operation} ({duration_seconds:.2f}s)")
    
    def log_error(self, error: Exception, component: str = "",
                  severity: str = "ERROR", context: Dict = None):
        """Log error with context."""
        error_event = {
            "timestamp": datetime.now().isoformat(),
            "component": component,
            "severity": severity,
            "exception_type": type(error).__name__,
            "message": str(error),
            "context": context or {}
        }
        
        with self._lock:
            self.metrics["errors"].append(error_event)
        
        self.logger.error(f"[{component}] {error}")
        return error_event
    
    def log_audit(self, user: str, action: str, resource: str,
                  result: str = "success", details: str = ""):
        """Log audit trail entry."""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "action": action,
            "resource": resource,
            "result": result,
            "details": details,
            "ip": "127.0.0.1"
        }
        
        with self._lock:
            self.metrics["audit"].append(audit_entry)
            
            audit_file = os.path.join(self.log_dir, "audit.jsonl")
            with open(audit_file, 'a') as f:
                f.write(json.dumps(audit_entry) + '\n')
        
        return audit_entry
    
    def get_metrics_summary(self, hours: int = 24) -> Dict:
        """Get performance metrics summary."""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        perf_data = [
            m for m in self.metrics.get("performance", [])
            if datetime.fromisoformat(m["timestamp"]) > cutoff
        ]
        
        if not perf_data:
            return {"total_operations": 0}
        
        durations = [m["duration_seconds"] for m in perf_data]
        successful = sum(1 for m in perf_data if m["success"])
        
        operations = defaultdict(list)
        for m in perf_data:
            operations[m["operation"]].append(m["duration_seconds"])
        
        slowest = sorted(operations.items(), 
                        key=lambda x: sum(x[1]) / len(x[1]), 
                        reverse=True)
        
        return {
            "total_operations": len(perf_data),
            "success_rate": round(successful / len(perf_data) * 100, 1) if perf_data else 0,
            "avg_duration": round(sum(durations) / len(durations), 4) if durations else 0,
            "max_duration": round(max(durations), 4) if durations else 0,
            "min_duration": round(min(durations), 4) if durations else 0,
            "slowest_operations": [
                {"operation": op, "avg_duration": round(sum(durs)/len(durs), 4)}
                for op, durs in slowest[:5]
            ]
        }
    
    def get_error_summary(self, hours: int = 24) -> Dict:
        """Get error summary."""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        errors = [
            e for e in self.metrics.get("errors", [])
            if datetime.fromisoformat(e["timestamp"]) > cutoff
        ]
        
        by_component = defaultdict(int)
        by_type = defaultdict(int)
        
        for e in errors:
            by_component[e["component"]] += 1
            by_type[e["exception_type"]] += 1
        
        return {
            "total_errors": len(errors),
            "by_component": dict(by_component),
            "by_type": dict(by_type)
        }
    
    def get_audit_summary(self, hours: int = 24) -> Dict:
        """Get audit trail summary."""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        audits = [
            a for a in self.metrics.get("audit", [])
            if datetime.fromisoformat(a["timestamp"]) > cutoff
        ]
        
        by_user = defaultdict(int)
        by_action = defaultdict(int)
        
        for a in audits:
            by_user[a["user"]] += 1
            by_action[a["action"]] += 1
        
        return {
            "total_audit_entries": len(audits),
            "by_user": dict(by_user),
            "by_action": dict(by_action)
        }
    
    def display_dashboard(self):
        """Display logging dashboard."""
        perf = self.get_metrics_summary()
        errors = self.get_error_summary()
        audit = self.get_audit_summary()
        
        print(f"\n[Logging Dashboard]")
        print(f"{'='*55}")
        print(f"  Performance:")
        print(f"    Operations: {perf.get('total_operations', 0)}")
        print(f"    Success:    {perf.get('success_rate', 0)}%")
        print(f"    Avg Time:   {perf.get('avg_duration', 0)}s")
        print(f"    Max Time:   {perf.get('max_duration', 0)}s")
        
        print(f"\n  Errors: {errors.get('total_errors', 0)}")
        if errors.get("by_component"):
            for comp, count in errors["by_component"].items():
                print(f"    {comp}: {count}")
        
        print(f"\n  Audit: {audit.get('total_audit_entries', 0)} entries")
        
        print(f"{'='*55}\n")
    
    def export_logs(self, output_file: str, log_type: str = "all", 
                    hours: int = 24):
        """Export logs to JSON."""
        export = {
            "exported_at": datetime.now().isoformat(),
            "period_hours": hours
        }
        
        if log_type in ["all", "performance"]:
            export["performance"] = self.metrics.get("performance", [])[-1000:]
        if log_type in ["all", "errors"]:
            export["errors"] = self.metrics.get("errors", [])[-500:]
        if log_type in ["all", "audit"]:
            export["audit"] = self.metrics.get("audit", [])[-500:]
        
        with open(output_file, 'w') as f:
            json.dump(export, f, indent=4)
        
        print(f"[+] Logs exported: {output_file}")
    
    def cleanup_old_logs(self, retention_days: int = 30):
        """Delete logs older than retention period."""
        cutoff = datetime.now() - timedelta(days=retention_days)
        deleted = 0
        
        for filename in os.listdir(self.log_dir):
            filepath = os.path.join(self.log_dir, filename)
            if os.path.isfile(filepath):
                file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                if file_time < cutoff:
                    os.remove(filepath)
                    deleted += 1
        
        if deleted:
            self.logger.info(f"Cleaned {deleted} old log files")
