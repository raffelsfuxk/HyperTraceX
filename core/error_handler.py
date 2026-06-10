#!/usr/bin/env python3
"""FORENSIX Error Handler - Global error management and recovery."""

import sys
import traceback
from datetime import datetime
from typing import Dict, Optional, Callable

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class ErrorHandler:
    """
    Global Error Handler for FORENSIX Framework.
    
    Features:
        - Structured error logging
        - Error severity classification
        - Automatic recovery attempts
        - Error statistics tracking
        - User-friendly error messages
    """
    
    ERROR_SEVERITY = {
        "CRITICAL": 5,
        "ERROR": 4,
        "WARNING": 3,
        "INFO": 2,
        "DEBUG": 1
    }
    
    ERROR_CODES = {
        "E001": {"message": "Root privileges required", "severity": "CRITICAL", "solution": "Run with: sudo forensix"},
        "E002": {"message": "Missing dependency", "severity": "CRITICAL", "solution": "Run: sudo bash install.sh"},
        "E003": {"message": "Source path not found", "severity": "ERROR", "solution": "Verify the source path exists"},
        "E004": {"message": "Destination not writable", "severity": "ERROR", "solution": "Check permissions on output directory"},
        "E005": {"message": "Hash mismatch detected", "severity": "ERROR", "solution": "Evidence may be compromised. Re-acquire."},
        "E006": {"message": "Mount operation failed", "severity": "ERROR", "solution": "Check filesystem type and permissions"},
        "E007": {"message": "Python module missing", "severity": "ERROR", "solution": "Run: pip install -r requirements.txt"},
        "E008": {"message": "Database locked", "severity": "WARNING", "solution": "Close other FORENSIX instances"},
        "E009": {"message": "Plugin load failed", "severity": "WARNING", "solution": "Check plugin syntax and dependencies"},
        "E010": {"message": "API server error", "severity": "ERROR", "solution": "Check port availability"},
        "E011": {"message": "Memory allocation failed", "severity": "CRITICAL", "solution": "Free memory or reduce batch size"},
        "E012": {"message": "Network timeout", "severity": "WARNING", "solution": "Check network connectivity"},
        "E013": {"message": "File too large", "severity": "WARNING", "solution": "Increase max file size limit or split file"},
        "E014": {"message": "Invalid file format", "severity": "ERROR", "solution": "Verify file format is supported"},
        "E015": {"message": "Permission denied", "severity": "ERROR", "solution": "Check file/directory permissions"},
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.error_stats: Dict[str, int] = {}
        self.error_history: list = []
        self.max_history = 100
        self._recovery_handlers: Dict[str, Callable] = {}
    
    def register_recovery(self, error_code: str, handler: Callable):
        """Register a recovery handler for specific error code."""
        self._recovery_handlers[error_code] = handler
    
    def handle_error(self, error: Exception, error_code: str = "E000",
                     context: Dict = None, recover: bool = True) -> Dict:
        """
        Handle an error with logging and optional recovery.
        
        Args:
            error: The exception object
            error_code: Error code from ERROR_CODES
            context: Additional context information
            recover: Attempt automatic recovery
        
        Returns:
            Error information dict
        """
        error_info = self.ERROR_CODES.get(error_code, {
            "message": str(error),
            "severity": "ERROR",
            "solution": "Check logs for details"
        })
        
        severity = error_info.get("severity", "ERROR")
        message = error_info.get("message", str(error))
        solution = error_info.get("solution", "")
        
        # Build error record
        record = {
            "error_code": error_code,
            "message": message,
            "severity": severity,
            "solution": solution,
            "exception": str(error),
            "exception_type": type(error).__name__,
            "traceback": traceback.format_exc(),
            "timestamp": datetime.now().isoformat(),
            "context": context or {}
        }
        
        # Log based on severity
        if severity == "CRITICAL":
            self.logger.critical(f"[{error_code}] {message}: {error}")
        elif severity == "ERROR":
            self.logger.error(f"[{error_code}] {message}: {error}")
        elif severity == "WARNING":
            self.logger.warning(f"[{error_code}] {message}: {error}")
        else:
            self.logger.info(f"[{error_code}] {message}: {error}")
        
        # Track statistics
        self.error_stats[error_code] = self.error_stats.get(error_code, 0) + 1
        
        # Store in history
        self.error_history.append(record)
        if len(self.error_history) > self.max_history:
            self.error_history.pop(0)
        
        # Attempt recovery
        if recover and error_code in self._recovery_handlers:
            try:
                self.logger.info(f"Attempting recovery for {error_code}...")
                self._recovery_handlers[error_code](context)
                record["recovered"] = True
            except Exception as e:
                self.logger.error(f"Recovery failed: {e}")
                record["recovered"] = False
        
        return record
    
    def get_error_summary(self) -> Dict:
        """Get error statistics summary."""
        total_errors = sum(self.error_stats.values())
        
        severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
        for code, count in self.error_stats.items():
            severity = self.ERROR_CODES.get(code, {}).get("severity", "ERROR")
            severity_counts[severity] = severity_counts.get(severity, 0) + count
        
        return {
            "total_errors": total_errors,
            "by_code": dict(self.error_stats),
            "by_severity": severity_counts,
            "recent_errors": self.error_history[-5:]
        }
    
    def display_error_report(self):
        """Display error summary report."""
        summary = self.get_error_summary()
        
        print(f"\n[Error Report]")
        print(f"{'='*60}")
        print(f"  Total Errors: {summary['total_errors']}")
        
        if summary["by_severity"]:
            print(f"\n  By Severity:")
            for sev, count in summary["by_severity"].items():
                if count > 0:
                    print(f"    {sev:<12} {count}")
        
        if summary["by_code"]:
            print(f"\n  By Error Code:")
            for code, count in sorted(summary["by_code"].items()):
                msg = self.ERROR_CODES.get(code, {}).get("message", "Unknown")[:40]
                print(f"    {code}: {count}x - {msg}")
        
        if summary["recent_errors"]:
            print(f"\n  Recent Errors:")
            for err in summary["recent_errors"][-3:]:
                print(f"    [{err['timestamp'][:19]}] {err['error_code']}: {err['message'][:50]}")
        
        print(f"{'='*60}\n")
    
    def clear_history(self):
        """Clear error history."""
        self.error_history.clear()
        self.error_stats.clear()
        self.logger.info("Error history cleared")


def safe_execute(func: Callable, error_code: str = "E000", 
                 default_return=None, **kwargs):
    """
    Safely execute a function with error handling.
    
    Args:
        func: Function to execute
        error_code: Error code for failures
        default_return: Default return value on error
        **kwargs: Arguments passed to the function
    
    Returns:
        Function result or default_return
    """
    handler = ErrorHandler()
    
    try:
        return func(**kwargs)
    except Exception as e:
        handler.handle_error(e, error_code, context={"function": func.__name__, "args": kwargs})
        return default_return


def validate_path(path: str, must_exist: bool = True, 
                  must_be_file: bool = False, must_be_dir: bool = False) -> bool:
    """Validate a file system path."""
    if must_exist and not os.path.exists(path):
        return False
    if must_be_file and not os.path.isfile(path):
        return False
    if must_be_dir and not os.path.isdir(path):
        return False
    return True


def validate_hash(hash_value: str, algorithm: str = "sha256") -> bool:
    """Validate hash format."""
    hash_lengths = {
        "md5": 32,
        "sha1": 40,
        "sha256": 64,
        "sha512": 128
    }
    expected_length = hash_lengths.get(algorithm, 0)
    if expected_length == 0:
        return False
    return len(hash_value) == expected_length and all(c in "0123456789abcdefABCDEF" for c in hash_value)
