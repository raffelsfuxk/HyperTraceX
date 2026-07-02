#!/usr/bin/env python3
"""HyperTraceX Advanced Error Handler - Enhanced error recovery and fault tolerance."""

import os
import sys
import time
import json
import signal
import threading
from datetime import datetime
from typing import Dict, Callable, Any, Optional
from functools import wraps

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class AdvancedErrorHandler:
    """
    Advanced Error Handler with automatic recovery.
    
    Features:
        - Retry mechanism with exponential backoff
        - Circuit breaker pattern
        - Error rate monitoring
        - Automatic fallback strategies
        - Health check system
        - Graceful degradation
        - Resource cleanup
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.error_counts: Dict[str, int] = {}
        self.circuit_breakers: Dict[str, bool] = {}
        self.last_error_time: Dict[str, float] = {}
        self.recovery_handlers: Dict[str, Callable] = {}
        self.max_retries = 3
        self.backoff_factor = 2
        self.circuit_timeout = 60
    
    def retry(self, max_attempts: int = 3, delay: float = 1.0, 
              backoff: float = 2.0, exceptions: tuple = (Exception,)):
        """
        Decorator for retrying functions on failure.
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                last_exception = None
                current_delay = delay
                
                for attempt in range(max_attempts):
                    try:
                        return func(*args, **kwargs)
                    except exceptions as e:
                        last_exception = e
                        self.logger.warning(
                            f"Retry {attempt + 1}/{max_attempts} for {func.__name__}: {e}"
                        )
                        
                        if attempt < max_attempts - 1:
                            time.sleep(current_delay)
                            current_delay *= backoff
                
                self.logger.error(f"All retries failed for {func.__name__}: {last_exception}")
                raise last_exception
            
            return wrapper
        return decorator
    
    def circuit_breaker(self, failure_threshold: int = 5, 
                        recovery_timeout: float = 60.0):
        """
        Decorator implementing Circuit Breaker pattern.
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                func_name = func.__name__
                
                if self.circuit_breakers.get(func_name, False):
                    elapsed = time.time() - self.last_error_time.get(func_name, 0)
                    if elapsed < recovery_timeout:
                        self.logger.warning(f"Circuit OPEN for {func_name}")
                        return None
                    else:
                        self.circuit_breakers[func_name] = False
                        self.logger.info(f"Circuit HALF-OPEN for {func_name}")
                
                try:
                    result = func(*args, **kwargs)
                    self.error_counts[func_name] = 0
                    self.circuit_breakers[func_name] = False
                    return result
                except Exception as e:
                    self.error_counts[func_name] = self.error_counts.get(func_name, 0) + 1
                    self.last_error_time[func_name] = time.time()
                    
                    if self.error_counts[func_name] >= failure_threshold:
                        self.circuit_breakers[func_name] = True
                        self.logger.error(f"Circuit TRIPPED for {func_name}")
                    
                    raise e
            
            return wrapper
        return decorator
    
    def register_fallback(self, primary_func: Callable, fallback_func: Callable):
        """Register fallback handler for function."""
        self.recovery_handlers[primary_func.__name__] = fallback_func
    
    def safe_execute(self, func: Callable, *args, 
                     fallback: Callable = None, 
                     default: Any = None, **kwargs) -> Any:
        """
        Safely execute function with fallback.
        """
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self.logger.error(f"Error in {func.__name__}: {e}")
            
            if fallback:
                try:
                    return fallback(*args, **kwargs)
                except Exception as fe:
                    self.logger.error(f"Fallback also failed: {fe}")
            
            return default
    
    def health_check(self, component: str) -> Dict:
        """
        Perform health check on component.
        """
        checks = {
            "database": self._check_database,
            "filesystem": self._check_filesystem,
            "memory": self._check_memory,
            "network": self._check_network,
            "python_modules": self._check_modules,
        }
        
        if component in checks:
            return checks[component]()
        
        return {"status": "unknown", "component": component}
    
    def _check_database(self) -> Dict:
        try:
            import sqlite3
            conn = sqlite3.connect(":memory:")
            conn.execute("SELECT 1")
            conn.close()
            return {"status": "healthy", "latency_ms": 0}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    def _check_filesystem(self) -> Dict:
        try:
            test_file = "/tmp/tracex_health_check"
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            return {"status": "healthy", "writeable": True}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    def _check_memory(self) -> Dict:
        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            return {
                "status": "healthy",
                "max_rss_mb": round(usage.ru_maxrss / 1024, 2)
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    def _check_network(self) -> Dict:
        try:
            import socket
            socket.gethostbyname("google.com")
            return {"status": "healthy", "dns_ok": True}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    def _check_modules(self) -> Dict:
        required_modules = [
            "scapy", "flask", "sqlite3", "json", "hashlib"
        ]
        missing = []
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing.append(module)
        
        return {
            "status": "healthy" if not missing else "degraded",
            "missing": missing
        }
    
    def health_report(self) -> Dict:
        """Generate full health report."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "components": {},
            "overall_status": "healthy"
        }
        
        for component in ["database", "filesystem", "memory", "network", "python_modules"]:
            report["components"][component] = self.health_check(component)
        
        unhealthy = [k for k, v in report["components"].items() 
                    if v.get("status") != "healthy"]
        
        if unhealthy:
            report["overall_status"] = "degraded" if len(unhealthy) < 3 else "unhealthy"
            report["unhealthy_components"] = unhealthy
        
        return report
    
    def display_health_report(self):
        """Display health check report."""
        report = self.health_report()
        
        print(f"\n[System Health Report]")
        print(f"{'='*50}")
        print(f"  Overall: {report['overall_status'].upper()}")
        
        for component, status in report["components"].items():
            icon = "[OK]" if status["status"] == "healthy" else "[!!]"
            print(f"  {icon} {component}: {status['status']}")
        
        print(f"{'='*50}\n")


class ResourceGuard:
    """Context manager for guaranteed resource cleanup."""
    
    def __init__(self, acquire_func: Callable, release_func: Callable, 
                 logger=None):
        self.acquire = acquire_func
        self.release = release_func
        self.logger = logger or get_logger()
        self.resource = None
    
    def __enter__(self):
        try:
            self.resource = self.acquire()
            return self.resource
        except Exception as e:
            self.logger.error(f"Failed to acquire resource: {e}")
            raise
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if self.resource:
                self.release(self.resource)
        except Exception as e:
            self.logger.error(f"Failed to release resource: {e}")
        
        if exc_type:
            self.logger.error(f"Exception in guarded block: {exc_val}")
        
        return False


class TimeoutGuard:
    """Context manager for timeout enforcement."""
    
    def __init__(self, timeout: float, logger=None):
        self.timeout = timeout
        self.logger = logger or get_logger()
        self.timer = None
    
    def __enter__(self):
        self.timer = threading.Timer(self.timeout, self._timeout_handler)
        self.timer.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.timer:
            self.timer.cancel()
        return False
    
    def _timeout_handler(self):
        self.logger.error(f"Operation timed out after {self.timeout}s")
        raise TimeoutError(f"Operation timed out after {self.timeout}s")
