#!/usr/bin/env python3
"""
FORENSIX Core Engine
Enterprise Digital Forensics Platform
Version: 1.0.0
"""

import os
import sys
import time
import json
import signal
import hashlib
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from core.database import DatabaseManager
from core.config import ConfigManager
from core.logger import setup_logging, get_logger

__version__ = "1.0.0"
__author__ = "CR0WNNE0_fuxv>#SUDOIT"

class ForensixEngine:
    """
    FORENSIX Core Acquisition & Analysis Engine.
    
    Features:
        - Multi-threaded evidence acquisition
        - Chain of custody tracking
        - Hash verification (MD5, SHA1, SHA256)
        - Case management
        - Plugin system support
        - Audit logging
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config_manager = ConfigManager()
        self.config = self.config_manager.load_default()
        if config:
            self.config.update(config)
        
        self.output_dir = Path(self.config.get("storage", {}).get("output_dir", "./output"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = setup_logging(self.output_dir, self.config.get("logging", {}).get("level", "INFO"))
        self.logger.info(f"FORENSIX Engine v{__version__} initializing")
        
        self.db = DatabaseManager(self.config.get("database", {}).get("path", "forensix.db"))
        
        self.running = False
        self.current_case_id = None
        self.acquisition_tasks: List[Dict] = []
        self._threads: List[threading.Thread] = []
        self._lock = threading.Lock()
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self._display_banner()
        self.logger.info("FORENSIX Engine initialized")
    
    def _display_banner(self):
        banner = f"""
    ╔══════════════════════════════════════════════════════════╗
    ║     FORENSIX - Enterprise Digital Forensics Platform     ║
    ║     Version {__version__}  |  Ethical Use Only                 ║
    ╚══════════════════════════════════════════════════════════╝
    """
        print(banner)
    
    def _signal_handler(self, sig, frame):
        print("\n[!] Interrupt received. Cleaning up...")
        self.running = False
        self.shutdown()
    
    def check_root(self) -> bool:
        if os.geteuid() != 0:
            self.logger.critical("Root privileges required")
            print("[ERROR] Root privileges required! Run with: sudo python3 forensix.py")
            sys.exit(1)
        return True
    
    def check_dependencies(self) -> bool:
        required_tools = ["dd", "mount", "lsblk", "md5sum", "sha1sum", "sha256sum"]
        missing = []
        for tool in required_tools:
            if subprocess.run(["which", tool], capture_output=True).returncode != 0:
                missing.append(tool)
        
        if missing:
            print(f"[!] Missing tools: {', '.join(missing)}")
            return False
        return True
    
    # Case Management
    def create_case(self, case_id: str, investigator: str,
                    organization: str = "", description: str = "") -> int:
        self.logger.info(f"Creating case: {case_id}")
        case_pk = self.db.create_case(case_id, investigator, organization, description)
        self.current_case_id = case_pk
        
        case_dir = self.output_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        
        self.db.log_audit(case_pk, "CASE_CREATED", investigator, f"Case {case_id} created")
        
        print(f"\n[+] Case created: {case_id}")
        print(f"    Investigator: {investigator}")
        print(f"    Directory: {case_dir}")
        return case_pk
    
    def close_case(self, case_id: str = None):
        cid = case_id or self.current_case_id
        if cid:
            self.db.close_case(cid)
            self.db.log_audit(cid, "CASE_CLOSED", "investigator", f"Case closed")
            print(f"[+] Case closed")
    
    # Hash Functions
    def calculate_hash(self, filepath: str, algorithm: str = "sha256") -> Optional[str]:
        try:
            h = hashlib.new(algorithm)
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            self.logger.error(f"Hash calculation failed: {e}")
            return None
    
    def verify_file_integrity(self, filepath: str, expected_hash: str, algorithm: str = "sha256") -> bool:
        actual = self.calculate_hash(filepath, algorithm)
        if actual and actual == expected_hash:
            self.logger.info(f"Hash verified: {filepath}")
            return True
        self.logger.warning(f"Hash mismatch: {filepath}")
        return False
    
    # Evidence Acquisition
    def acquire_file(self, source: str, destination: str, 
                     preserve_metadata: bool = True) -> Optional[Dict]:
        try:
            if not os.path.exists(source):
                self.logger.error(f"Source not found: {source}")
                return None
            
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            
            if preserve_metadata:
                import shutil
                shutil.copy2(source, destination)
            else:
                import shutil
                shutil.copyfile(source, destination)
            
            file_size = os.path.getsize(destination)
            md5_hash = self.calculate_hash(destination, "md5")
            sha1_hash = self.calculate_hash(destination, "sha1")
            sha256_hash = self.calculate_hash(destination, "sha256")
            
            return {
                "source": source,
                "destination": destination,
                "size": file_size,
                "md5": md5_hash,
                "sha1": sha1_hash,
                "sha256": sha256_hash,
                "acquired_at": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Acquisition failed: {e}")
            return None
    
    def acquire_directory(self, source_dir: str, dest_dir: str,
                          extensions: List[str] = None,
                          max_size_gb: float = 4) -> List[Dict]:
        results = []
        max_size_bytes = max_size_gb * 1024 * 1024 * 1024
        total_size = 0
        
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                if extensions:
                    ext = file.split('.')[-1].lower() if '.' in file else ''
                    if ext not in extensions:
                        continue
                
                src_path = os.path.join(root, file)
                rel_path = os.path.relpath(src_path, source_dir)
                dst_path = os.path.join(dest_dir, rel_path)
                
                file_size = os.path.getsize(src_path)
                if total_size + file_size > max_size_bytes:
                    self.logger.warning("Max size limit reached")
                    break
                
                result = self.acquire_file(src_path, dst_path)
                if result:
                    results.append(result)
                    total_size += file_size
                    
                    if self.current_case_id:
                        self.db.add_evidence(
                            self.current_case_id, dst_path, src_path,
                            file_size, result["md5"], result["sha1"], result["sha256"]
                        )
        
        return results
    
    # Drive Detection
    def scan_drives(self) -> List[Dict]:
        drives = []
        try:
            output = subprocess.check_output(
                "lsblk -lno NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE", 
                shell=True
            ).decode()
            
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "part":
                    drives.append({
                        "device": f"/dev/{parts[0]}",
                        "size": parts[1],
                        "mountpoint": parts[3] if len(parts) > 3 else "",
                        "filesystem": parts[4] if len(parts) > 4 else "unknown"
                    })
        except Exception as e:
            self.logger.error(f"Drive scan failed: {e}")
        
        return drives
    
    def find_windows_partitions(self) -> List[Dict]:
        all_drives = self.scan_drives()
        return [d for d in all_drives if d.get("filesystem", "").lower() in ["ntfs", "fuseblk"]]
    
    # Chain of Custody
    def log_custody(self, evidence_id: int, action: str, handler: str,
                    location: str = "", notes: str = "") -> int:
        return self.db.add_custody_entry(evidence_id, action, handler, location, notes)
    
    # Reporting
    def generate_case_report(self, case_id: str = None) -> Dict:
        cid = case_id or self.current_case_id
        if not cid:
            return {}
        
        case_info = self.db.get_case(cid)
        evidence = self.db.get_case_evidence(cid)
        stats = self.db.get_case_stats(cid)
        audit = self.db.get_audit_log(cid)
        
        return {
            "case": case_info,
            "evidence": evidence,
            "statistics": stats,
            "audit_log": audit,
            "generated_at": datetime.now().isoformat()
        }
    
    def export_report_json(self, filepath: str, case_id: str = None):
        report = self.generate_case_report(case_id)
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=4, default=str)
        self.logger.info(f"Report exported: {filepath}")
        print(f"[+] Report saved: {filepath}")
    
    def shutdown(self):
        self.logger.info("Shutting down FORENSIX Engine")
        self.running = False
        self.db.close()
        print("[+] Shutdown complete")

    
    # Plugin System
    def load_plugins(self, plugin_dir: str = "./plugins"):
        """Load external plugins."""
        plugin_path = Path(plugin_dir)
        if not plugin_path.is_dir():
            return
        
        import importlib.util
        for file in plugin_path.glob("*.py"):
            if file.stem.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(file.stem, file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, 'register'):
                    module.register(self)
                    self.logger.info(f"Plugin loaded: {file.stem}")
            except Exception as e:
                self.logger.error(f"Plugin load failed: {e}")
    
    # Status & Monitoring
    def get_status(self) -> Dict:
        return {
            "version": __version__,
            "running": self.running,
            "current_case": self.current_case_id,
            "output_dir": str(self.output_dir)
        }
    
    def display_status(self):
        status = self.get_status()
        print(f"\n[FORENSIX Status]")
        print(f"  Version:      {status['version']}")
        print(f"  Case ID:      {status['current_case'] or 'None'}")
        print(f"  Output:       {status['output_dir']}")
        print(f"  Running:      {'Yes' if status['running'] else 'No'}")
        print()

    # Interactive CLI
    def interactive_menu(self):
        """Main interactive menu."""
        menu = f"""
╔══════════════════════════════════════════════════╗
║        FORENSIX Digital Forensics Suite          ║
╠══════════════════════════════════════════════════╣
║  1. Create New Case                             ║
║  2. Scan Drives                                 ║
║  3. Acquire Evidence                            ║
║  4. Verify File Integrity                       ║
║  5. Generate Report                             ║
║  6. Chain of Custody Log                        ║
║  7. View Case Status                            ║
║  8. Load Plugins                                ║
║  0. Exit                                        ║
╚══════════════════════════════════════════════════╝
"""
        print(menu)
        choice = input("Select module: ").strip()
        
        if choice == '1':
            case_id = input("Case ID: ")
            investigator = input("Investigator name: ")
            org = input("Organization (optional): ")
            desc = input("Description (optional): ")
            self.create_case(case_id, investigator, org, desc)
            
        elif choice == '2':
            print("\n[*] Scanning drives...")
            drives = self.scan_drives()
            for d in drives:
                print(f"  {d['device']:<12} {d['size']:<8} {d.get('filesystem', 'N/A'):<10} {d.get('mountpoint', '')}")
            windows = self.find_windows_partitions()
            if windows:
                print(f"\n[+] Windows partitions found: {len(windows)}")
                
        elif choice == '3':
            if not self.current_case_id:
                print("[!] Create a case first!")
                return choice != '0'
            source = input("Source directory: ")
            dest = input("Destination directory: ")
            exts = input("File extensions (comma separated, blank for all): ")
            ext_list = [e.strip() for e in exts.split(',')] if exts else None
            print("[*] Acquiring evidence...")
            results = self.acquire_directory(source, dest, ext_list)
            print(f"[+] Acquired {len(results)} files")
            
        elif choice == '4':
            filepath = input("File path: ")
            expected = input("Expected hash: ")
            algo = input("Algorithm (md5/sha1/sha256) [sha256]: ") or "sha256"
            valid = self.verify_file_integrity(filepath, expected, algo)
            print(f"[+] Integrity check: {'PASSED' if valid else 'FAILED'}")
            
        elif choice == '5':
            filepath = input("Output file path: ")
            self.export_report_json(filepath)
            
        elif choice == '6':
            if not self.current_case_id:
                print("[!] Create a case first!")
                return choice != '0'
            evidence = self.db.get_case_evidence(self.current_case_id)
            for i, ev in enumerate(evidence):
                print(f"  [{i}] {ev['file_path']}")
            idx = int(input("Evidence index: "))
            if idx < len(evidence):
                action = input("Action (acquired/transferred/analyzed): ")
                handler = input("Handler name: ")
                loc = input("Location: ")
                notes = input("Notes: ")
                self.log_custody(evidence[idx]['id'], action, handler, loc, notes)
                print("[+] Custody logged")
                
        elif choice == '7':
            self.display_status()
            
        elif choice == '8':
            plugin_dir = input("Plugin directory [./plugins]: ") or "./plugins"
            self.load_plugins(plugin_dir)
            
        elif choice == '0':
            self.shutdown()
            
        else:
            print("[!] Invalid choice")
        
        return choice != '0'


# Module Lazy Loaders
def get_disk_imager():
    if not hasattr(get_disk_imager, '_instance'):
        from modules.acquisition.disk_imager import DiskImager
        get_disk_imager._instance = DiskImager
    return get_disk_imager._instance

def get_partition_scanner():
    if not hasattr(get_partition_scanner, '_instance'):
        from modules.acquisition.partition_scanner import PartitionScanner
        get_partition_scanner._instance = PartitionScanner
    return get_partition_scanner._instance

def get_registry_parser():
    if not hasattr(get_registry_parser, '_instance'):
        from modules.artifacts.registry_parser import RegistryParser
        get_registry_parser._instance = RegistryParser
    return get_registry_parser._instance

def get_browser_forensics():
    if not hasattr(get_browser_forensics, '_instance'):
        from modules.artifacts.browser_forensics import BrowserForensics
        get_browser_forensics._instance = BrowserForensics
    return get_browser_forensics._instance

def get_file_carver():
    if not hasattr(get_file_carver, '_instance'):
        from modules.analysis.file_carver import FileCarver
        get_file_carver._instance = FileCarver
    return get_file_carver._instance

def get_hash_manager():
    if not hasattr(get_hash_manager, '_instance'):
        from modules.analysis.hash_manager import HashManager
        get_hash_manager._instance = HashManager
    return get_hash_manager._instance
