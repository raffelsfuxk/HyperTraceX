#!/usr/bin/env python3
"""HyperTraceX Cloud Scanner - Collect forensic artifacts from cloud services."""

import os
import re
import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class CloudScanner:
    """
    Cloud Service Forensic Scanner.
    
    Collects artifacts from:
        - OneDrive
        - Google Drive
        - Dropbox
        - Amazon S3
        - iCloud
        - Box
        - Mega
    """
    
    # Cloud service paths on Windows
    CLOUD_PATHS = {
        "onedrive": [
            "OneDrive",
            "Microsoft/OneDrive"
        ],
        "google_drive": [
            "Google Drive",
            "Google/Drive"
        ],
        "dropbox": [
            "Dropbox",
            "Dropbox (Personal)",
            "Dropbox (Business)"
        ],
        "icloud": [
            "iCloudDrive",
            "Apple/MobileSync/Backup"
        ],
        "box": [
            "Box",
            "Box Sync"
        ]
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "onedrive": [],
            "google_drive": [],
            "dropbox": [],
            "icloud": [],
            "others": []
        }
    
    def scan_user_directory(self, user_path: str) -> Dict:
        """
        Scan user directory for cloud service artifacts.
        
        Args:
            user_path: Path to user home directory
        
        Returns:
            Dict with found cloud artifacts
        """
        if not os.path.exists(user_path):
            self.logger.error(f"User path not found: {user_path}")
            return self.results
        
        print(f"\n[*] Scanning cloud artifacts in: {user_path}")
        
        for service, paths in self.CLOUD_PATHS.items():
            for service_path in paths:
                full_path = os.path.join(user_path, service_path)
                
                if os.path.exists(full_path):
                    self._scan_service_directory(service, full_path)
        
        return self.results
    
    def _scan_service_directory(self, service: str, directory: str):
        """Scan a specific cloud service directory."""
        file_list = []
        total_size = 0
        
        try:
            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    try:
                        stat = os.stat(filepath)
                        file_info = {
                            "filename": filename,
                            "path": filepath,
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                            "created": datetime.fromtimestamp(stat.st_ctime).isoformat()
                        }
                        file_list.append(file_info)
                        total_size += stat.st_size
                    except:
                        pass
            
            self.results[service] = {
                "directory": directory,
                "total_files": len(file_list),
                "total_size_mb": round(total_size / (1024*1024), 2),
                "files": file_list[:200],
                "last_sync": self._find_latest_sync(file_list)
            }
            
            print(f"  [{service}] {len(file_list)} files ({round(total_size/(1024*1024), 2)} MB)")
            
        except Exception as e:
            self.logger.error(f"Cloud scan error for {service}: {e}")
    
    def _find_latest_sync(self, file_list: List[Dict]) -> Optional[str]:
        """Find the most recent file modification time (indicates last sync)."""
        if not file_list:
            return None
        
        latest = max(file_list, key=lambda x: x.get("modified", ""))
        return latest.get("modified")
    
    def extract_onedrive_logs(self, log_path: str) -> List[Dict]:
        """Extract OneDrive sync logs."""
        logs = []
        
        if not os.path.exists(log_path):
            return logs
        
        try:
            for filename in os.listdir(log_path):
                if filename.startswith("OneDrive") and filename.endswith(".log"):
                    filepath = os.path.join(log_path, filename)
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f.readlines()[-100:]:
                            logs.append({
                                "log_file": filename,
                                "entry": line.strip(),
                                "timestamp": line[:23] if len(line) > 23 else ""
                            })
        except Exception as e:
            self.logger.error(f"OneDrive log extraction failed: {e}")
        
        return logs
    
    def extract_google_drive_cache(self, cache_path: str) -> List[Dict]:
        """Extract Google Drive file cache metadata."""
        cached_files = []
        
        if not os.path.exists(cache_path):
            return cached_files
        
        # Google Drive stores metadata in SQLite
        db_files = []
        for root, _, files in os.walk(cache_path):
            for f in files:
                if f.startswith("snapshot") and f.endswith(".db"):
                    db_files.append(os.path.join(root, f))
        
        for db_file in db_files:
            try:
                conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                
                for table in tables:
                    try:
                        cursor.execute(f"SELECT * FROM {table} LIMIT 100")
                        for row in cursor.fetchall():
                            cached_files.append(dict(row))
                    except:
                        pass
                
                conn.close()
            except:
                pass
        
        return cached_files
    
    def extract_dropbox_config(self, dropbox_path: str) -> Dict:
        """Extract Dropbox account configuration."""
        config = {}
        
        config_files = [
            os.path.join(dropbox_path, "info.json"),
            os.path.join(dropbox_path, "host.db"),
            os.path.join(dropbox_path, ".dropbox", "config.db")
        ]
        
        for config_file in config_files:
            if os.path.exists(config_file):
                try:
                    if config_file.endswith(".json"):
                        with open(config_file, 'r') as f:
                            config.update(json.load(f))
                    elif config_file.endswith(".db"):
                        conn = sqlite3.connect(f"file:{config_file}?mode=ro", uri=True)
                        conn.row_factory = sqlite3.Row
                        cursor = conn.cursor()
                        cursor.execute("SELECT * FROM config")
                        for row in cursor.fetchall():
                            config[dict(row).get("key", "")] = dict(row).get("value", "")
                        conn.close()
                except:
                    pass
        
        return config
    
    def get_statistics(self) -> Dict:
        """Get cloud scan statistics."""
        stats = {
            "total_services": 0,
            "total_files": 0,
            "total_size_mb": 0,
            "service_details": {}
        }
        
        for service, data in self.results.items():
            if data and isinstance(data, dict):
                stats["total_services"] += 1
                stats["total_files"] += data.get("total_files", 0)
                stats["total_size_mb"] += data.get("total_size_mb", 0)
                stats["service_details"][service] = {
                    "files": data.get("total_files", 0),
                    "size_mb": data.get("total_size_mb", 0)
                }
        
        stats["total_size_gb"] = round(stats["total_size_mb"] / 1024, 2)
        
        return stats
    
    def display_summary(self):
        """Display cloud scan summary."""
        stats = self.get_statistics()
        
        print(f"\n[Cloud Forensics Summary]")
        print(f"{'='*55}")
        print(f"  Services Found: {stats['total_services']}")
        print(f"  Total Files:    {stats['total_files']}")
        print(f"  Total Size:     {stats['total_size_gb']:.2f} GB")
        
        for service, detail in stats.get("service_details", {}).items():
            print(f"\n  [{service.upper()}]")
            print(f"    Files: {detail['files']}")
            print(f"    Size:  {detail['size_mb']:.1f} MB")
        
        print(f"{'='*55}\n")
    
    def export_json(self, output_file: str):
        """Export results to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Cloud results exported: {output_file}")
