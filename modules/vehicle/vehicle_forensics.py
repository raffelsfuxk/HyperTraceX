#!/usr/bin/env python3
"""FORENSIX Vehicle Forensics - Analyze vehicle infotainment and telematics data."""

import os
import re
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class VehicleForensics:
    """
    Vehicle Forensic Analysis Module.
    
    Extracts artifacts from:
        - Infotainment systems (Android Auto, Apple CarPlay)
        - Navigation history (GPS waypoints, routes)
        - Bluetooth connections (paired devices, call logs)
        - USB device history
        - Vehicle telematics (speed, location, events)
        - OBD-II diagnostic data
        - Dashcam footage
    """
    
    VEHICLE_PATTERNS = {
        "android_auto": {
            "paths": ["AndroidAuto", "com.google.android.projection.gearhead"],
            "db_patterns": ["*android_auto*.db", "*car*.db"]
        },
        "carplay": {
            "paths": ["CarPlay", "com.apple.carplay"],
            "db_patterns": ["*carplay*.db"]
        },
        "navigation": {
            "paths": ["Navigation", "nav", "gps", "maps"],
            "db_patterns": ["*nav*.db", "*gps*.db", "*maps*.db", "*route*"]
        },
        "bluetooth": {
            "paths": ["Bluetooth", "bt", "handsfree"],
            "db_patterns": ["*bluetooth*.db", "*bt*.db", "*paired*"]
        },
        "dashcam": {
            "paths": ["dashcam", "dash_cam", "BlackVue", "Garmin"],
            "media_patterns": ["*.mp4", "*.avi", "*.mov"]
        }
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "infotainment": [],
            "navigation": [],
            "bluetooth_devices": [],
            "call_logs": [],
            "usb_devices": [],
            "telematics": [],
            "dashcam": []
        }
    
    def scan_directory(self, directory: str, recursive: bool = True) -> Dict:
        """Scan for vehicle-related artifacts."""
        if not os.path.exists(directory):
            return self.results
        
        print(f"\n[*] Scanning for vehicle artifacts in: {directory}")
        
        for system_type, patterns in self.VEHICLE_PATTERNS.items():
            for path_pattern in patterns["paths"]:
                search_path = os.path.join(directory, path_pattern)
                if os.path.exists(search_path):
                    self.results["infotainment"].append({
                        "system": system_type,
                        "path": search_path,
                        "found_at": datetime.now().isoformat()
                    })
                    print(f"  [+] {system_type}: {search_path}")
        
        return self.results
    
    def parse_navigation_history(self, db_path: str) -> List[Dict]:
        """Extract navigation history from GPS database."""
        history = []
        
        if not os.path.exists(db_path):
            return history
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM {table} LIMIT 50")
                    for row in cursor.fetchall():
                        data = dict(row)
                        data["_source_table"] = table
                        history.append(data)
                except:
                    pass
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Navigation history extraction failed: {e}")
        
        self.results["navigation"] = history
        return history
    
    def extract_bluetooth_devices(self, db_path: str) -> List[Dict]:
        """Extract paired Bluetooth devices."""
        devices = []
        
        if not os.path.exists(db_path):
            return devices
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                table_lower = table.lower()
                if any(kw in table_lower for kw in ["device", "paired", "bt", "bluetooth"]):
                    try:
                        cursor.execute(f"SELECT * FROM {table} LIMIT 50")
                        for row in cursor.fetchall():
                            device = dict(row)
                            device["_source_table"] = table
                            devices.append(device)
                    except:
                        pass
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Bluetooth extraction failed: {e}")
        
        self.results["bluetooth_devices"] = devices
        return devices
    
    def extract_call_logs(self, db_path: str) -> List[Dict]:
        """Extract call logs from handsfree system."""
        calls = []
        
        if not os.path.exists(db_path):
            return calls
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                table_lower = table.lower()
                if any(kw in table_lower for kw in ["call", "phone", "dial", "contact"]):
                    try:
                        cursor.execute(f"SELECT * FROM {table} LIMIT 50")
                        for row in cursor.fetchall():
                            call = dict(row)
                            call["_source_table"] = table
                            calls.append(call)
                    except:
                        pass
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Call log extraction failed: {e}")
        
        self.results["call_logs"] = calls
        return calls
    
    def parse_dashcam_metadata(self, directory: str) -> List[Dict]:
        """Find and catalog dashcam footage."""
        footage = []
        
        for root, _, files in os.walk(directory):
            for filename in files:
                if filename.lower().endswith(('.mp4', '.avi', '.mov')):
                    filepath = os.path.join(root, filename)
                    
                    dashcam_keywords = ["dash", "cam", "blackvue", "garmin", "thinkware", 
                                        "viofo", "nextbase", "front", "rear", "event"]
                    
                    if any(kw in filepath.lower() for kw in dashcam_keywords):
                        footage.append({
                            "file": filepath,
                            "size": os.path.getsize(filepath),
                            "modified": datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                        })
        
        self.results["dashcam"] = footage
        return footage
    
    def get_statistics(self) -> Dict:
        return {
            "infotainment_systems": len(self.results.get("infotainment", [])),
            "navigation_points": len(self.results.get("navigation", [])),
            "bluetooth_devices": len(self.results.get("bluetooth_devices", [])),
            "call_logs": len(self.results.get("call_logs", [])),
            "dashcam_files": len(self.results.get("dashcam", []))
        }
    
    def display_summary(self):
        stats = self.get_statistics()
        
        print(f"\n[Vehicle Forensics Summary]")
        print(f"{'='*50}")
        print(f"  Infotainment:     {stats['infotainment_systems']}")
        print(f"  Nav Points:       {stats['navigation_points']}")
        print(f"  BT Devices:       {stats['bluetooth_devices']}")
        print(f"  Call Logs:        {stats['call_logs']}")
        print(f"  Dashcam Files:    {stats['dashcam_files']}")
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Vehicle results exported: {output_file}")
