#!/usr/bin/env python3
"""FORENSIX Drone Forensics - Analyze drone/UAV forensic artifacts."""

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


class DroneForensics:
    """
    Drone/UAV Forensic Analysis Module.
    
    Extracts artifacts from:
        - DJI drones (flight logs, telemetry, media)
        - Parrot drones
        - Autel drones
        - Skydio drones
        - Custom/DIY drones (ArduPilot, PX4)
        - Drone controller apps
    """
    
    DRONE_PATTERNS = {
        "dji": {
            "paths": ["DJI", "dji", "com.dji"],
            "db_patterns": ["*dji*.db", "*fly*.db", "*flight*"],
            "log_patterns": ["*FLY*.DAT", "*FLY*.txt", "*log*"]
        },
        "parrot": {
            "paths": ["Parrot", "parrot", "com.parrot"],
            "db_patterns": ["*parrot*.db", "*freeflight*"]
        },
        "autel": {
            "paths": ["Autel", "autel", "com.autel"],
            "db_patterns": ["*autel*.db", "*explorer*"]
        },
        "ardupilot": {
            "paths": ["ardupilot", "APM", "Mission Planner"],
            "log_patterns": ["*.bin", "*log*.bin", "*tlog*"]
        },
        "px4": {
            "paths": ["px4", "QGroundControl", "qgc"],
            "log_patterns": ["*.ulg", "*log*.ulg"]
        }
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "devices_found": [],
            "flight_logs": [],
            "telemetry": [],
            "media_files": [],
            "gps_data": []
        }
    
    def scan_directory(self, directory: str, recursive: bool = True) -> Dict:
        """Scan for drone-related artifacts."""
        if not os.path.exists(directory):
            return self.results
        
        print(f"\n[*] Scanning for drone artifacts in: {directory}")
        
        for drone_type, patterns in self.DRONE_PATTERNS.items():
            for path_pattern in patterns["paths"]:
                search_path = os.path.join(directory, path_pattern)
                if os.path.exists(search_path):
                    self.results["devices_found"].append({
                        "drone_type": drone_type,
                        "path": search_path,
                        "found_at": datetime.now().isoformat()
                    })
                    print(f"  [+] {drone_type.upper()}: {search_path}")
        
        return self.results
    
    def parse_dji_flight_log(self, log_file: str) -> Optional[Dict]:
        """Parse DJI flight log (.txt or .DAT file)."""
        if not os.path.exists(log_file):
            return None
        
        flight_data = {
            "file": log_file,
            "drone_model": "Unknown",
            "flight_date": None,
            "duration": 0,
            "max_altitude": 0,
            "max_distance": 0,
            "max_speed": 0,
            "takeoff_location": None,
            "landing_location": None,
            "gps_points": [],
            "battery": {}
        }
        
        try:
            with open(log_file, 'r', errors='ignore') as f:
                content = f.read()
            
            alt_match = re.search(r'(?:altitude|height|ALT)[:=]\s*([\d.]+)', content, re.I)
            if alt_match:
                flight_data["max_altitude"] = float(alt_match.group(1))
            
            speed_match = re.search(r'(?:speed|vel|SPD)[:=]\s*([\d.]+)', content, re.I)
            if speed_match:
                flight_data["max_speed"] = float(speed_match.group(1))
            
            gps_pattern = re.compile(r'(-?\d+\.\d+),\s*(-?\d+\.\d+)')
            gps_matches = gps_pattern.findall(content)
            
            for lat, lon in gps_matches[:50]:
                flight_data["gps_points"].append({
                    "latitude": float(lat),
                    "longitude": float(lon)
                })
            
            if gps_matches:
                flight_data["takeoff_location"] = {
                    "latitude": float(gps_matches[0][0]),
                    "longitude": float(gps_matches[0][1])
                }
                if len(gps_matches) > 1:
                    flight_data["landing_location"] = {
                        "latitude": float(gps_matches[-1][0]),
                        "longitude": float(gps_matches[-1][1])
                    }
            
        except Exception as e:
            self.logger.error(f"DJI log parsing failed: {e}")
        
        self.results["flight_logs"].append(flight_data)
        return flight_data
    
    def extract_telemetry_db(self, db_path: str) -> List[Dict]:
        """Extract drone telemetry from SQLite database."""
        telemetry = []
        
        if not os.path.exists(db_path):
            return telemetry
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM {table} LIMIT 20")
                    for row in cursor.fetchall():
                        telemetry.append(dict(row))
                except:
                    pass
            
            conn.close()
        except Exception as e:
            self.logger.error(f"Telemetry extraction failed: {e}")
        
        self.results["telemetry"] = telemetry
        return telemetry
    
    def find_drone_media(self, directory: str) -> List[Dict]:
        """Find drone-captured media files."""
        media = []
        
        drone_media_patterns = ["DJI_", "PANO_", "THUMB_", "PANORAMA_"]
        media_extensions = ['.jpg', '.jpeg', '.mp4', '.mov', '.dng', '.raw']
        
        for root, _, files in os.walk(directory):
            for filename in files:
                if any(filename.startswith(p) for p in drone_media_patterns) and \
                   any(filename.lower().endswith(ext) for ext in media_extensions):
                    filepath = os.path.join(root, filename)
                    media.append({
                        "file": filepath,
                        "size": os.path.getsize(filepath),
                        "type": "photo" if filename.lower().endswith(('.jpg', '.jpeg', '.dng', '.raw')) else "video"
                    })
        
        self.results["media_files"] = media
        return media
    
    def get_statistics(self) -> Dict:
        return {
            "devices_found": len(self.results.get("devices_found", [])),
            "flight_logs": len(self.results.get("flight_logs", [])),
            "telemetry_points": len(self.results.get("telemetry", [])),
            "media_files": len(self.results.get("media_files", []))
        }
    
    def display_summary(self):
        stats = self.get_statistics()
        
        print(f"\n[Drone Forensics Summary]")
        print(f"{'='*50}")
        print(f"  Devices Found:  {stats['devices_found']}")
        print(f"  Flight Logs:    {stats['flight_logs']}")
        print(f"  Telemetry Pts:  {stats['telemetry_points']}")
        print(f"  Media Files:    {stats['media_files']}")
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Drone results exported: {output_file}")
