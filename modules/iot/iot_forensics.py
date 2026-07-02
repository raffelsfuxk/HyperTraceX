#!/usr/bin/env python3
"""HyperTraceX IoT Forensics - Analyze Internet of Things device artifacts."""

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
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class IoTForensics:
    """
    IoT Device Forensic Analysis Module.
    
    Extracts artifacts from:
        - Smart home devices (Alexa, Google Home)
        - IP cameras (Ring, Nest, Wyze)
        - Smart TVs
        - Router/firewall logs
        - Smart watches
        - Fitness trackers
        - Vehicle infotainment systems
    """
    
    IOT_DEVICE_PATTERNS = {
        "alexa": {
            "paths": ["com.amazon.dee.app", "alexa", "echo"],
            "db_patterns": ["*alexa*.db", "*echo*.db"]
        },
        "google_home": {
            "paths": ["com.google.android.apps.chromecast.app", "google_home", "googlehome"],
            "db_patterns": ["*google_home*.db", "*chromecast*.db"]
        },
        "ring": {
            "paths": ["com.ringapp", "ring"],
            "db_patterns": ["*ring*.db"]
        },
        "nest": {
            "paths": ["com.nest.android", "nest"],
            "db_patterns": ["*nest*.db"]
        },
        "smart_tv": {
            "paths": ["samsung", "lg", "roku", "fire_tv", "android_tv"],
            "db_patterns": ["*tv*.db", "*smart*.db"]
        },
        "router": {
            "paths": ["router", "gateway", "modem"],
            "log_patterns": ["*syslog*", "*router*.log", "*dhcp*"]
        },
        "camera": {
            "paths": ["camera", "cam", "ipcam", "cctv", "surveillance"],
            "db_patterns": ["*camera*.db", "*cam*.db"]
        }
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "devices_found": [],
            "network_logs": [],
            "device_configs": [],
            "firmware_info": []
        }
    
    def scan_directory(self, directory: str, recursive: bool = True) -> Dict:
        """Scan for IoT device artifacts."""
        if not os.path.exists(directory):
            self.logger.error(f"Directory not found: {directory}")
            return self.results
        
        print(f"\n[*] Scanning for IoT artifacts in: {directory}")
        
        for device_type, patterns in self.IOT_DEVICE_PATTERNS.items():
            for path_pattern in patterns["paths"]:
                search_path = os.path.join(directory, path_pattern)
                if os.path.exists(search_path):
                    self.results["devices_found"].append({
                        "device_type": device_type,
                        "path": search_path,
                        "found_at": datetime.now().isoformat()
                    })
                    print(f"  [+] {device_type}: {search_path}")
        
        return self.results
    
    def extract_router_logs(self, log_file: str) -> List[Dict]:
        """Extract and parse router/firewall logs."""
        logs = []
        
        if not os.path.exists(log_file):
            return logs
        
        try:
            with open(log_file, 'r', errors='ignore') as f:
                for line in f.readlines()[-500:]:
                    line = line.strip()
                    if not line:
                        continue
                    
                    log_entry = {
                        "raw": line[:200],
                        "timestamp": line[:23] if len(line) > 23 else "",
                        "source": "router_log"
                    }
                    
                    if "DHCP" in line:
                        log_entry["type"] = "DHCP"
                    elif "DNS" in line:
                        log_entry["type"] = "DNS"
                    elif "Firewall" in line:
                        log_entry["type"] = "FIREWALL"
                    else:
                        log_entry["type"] = "SYSTEM"
                    
                    logs.append(log_entry)
        except:
            pass
        
        self.results["network_logs"] = logs
        return logs
    
    def extract_device_info(self, device_path: str) -> Dict:
        """Extract device configuration and info."""
        info = {
            "path": device_path,
            "config_files": [],
            "firmware_version": "Unknown",
            "serial_number": "Unknown",
            "mac_address": "Unknown"
        }
        
        if os.path.exists(device_path):
            for root, _, files in os.walk(device_path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    if filename.endswith(('.conf', '.cfg', '.ini', '.xml', '.json')):
                        info["config_files"].append(filepath)
                        
                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                content = f.read()
                                
                                fw_match = re.search(r'(?:firmware|version|fw)[:=]\s*["\']?([\d.]+)', content, re.I)
                                if fw_match:
                                    info["firmware_version"] = fw_match.group(1)
                                
                                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', content)
                                if mac_match:
                                    info["mac_address"] = mac_match.group(0)
                                
                                sn_match = re.search(r'(?:serial|sn)[:=]\s*["\']?(\w+)', content, re.I)
                                if sn_match:
                                    info["serial_number"] = sn_match.group(1)
                        except:
                            pass
        
        return info
    
    def find_smart_devices_on_network(self, pcap_file: str = None, arp_table: List = None) -> List[Dict]:
        """Identify IoT devices based on MAC OUI or network behavior."""
        devices = []
        
        iot_ouis = {
            "Amazon": ["FCA621", "B0FC0D"],
            "Google": ["ACF1DF", "3C5AB4"],
            "Samsung": ["001377", "60A4B7"],
            "Apple": ["FCA621", "B8E856"],
            "Ring": ["B8E856"],
            "Nest": ["18B430", "64167F"],
            "Roku": ["B0A737"],
            "Sonos": ["000E58", "5CAAFD"],
            "Philips": ["001788"],
            "Belkin": ["94103E"],
            "D-Link": ["00A0C5"],
            "TP-Link": ["001D7E"]
        }
        
        if arp_table:
            for entry in arp_table:
                mac = entry.get("mac", "").upper().replace(":", "").replace("-", "")[:6]
                for vendor, ouis in iot_ouis.items():
                    if mac in [o.upper() for o in ouis]:
                        devices.append({
                            "ip": entry.get("ip", ""),
                            "mac": entry.get("mac", ""),
                            "vendor": vendor,
                            "device_type": "IoT"
                        })
        
        return devices
    
    def get_statistics(self) -> Dict:
        """Get IoT forensics statistics."""
        return {
            "devices_found": len(self.results.get("devices_found", [])),
            "network_logs": len(self.results.get("network_logs", [])),
            "config_files": sum(
                len(d.get("config_files", [])) 
                for d in self.results.get("device_configs", [])
            )
        }
    
    def display_summary(self):
        """Display IoT forensics summary."""
        stats = self.get_statistics()
        
        print(f"\n[IoT Forensics Summary]")
        print(f"{'='*50}")
        print(f"  IoT Devices Found: {stats['devices_found']}")
        print(f"  Network Logs:      {stats['network_logs']}")
        print(f"  Config Files:      {stats['config_files']}")
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] IoT results exported: {output_file}")
