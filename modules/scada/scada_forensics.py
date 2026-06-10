#!/usr/bin/env python3
"""FORENSIX SCADA/ICS Forensics - Analyze industrial control system artifacts."""

import os
import re
import json
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class SCADAForensics:
    """
    SCADA/ICS Forensic Analysis Module.
    
    Extracts artifacts from:
        - PLC configuration files
        - HMI/SCADA project files
        - Industrial network logs
        - MODBUS/DNP3 communication logs
        - OPC server data
        - Engineering workstation files
    """
    
    SCADA_PATTERNS = {
        "siemens": {
            "paths": ["Siemens", "Step7", "TIA Portal", "WinCC"],
            "file_patterns": ["*.s7p", "*.ap*", "*.awl", "*.scl", "*.mwp"]
        },
        "rockwell": {
            "paths": ["Rockwell", "Allen-Bradley", "RSLogix", "FactoryTalk"],
            "file_patterns": ["*.acd", "*.rss", "*.l5k", "*.l5x", "*.apa"]
        },
        "schneider": {
            "paths": ["Schneider", "Unity Pro", "EcoStruxure"],
            "file_patterns": ["*.stu", "*.xef", "*.zef", "*.prj"]
        },
        "mitsubishi": {
            "paths": ["Mitsubishi", "GX Works", "Melsec"],
            "file_patterns": ["*.gxw", "*.gx3", "*.gxd"]
        },
        "opc": {
            "paths": ["OPC", "Matrikon", "Kepware", "OPC Server"],
            "file_patterns": ["*.opf", "*.xml", "*.cfg"]
        },
        "modbus": {
            "paths": ["Modbus", "modbus", "MBTools"],
            "file_patterns": ["*.mbs", "*.mod", "*.cfg"]
        }
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "plc_files": [],
            "hmi_projects": [],
            "network_logs": [],
            "firmware_info": [],
            "config_changes": []
        }
    
    def scan_directory(self, directory: str, recursive: bool = True) -> Dict:
        """Scan for SCADA/ICS artifacts."""
        if not os.path.exists(directory):
            return self.results
        
        print(f"\n[*] Scanning for SCADA/ICS artifacts in: {directory}")
        
        for vendor, patterns in self.SCADA_PATTERNS.items():
            for path_pattern in patterns["paths"]:
                search_path = os.path.join(directory, path_pattern)
                if os.path.exists(search_path):
                    self.results["plc_files"].append({
                        "vendor": vendor,
                        "path": search_path,
                        "found_at": datetime.now().isoformat()
                    })
                    print(f"  [+] {vendor.upper()}: {search_path}")
            
            for file_pattern in patterns["file_patterns"]:
                import glob
                for filepath in glob.glob(os.path.join(directory, "**", file_pattern), recursive=recursive)[:50]:
                    self.results["plc_files"].append({
                        "vendor": vendor,
                        "file": filepath,
                        "size": os.path.getsize(filepath) if os.path.exists(filepath) else 0,
                        "found_at": datetime.now().isoformat()
                    })
        
        return self.results
    
    def parse_plc_config(self, filepath: str) -> Optional[Dict]:
        """Parse PLC configuration file."""
        if not os.path.exists(filepath):
            return None
        
        config = {
            "file": filepath,
            "filename": os.path.basename(filepath),
            "size": os.path.getsize(filepath),
            "vendor": "Unknown",
            "version": "Unknown",
            "ip_addresses": [],
            "tags": [],
            "logic_sections": []
        }
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if "Siemens" in content or "STEP" in content:
                config["vendor"] = "Siemens"
            elif "Rockwell" in content or "Allen-Bradley" in content:
                config["vendor"] = "Rockwell"
            elif "Schneider" in content or "Unity" in content:
                config["vendor"] = "Schneider"
            
            version_match = re.search(r'(?:version|ver|v)[:=]\s*["\']?([\d.]+)', content, re.I)
            if version_match:
                config["version"] = version_match.group(1)
            
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            config["ip_addresses"] = list(set(ip_pattern.findall(content)))[:20]
            
            tag_pattern = re.compile(r'(?:tag|variable|symbol|label)\s+["\']?(\w+)["\']?', re.I)
            config["tags"] = tag_pattern.findall(content)[:50]
            
        except Exception as e:
            self.logger.error(f"PLC config parsing failed: {e}")
        
        return config
    
    def extract_modbus_logs(self, log_file: str) -> List[Dict]:
        """Parse MODBUS communication logs."""
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
                        "type": "MODBUS"
                    }
                    
                    if "read" in line.lower():
                        log_entry["function"] = "READ"
                    elif "write" in line.lower():
                        log_entry["function"] = "WRITE"
                    
                    logs.append(log_entry)
        except:
            pass
        
        self.results["network_logs"] = logs
        return logs
    
    def find_firmware_files(self, directory: str) -> List[Dict]:
        """Find PLC/HMI firmware files."""
        firmware = []
        
        firmware_patterns = ["*.fw", "*.bin", "*.hex", "*.s19", "*.img", "*.upd", "*.upgrade"]
        
        import glob
        for pattern in firmware_patterns:
            for filepath in glob.glob(os.path.join(directory, "**", pattern), recursive=True)[:30]:
                firmware.append({
                    "file": filepath,
                    "size": os.path.getsize(filepath) if os.path.exists(filepath) else 0,
                    "type": "firmware"
                })
        
        self.results["firmware_info"] = firmware
        return firmware
    
    def get_statistics(self) -> Dict:
        return {
            "plc_files_found": len(self.results.get("plc_files", [])),
            "network_logs": len(self.results.get("network_logs", [])),
            "firmware_files": len(self.results.get("firmware_info", [])),
            "config_changes": len(self.results.get("config_changes", []))
        }
    
    def display_summary(self):
        stats = self.get_statistics()
        
        print(f"\n[SCADA/ICS Forensics Summary]")
        print(f"{'='*50}")
        print(f"  PLC Files:       {stats['plc_files_found']}")
        print(f"  Network Logs:    {stats['network_logs']}")
        print(f"  Firmware Files:  {stats['firmware_files']}")
        print(f"  Config Changes:  {stats['config_changes']}")
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] SCADA results exported: {output_file}")
