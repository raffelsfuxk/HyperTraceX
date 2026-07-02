#!/usr/bin/env python3
"""HyperTraceX Memory Forensics - Analyze RAM dumps and live memory."""

import os
import re
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class MemoryForensics:
    """
    Memory Forensics Analysis Module.
    
    Features:
        - Process enumeration
        - Network connection extraction
        - DLL/Module listing
        - Registry hive extraction
        - Malware detection in memory
        - String extraction
        - Timeline analysis
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "processes": [],
            "connections": [],
            "modules": [],
            "registry_keys": [],
            "suspicious": [],
            "strings": []
        }
    
    def analyze_memory_dump(self, dump_file: str, profile: str = "auto") -> Dict:
        """
        Analyze memory dump using Volatility.
        
        Args:
            dump_file: Path to memory dump file
            profile: Volatility profile (e.g., Win10x64, LinuxUbuntu)
        
        Returns:
            Analysis results dict
        """
        if not os.path.exists(dump_file):
            self.logger.error(f"Dump file not found: {dump_file}")
            return self.results
        
        print(f"\n[*] Analyzing memory dump: {os.path.basename(dump_file)}")
        
        volatility_path = self._find_volatility()
        
        if volatility_path:
            self._run_volatility_plugins(volatility_path, dump_file, profile)
        else:
            self._basic_memory_analysis(dump_file)
        
        return self.results
    
    def _find_volatility(self) -> Optional[str]:
        """Find Volatility installation path."""
        possible_paths = [
            "/usr/bin/volatility3",
            "/usr/bin/volatility",
            "/usr/local/bin/volatility3",
            "/opt/volatility3/vol.py",
            "/opt/volatility/vol.py"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def _run_volatility_plugins(self, vol_path: str, dump_file: str, profile: str):
        """Run common Volatility plugins."""
        plugins = {
            "windows": [
                ("windows.pslist", "List processes"),
                ("windows.netscan", "Network connections"),
                ("windows.dlllist", "Loaded DLLs"),
                ("windows.hivelist", "Registry hives"),
                ("windows.malfind", "Find hidden/injected code"),
                ("windows.cmdline", "Process command lines"),
            ],
            "linux": [
                ("linux.pslist", "List processes"),
                ("linux.netstat", "Network connections"),
                ("linux.lsof", "Open files"),
                ("linux.bash", "Bash history"),
            ]
        }
        
        # Detect OS type
        is_windows = self._detect_os_type(dump_file)
        plugin_list = plugins["windows"] if is_windows else plugins["linux"]
        
        for plugin_name, description in plugin_list:
            print(f"  [*] Running: {description}")
            
            try:
                cmd = ["python3", vol_path, "-f", dump_file, plugin_name]
                if profile != "auto":
                    cmd.extend(["--profile", profile])
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if plugin_name == "windows.pslist" or plugin_name == "linux.pslist":
                    self._parse_process_list(result.stdout)
                elif "netscan" in plugin_name or "netstat" in plugin_name:
                    self._parse_network_connections(result.stdout)
                elif "malfind" in plugin_name:
                    self._parse_malfind(result.stdout)
                
            except FileNotFoundError:
                self.logger.warning(f"Volatility not properly installed")
                break
            except subprocess.TimeoutExpired:
                self.logger.warning(f"Timeout running {plugin_name}")
            except Exception as e:
                self.logger.error(f"Error running {plugin_name}: {e}")
    
    def _basic_memory_analysis(self, dump_file: str):
        """Basic memory analysis without Volatility."""
        print("  [*] Performing basic analysis (strings + hex)")
        
        try:
            # Extract strings from memory dump
            result = subprocess.run(
                ["strings", "-n", "8", dump_file],
                capture_output=True, text=True, timeout=30
            )
            
            strings = result.stdout.splitlines()
            self.results["strings"] = strings[:500]
            
            # Search for indicators
            indicators = {
                "passwords": [r'password[=:]\s*\S+', r'pwd[=:]\s*\S+'],
                "urls": [r'https?://[^\s]+'],
                "ips": [r'\b(?:\d{1,3}\.){3}\d{1,3}\b'],
                "emails": [r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b']
            }
            
            for category, patterns in indicators.items():
                for pattern in patterns:
                    for line in strings:
                        matches = re.findall(pattern, line, re.IGNORECASE)
                        for match in matches[:10]:
                            self.results["suspicious"].append({
                                "category": category,
                                "value": match
                            })
            
        except Exception as e:
            self.logger.error(f"Basic analysis failed: {e}")
    
    def _detect_os_type(self, dump_file: str) -> bool:
        """Detect if memory dump is from Windows."""
        try:
            result = subprocess.run(
                ["strings", dump_file],
                capture_output=True, text=True, timeout=10
            )
            return "Windows" in result.stdout
        except:
            return False
    
    def _parse_process_list(self, output: str):
        """Parse Volatility process listing output."""
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0].isdigit():
                try:
                    process = {
                        "pid": int(parts[0]),
                        "ppid": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                        "name": parts[-1] if parts else ""
                    }
                    self.results["processes"].append(process)
                    
                    # Check for suspicious process names
                    suspicious_names = ["cmd.exe", "powershell.exe", "wscript.exe",
                                       "cscript.exe", "rundll32.exe", "regsvr32.exe",
                                       "mshta.exe", "certutil.exe", "bitsadmin.exe"]
                    
                    if any(s in process["name"].lower() for s in suspicious_names):
                        self.results["suspicious"].append({
                            "type": "suspicious_process",
                            "process": process["name"],
                            "pid": process["pid"]
                        })
                except:
                    pass
    
    def _parse_network_connections(self, output: str):
        """Parse Volatility network scan output."""
        for line in output.splitlines():
            if "ESTABLISHED" in line or "LISTEN" in line:
                parts = line.split()
                if len(parts) >= 4:
                    self.results["connections"].append({
                        "protocol": parts[0] if parts else "",
                        "local": parts[2] if len(parts) > 2 else "",
                        "remote": parts[3] if len(parts) > 3 else "",
                        "state": "ESTABLISHED" if "ESTABLISHED" in line else "LISTEN"
                    })
    
    def _parse_malfind(self, output: str):
        """Parse Volatility malfind output for hidden code."""
        if "Process" in output or "Vad" in output:
            self.results["suspicious"].append({
                "type": "code_injection",
                "details": "Possible hidden/injected code found"
            })
    
    def analyze_live_system(self) -> Dict:
        """Analyze live system memory (Linux only)."""
        print(f"\n[*] Analyzing live system memory...")
        
        try:
            # List processes
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True
            )
            
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 11:
                    self.results["processes"].append({
                        "user": parts[0],
                        "pid": int(parts[1]),
                        "cpu": parts[2],
                        "mem": parts[3],
                        "command": " ".join(parts[10:])
                    })
            
            # Memory info
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo", 'r') as f:
                    self.results["memory_info"] = f.read()
            
            print(f"[+] Live analysis complete: {len(self.results['processes'])} processes")
            
        except Exception as e:
            self.logger.error(f"Live analysis failed: {e}")
        
        return self.results
    
    def find_suspicious_processes(self) -> List[Dict]:
        """Identify suspicious processes based on heuristics."""
        suspicious = []
        
        for proc in self.results.get("processes", []):
            reasons = []
            
            # Process name checks
            name = str(proc.get("name", proc.get("command", ""))).lower()
            
            if not name:
                continue
            
            if "cmd.exe" in name or "powershell.exe" in name:
                reasons.append("Command shell execution")
            
            if "nc.exe" in name or "ncat" in name:
                reasons.append("Netcat detected")
            
            if "mimikatz" in name:
                reasons.append("Mimikatz credential theft tool")
            
            if "procdump" in name or "lsass" in name:
                reasons.append("Process memory dumping")
            
            if reasons:
                suspicious.append({
                    "process": proc,
                    "reasons": reasons,
                    "risk": "HIGH"
                })
        
        return suspicious
    
    def extract_credentials(self, dump_file: str) -> List[Dict]:
        """Try to extract credentials from memory dump."""
        credentials = []
        
        password_patterns = [
            r'password[=:]\s*["\']?([^"\'&\s]+)',
            r'pwd[=:]\s*["\']?([^"\'&\s]+)',
            r'pass[=:]\s*["\']?([^"\'&\s]+)',
            r'login[=:]\s*["\']?([^"\'&\s]+)',
        ]
        
        try:
            result = subprocess.run(
                ["strings", dump_file],
                capture_output=True, text=True, timeout=30
            )
            
            for pattern in password_patterns:
                matches = re.findall(pattern, result.stdout, re.IGNORECASE)
                for match in matches[:20]:
                    if len(match) > 3:
                        credentials.append({
                            "pattern": pattern,
                            "value": match
                        })
            
        except Exception as e:
            self.logger.error(f"Credential extraction failed: {e}")
        
        return credentials
    
    def get_statistics(self) -> Dict:
        """Get memory analysis statistics."""
        return {
            "total_processes": len(self.results.get("processes", [])),
            "total_connections": len(self.results.get("connections", [])),
            "total_modules": len(self.results.get("modules", [])),
            "suspicious_found": len(self.results.get("suspicious", [])),
            "strings_extracted": len(self.results.get("strings", []))
        }
    
    def display_summary(self):
        """Display memory analysis summary."""
        stats = self.get_statistics()
        
        print(f"\n[Memory Forensics Summary]")
        print(f"{'='*50}")
        print(f"  Processes Found:    {stats['total_processes']}")
        print(f"  Network Connections:{stats['total_connections']}")
        print(f"  Modules Loaded:     {stats['total_modules']}")
        print(f"  Suspicious Items:   {stats['suspicious_found']}")
        print(f"  Strings Extracted:  {stats['strings_extracted']}")
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        """Export results to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Memory analysis exported: {output_file}")
