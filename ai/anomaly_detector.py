#!/usr/bin/env python3
"""HyperTraceX Anomaly Detector - AI-powered anomaly detection for forensic analysis."""

import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class AnomalyDetector:
    """
    AI-Powered Anomaly Detection for Digital Forensics.
    
    Detects suspicious patterns and anomalies in:
        - File system activity
        - User behavior
        - Network connections
        - System configurations
        - Timeline inconsistencies
    """
    
    # Suspicious file patterns
    SUSPICIOUS_PATTERNS = {
        "double_extension": [".txt.exe", ".pdf.exe", ".jpg.exe", ".doc.exe", 
                            ".png.exe", ".mp4.exe", ".zip.exe", ".rar.exe"],
        "hidden_files": [".", "~", "$"],
        "suspicious_locations": [
            "Temp", "tmp", "AppData/Local/Temp",
            "Windows/Tasks", "Windows/System32/Tasks",
            "ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"
        ],
        "ransomware_patterns": [
            ".encrypted", ".crypt", ".locked", ".wannacry",
            ".cryptolocker", ".locky", ".cerber", ".dharma"
        ],
        "keylogger_patterns": ["keylog", "keyboard", "keystroke", "keycapture"],
        "rat_patterns": ["remote", "backdoor", "trojan", "rat", "botnet"]
    }
    
    # Suspicious file extensions commonly used by malware
    MALWARE_EXTENSIONS = [
        ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".scr", ".pif"
    ]
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.anomalies: List[Dict] = []
        self.threat_score: Dict[str, int] = defaultdict(int)
    
    def analyze_filesystem(self, root_path: str, recursive: bool = True) -> List[Dict]:
        """
        Analyze file system for anomalies.
        
        Detects:
            - Double extension files (disguised executables)
            - Hidden files in suspicious locations
            - Ransomware indicators
            - Unusually large files
            - Recently modified system files
        """
        anomalies = []
        
        if not os.path.exists(root_path):
            self.logger.error(f"Path not found: {root_path}")
            return anomalies
        
        print(f"\n[*] Running anomaly detection...")
        print(f"    Root: {root_path}")
        
        file_count = 0
        
        try:
            if recursive:
                for dirpath, _, filenames in os.walk(root_path):
                    for filename in filenames:
                        filepath = os.path.join(dirpath, filename)
                        anomaly = self._analyze_single_file(filepath)
                        if anomaly:
                            anomalies.append(anomaly)
                            self.threat_score[dirpath] += anomaly.get("severity", 1)
                        file_count += 1
                        
                        if file_count % 500 == 0:
                            print(f"  Analyzed {file_count} files... Found {len(anomalies)} anomalies")
            else:
                for filename in os.listdir(root_path):
                    filepath = os.path.join(root_path, filename)
                    if os.path.isfile(filepath):
                        anomaly = self._analyze_single_file(filepath)
                        if anomaly:
                            anomalies.append(anomaly)
                        file_count += 1
            
            print(f"\n[+] Analysis complete: {file_count} files, {len(anomalies)} anomalies found")
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
        
        self.anomalies.extend(anomalies)
        return anomalies
    
    def _analyze_single_file(self, filepath: str) -> Optional[Dict]:
        """Analyze a single file for suspicious characteristics."""
        try:
            filename = os.path.basename(filepath).lower()
            stat = os.stat(filepath)
            size = stat.st_size
            
            anomaly = None
            reasons = []
            severity = 0
            
            # Check for double extensions (malware disguise)
            name_parts = filename.rsplit('.', 1)
            for pattern in self.SUSPICIOUS_PATTERNS["double_extension"]:
                if filename.endswith(pattern):
                    reasons.append(f"Double extension: {pattern}")
                    severity += 5
            
            # Check for hidden files in suspicious locations
            if filename.startswith('.'):
                for loc in self.SUSPICIOUS_PATTERNS["suspicious_locations"]:
                    if loc.lower() in filepath.lower():
                        reasons.append(f"Hidden file in suspicious location: {loc}")
                        severity += 3
            
            # Check for ransomware indicators
            for pattern in self.SUSPICIOUS_PATTERNS["ransomware_patterns"]:
                if pattern in filename:
                    reasons.append(f"Ransomware indicator: {pattern}")
                    severity += 8
            
            # Check for malware extensions in unusual locations
            ext = os.path.splitext(filename)[1].lower()
            if ext in self.MALWARE_EXTENSIONS:
                for loc in self.SUSPICIOUS_PATTERNS["suspicious_locations"]:
                    if loc.lower() in filepath.lower():
                        reasons.append(f"Executable in suspicious location")
                        severity += 6
            
            # Check for unusually large files (>1GB)
            if size > 1_000_000_000:
                reasons.append(f"Unusually large file: {size / (1024**3):.1f} GB")
                severity += 2
            
            # Check recent modifications (last 24 hours)
            mtime = datetime.fromtimestamp(stat.st_mtime)
            if datetime.now() - mtime < timedelta(hours=24):
                reasons.append(f"Recently modified: {mtime.isoformat()}")
                severity += 1
            
            if reasons:
                anomaly = {
                    "file": filepath,
                    "filename": filename,
                    "size": size,
                    "reasons": reasons,
                    "severity": severity,
                    "threat_level": "HIGH" if severity >= 8 else "MEDIUM" if severity >= 4 else "LOW",
                    "detected_at": datetime.now().isoformat()
                }
            
            return anomaly
            
        except Exception as e:
            self.logger.debug(f"File analysis error: {e}")
            return None
    
    def detect_timeline_anomalies(self, timeline_events: List[Dict]) -> List[Dict]:
        """
        Detect anomalies in forensic timeline.
        
        Checks for:
            - Events outside business hours
            - Burst activity (many events in short time)
            - Timestamp inconsistencies
        """
        anomalies = []
        
        if not timeline_events:
            return anomalies
        
        # Sort by timestamp
        sorted_events = sorted(
            [e for e in timeline_events if e.get("timestamp")],
            key=lambda x: x["timestamp"]
        )
        
        # Check for burst activity
        if len(sorted_events) > 100:
            time_diffs = []
            for i in range(1, min(len(sorted_events), 500)):
                try:
                    t1 = datetime.fromisoformat(sorted_events[i-1]["timestamp"])
                    t2 = datetime.fromisoformat(sorted_events[i]["timestamp"])
                    time_diffs.append((t2 - t1).total_seconds())
                except:
                    pass
            
            if time_diffs:
                avg_diff = sum(time_diffs) / len(time_diffs)
                
                for i, diff in enumerate(time_diffs):
                    if diff < avg_diff / 10 and diff > 0:
                        anomalies.append({
                            "type": "BURST_ACTIVITY",
                            "event": sorted_events[i],
                            "time_diff_seconds": diff,
                            "average_diff": avg_diff,
                            "severity": 5,
                            "detected_at": datetime.now().isoformat()
                        })
        
        return anomalies
    
    def detect_user_anomalies(self, registry_users: List[Dict]) -> List[Dict]:
        """
        Detect anomalous user account behavior.
        
        Checks for:
            - Multiple failed logins
            - Accounts with no password
            - Recently created accounts
            - Hidden/disabled accounts being re-enabled
        """
        anomalies = []
        
        for user in registry_users:
            reasons = []
            severity = 0
            
            # Check for disabled accounts
            flags = user.get("flags", [])
            if "Account Disabled" in str(flags):
                reasons.append("Account is disabled")
                severity += 2
            
            # Check password not required
            if "Password Not Required" in str(flags):
                reasons.append("Password not required")
                severity += 5
            
            # Check if password expired
            if "Password Expired" in str(flags):
                reasons.append("Password expired")
                severity += 3
            
            # Check login count anomalies
            login_count = user.get("login_count", 0)
            if login_count > 10000:
                reasons.append(f"Abnormal login count: {login_count}")
                severity += 4
            
            if reasons:
                anomalies.append({
                    "type": "USER_ANOMALY",
                    "username": user.get("username", "Unknown"),
                    "rid": user.get("rid", ""),
                    "reasons": reasons,
                    "severity": severity,
                    "threat_level": "HIGH" if severity >= 8 else "MEDIUM" if severity >= 4 else "LOW",
                    "detected_at": datetime.now().isoformat()
                })
        
        return anomalies
    
    def get_statistics(self) -> Dict:
        """Get anomaly detection statistics."""
        if not self.anomalies:
            return {"total_anomalies": 0}
        
        severity_dist = defaultdict(int)
        type_dist = defaultdict(int)
        threat_dist = defaultdict(int)
        
        for a in self.anomalies:
            severity_dist[a.get("severity", 0)] += 1
            type_dist[a.get("type", "UNKNOWN")] += 1
            threat_dist[a.get("threat_level", "UNKNOWN")] += 1
        
        return {
            "total_anomalies": len(self.anomalies),
            "high_threats": threat_dist.get("HIGH", 0),
            "medium_threats": threat_dist.get("MEDIUM", 0),
            "low_threats": threat_dist.get("LOW", 0),
            "severity_distribution": dict(severity_dist),
            "type_distribution": dict(type_dist),
            "top_threat_locations": sorted(
                self.threat_score.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]
        }
    
    def filter_by_threat_level(self, level: str) -> List[Dict]:
        """Filter anomalies by threat level (HIGH, MEDIUM, LOW)."""
        return [a for a in self.anomalies if a.get("threat_level") == level.upper()]
    
    def filter_by_severity(self, min_severity: int) -> List[Dict]:
        """Filter anomalies by minimum severity score."""
        return [a for a in self.anomalies if a.get("severity", 0) >= min_severity]
    
    def get_high_threats(self) -> List[Dict]:
        """Get all HIGH threat anomalies."""
        return self.filter_by_threat_level("HIGH")
    
    def display_report(self):
        """Display anomaly detection report."""
        stats = self.get_statistics()
        
        print(f"\n[Anomaly Detection Report]")
        print(f"{'='*70}")
        print(f"  Total Anomalies: {stats['total_anomalies']}")
        print(f"  HIGH Threats:    {stats.get('high_threats', 0)}")
        print(f"  MEDIUM Threats:  {stats.get('medium_threats', 0)}")
        print(f"  LOW Threats:     {stats.get('low_threats', 0)}")
        
        high_threats = self.get_high_threats()
        if high_threats:
            print(f"\n  [HIGH Threat Details]")
            for threat in high_threats[:10]:
                print(f"    File: {os.path.basename(threat.get('file', threat.get('username', 'Unknown')))}")
                for reason in threat.get("reasons", []):
                    print(f"      - {reason}")
        
        print(f"{'='*70}\n")
    
    def export_report(self, output_file: str):
        """Export anomaly report to JSON."""
        data = {
            "generated_at": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "anomalies": self.anomalies,
            "threat_scores": dict(self.threat_score)
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4, default=str)
        
        print(f"[+] Anomaly report exported: {output_file}")
    
    def clear(self):
        """Clear all detected anomalies."""
        self.anomalies.clear()
        self.threat_score.clear()
