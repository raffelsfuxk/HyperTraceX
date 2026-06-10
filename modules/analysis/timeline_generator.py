#!/usr/bin/env python3
"""FORENSIX Timeline Generator - Build forensic timelines from file system metadata."""

import os
import time
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class TimelineGenerator:
    """
    Forensic Timeline Generator.
    
    Creates unified timelines from:
        - File system metadata (MAC times)
        - Registry timestamps
        - Browser history timestamps
        - Event logs
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.events: List[Dict] = []
    
    def scan_filesystem(self, root_path: str, recursive: bool = True) -> List[Dict]:
        """
        Extract timeline from file system metadata.
        
        Collects MAC (Modified, Accessed, Created/Changed) times
        for all files in the specified path.
        """
        events = []
        
        if not os.path.exists(root_path):
            self.logger.error(f"Path not found: {root_path}")
            return events
        
        print(f"\n[*] Building file system timeline...")
        print(f"    Root: {root_path}")
        
        count = 0
        try:
            if recursive:
                for dirpath, dirnames, filenames in os.walk(root_path):
                    for filename in filenames:
                        filepath = os.path.join(dirpath, filename)
                        event = self._get_file_events(filepath)
                        if event:
                            events.extend(event)
                            count += 1
                            if count % 1000 == 0:
                                print(f"  Processed {count} files...")
            else:
                for filename in os.listdir(root_path):
                    filepath = os.path.join(root_path, filename)
                    if os.path.isfile(filepath):
                        event = self._get_file_events(filepath)
                        if event:
                            events.extend(event)
                            count += 1
            
            print(f"[+] Timeline: {len(events)} events from {count} files")
            
        except Exception as e:
            self.logger.error(f"Timeline generation failed: {e}")
        
        self.events.extend(events)
        return events
    
    def _get_file_events(self, filepath: str) -> List[Dict]:
        """Extract timeline events from a single file."""
        events = []
        
        try:
            stat = os.stat(filepath)
            
            # File modified time
            mtime = datetime.fromtimestamp(stat.st_mtime)
            events.append({
                "timestamp": mtime.isoformat(),
                "type": "FILE_MODIFIED",
                "path": filepath,
                "size": stat.st_size,
                "source": "filesystem"
            })
            
            # File accessed time
            atime = datetime.fromtimestamp(stat.st_atime)
            events.append({
                "timestamp": atime.isoformat(),
                "type": "FILE_ACCESSED",
                "path": filepath,
                "size": stat.st_size,
                "source": "filesystem"
            })
            
            # File created/changed time
            ctime = datetime.fromtimestamp(stat.st_ctime)
            events.append({
                "timestamp": ctime.isoformat(),
                "type": "FILE_CREATED",
                "path": filepath,
                "size": stat.st_size,
                "source": "filesystem"
            })
            
        except Exception as e:
            self.logger.debug(f"File stat error: {e}")
        
        return events
    
    def add_custom_event(self, timestamp: str, event_type: str, 
                         description: str, source: str = "custom"):
        """Add a custom event to the timeline."""
        self.events.append({
            "timestamp": timestamp,
            "type": event_type,
            "description": description,
            "source": source
        })
    
    def add_browser_events(self, browser_data: List[Dict]):
        """Add browser history events to timeline."""
        for entry in browser_data:
            if entry.get("last_visit"):
                self.events.append({
                    "timestamp": entry["last_visit"],
                    "type": "BROWSER_VISIT",
                    "description": f"Visited: {entry.get('url', 'Unknown')}",
                    "source": "browser"
                })
    
    def add_registry_events(self, registry_data: Dict):
        """Add registry timestamp events to timeline."""
        if "sam_users" in registry_data:
            for user in registry_data["sam_users"]:
                if user.get("last_login"):
                    self.events.append({
                        "timestamp": str(user["last_login"]),
                        "type": "USER_LOGIN",
                        "description": f"User login: {user.get('username', 'Unknown')}",
                        "source": "registry"
                    })
                if user.get("password_set"):
                    self.events.append({
                        "timestamp": str(user["password_set"]),
                        "type": "PASSWORD_CHANGE",
                        "description": f"Password changed: {user.get('username', 'Unknown')}",
                        "source": "registry"
                    })
    
    def sort_timeline(self, ascending: bool = True) -> List[Dict]:
        """Sort events chronologically."""
        self.events.sort(
            key=lambda x: x.get("timestamp", ""),
            reverse=not ascending
        )
        return self.events
    
    def filter_by_date(self, start_date: str, end_date: str) -> List[Dict]:
        """Filter events by date range."""
        filtered = []
        for event in self.events:
            ts = event.get("timestamp", "")
            if ts and start_date <= ts <= end_date:
                filtered.append(event)
        return filtered
    
    def filter_by_type(self, event_type: str) -> List[Dict]:
        """Filter events by type."""
        return [e for e in self.events if e.get("type") == event_type]
    
    def filter_by_source(self, source: str) -> List[Dict]:
        """Filter events by source."""
        return [e for e in self.events if e.get("source") == source]
    
    def search(self, keyword: str) -> List[Dict]:
        """Search events by keyword."""
        keyword_lower = keyword.lower()
        results = []
        for event in self.events:
            desc = event.get("description", "") + event.get("path", "")
            if keyword_lower in desc.lower():
                results.append(event)
        return results
    
    def get_statistics(self) -> Dict:
        """Get timeline statistics."""
        if not self.events:
            return {"total_events": 0}
        
        timestamps = [e.get("timestamp", "") for e in self.events if e.get("timestamp")]
        
        event_types = {}
        sources = {}
        
        for e in self.events:
            etype = e.get("type", "UNKNOWN")
            source = e.get("source", "UNKNOWN")
            event_types[etype] = event_types.get(etype, 0) + 1
            sources[source] = sources.get(source, 0) + 1
        
        return {
            "total_events": len(self.events),
            "date_range": {
                "first": min(timestamps) if timestamps else None,
                "last": max(timestamps) if timestamps else None
            },
            "event_types": event_types,
            "sources": sources
        }
    
    def display_timeline(self, limit: int = 50):
        """Display timeline events."""
        if not self.events:
            print("\n[!] No timeline events.\n")
            return
        
        self.sort_timeline()
        
        print(f"\n[Forensic Timeline]")
        print(f"{'='*90}")
        print(f"{'Timestamp':<22} {'Type':<20} {'Description'}")
        print(f"{'='*90}")
        
        for event in self.events[:limit]:
            ts = event.get("timestamp", "N/A")[:19]
            etype = event.get("type", "?")[:19]
            desc = event.get("description", event.get("path", "?"))[:45]
            
            print(f"{ts:<22} {etype:<20} {desc}")
        
        if len(self.events) > limit:
            print(f"  ... and {len(self.events) - limit} more events")
        
        print(f"{'='*90}")
        print(f"Total: {len(self.events)} events\n")
    
    def export_csv(self, output_file: str):
        """Export timeline to CSV."""
        import csv
        
        self.sort_timeline()
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Type", "Description", "Source", "Path", "Size"])
            
            for event in self.events:
                writer.writerow([
                    event.get("timestamp", ""),
                    event.get("type", ""),
                    event.get("description", ""),
                    event.get("source", ""),
                    event.get("path", ""),
                    event.get("size", "")
                ])
        
        print(f"[+] Timeline exported: {output_file}")
    
    def clear(self):
        """Clear all timeline events."""
        self.events.clear()
