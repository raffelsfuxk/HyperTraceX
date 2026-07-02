#!/usr/bin/env python3
"""HyperTraceX Browser Forensics - Extract browser artifacts (history, cookies, passwords, downloads)."""

import os
import sqlite3
import json
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class BrowserForensics:
    """
    Browser Artifact Extractor.
    
    Supports Chrome, Firefox, Edge, Brave, Opera.
    Extracts history, cookies, passwords, downloads, bookmarks.
    """
    
    # Browser data paths relative to user profile
    BROWSER_PATHS = {
        "chrome": {
            "history": "Google/Chrome/User Data/Default/History",
            "cookies": "Google/Chrome/User Data/Default/Cookies",
            "passwords": "Google/Chrome/User Data/Default/Login Data",
            "bookmarks": "Google/Chrome/User Data/Default/Bookmarks",
            "downloads": "Google/Chrome/User Data/Default/History",
        },
        "firefox": {
            "history": "Mozilla/Firefox/Profiles",
            "cookies": "Mozilla/Firefox/Profiles",
            "passwords": "Mozilla/Firefox/Profiles",
            "bookmarks": "Mozilla/Firefox/Profiles",
            "downloads": "Mozilla/Firefox/Profiles",
        },
        "edge": {
            "history": "Microsoft/Edge/User Data/Default/History",
            "cookies": "Microsoft/Edge/User Data/Default/Cookies",
            "passwords": "Microsoft/Edge/User Data/Default/Login Data",
            "bookmarks": "Microsoft/Edge/User Data/Default/Bookmarks",
        },
        "brave": {
            "history": "BraveSoftware/Brave-Browser/User Data/Default/History",
            "cookies": "BraveSoftware/Brave-Browser/User Data/Default/Cookies",
            "passwords": "BraveSoftware/Brave-Browser/User Data/Default/Login Data",
            "bookmarks": "BraveSoftware/Brave-Browser/User Data/Default/Bookmarks",
        },
        "opera": {
            "history": "Opera Software/Opera Stable/Default/History",
            "cookies": "Opera Software/Opera Stable/Default/Cookies",
            "passwords": "Opera Software/Opera Stable/Default/Login Data",
            "bookmarks": "Opera Software/Opera Stable/Default/Bookmarks",
        }
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, Dict] = {}
    
    def extract_all(self, profile_path: str, browsers: List[str] = None,
                    copy_first: bool = True, output_dir: str = None) -> Dict:
        """
        Extract all browser artifacts.
        
        Args:
            profile_path: Path to Users folder (e.g., /mnt/Windows/Users)
            browsers: List of browsers to extract (None = all)
            copy_first: Copy DB files before reading (avoids locks)
            output_dir: Output directory for copied files
        
        Returns:
            Dict with all extracted data per browser per user
        """
        if not os.path.exists(profile_path):
            self.logger.error(f"Profile path not found: {profile_path}")
            return {}
        
        if browsers is None:
            browsers = list(self.BROWSER_PATHS.keys())
        
        print(f"\n[*] Starting Browser Forensics Extraction")
        print(f"    Profile: {profile_path}")
        print(f"    Browsers: {', '.join(browsers)}\n")
        
        self.results.clear()
        
        # Find all user directories
        users = [d for d in os.listdir(profile_path) 
                if os.path.isdir(os.path.join(profile_path, d)) 
                and d not in ["Public", "Default", "All Users"]]
        
        for user in users:
            user_path = os.path.join(profile_path, user)
            appdata_local = os.path.join(user_path, "AppData", "Local")
            appdata_roaming = os.path.join(user_path, "AppData", "Roaming")
            
            if not os.path.exists(appdata_local):
                continue
            
            self.results[user] = {}
            
            for browser in browsers:
                if browser not in self.BROWSER_PATHS:
                    continue
                
                paths = self.BROWSER_PATHS[browser]
                browser_data = {}
                
                # Determine base path
                if browser in ["chrome", "edge", "brave", "opera"]:
                    base = appdata_local
                else:
                    base = appdata_roaming
                
                # Chrome-based browsers (History is SQLite)
                if browser != "firefox":
                    self._extract_chromium(browser, base, paths, browser_data, copy_first, output_dir)
                else:
                    self._extract_firefox(base, paths, browser_data, copy_first, output_dir)
                
                if browser_data:
                    self.results[user][browser] = browser_data
                    
                    total_entries = sum(
                        len(v) if isinstance(v, list) else 1 
                        for v in browser_data.values()
                    )
                    print(f"  [{user}] {browser.title()}: {len(browser_data)} artifact types extracted")
        
        return self.results
    
    def _extract_chromium(self, browser: str, base_path: str, paths: Dict,
                          results: Dict, copy_first: bool, output_dir: str = None):
        """Extract Chromium-based browser artifacts."""
        
        for artifact_type, rel_path in paths.items():
            full_path = os.path.join(base_path, rel_path)
            
            if not os.path.exists(full_path):
                continue
            
            if artifact_type == "bookmarks":
                data = self._parse_chrome_bookmarks(full_path)
                if data:
                    results["bookmarks"] = data
            
            elif artifact_type in ["history", "cookies", "passwords", "downloads"]:
                if copy_first and output_dir:
                    os.makedirs(output_dir, exist_ok=True)
                    tmp_path = os.path.join(output_dir, f"{browser}_{artifact_type}.db")
                    shutil.copy2(full_path, tmp_path)
                    full_path = tmp_path
                
                if artifact_type == "history":
                    data = self._parse_chrome_history(full_path)
                    if data:
                        results["history"] = data
                
                elif artifact_type == "cookies":
                    data = self._parse_chrome_cookies(full_path)
                    if data:
                        results["cookies"] = data
                
                elif artifact_type == "passwords":
                    data = self._parse_chrome_passwords(full_path)
                    if data:
                        results["passwords"] = data
    
    def _extract_firefox(self, base_path: str, paths: Dict,
                         results: Dict, copy_first: bool, output_dir: str = None):
        """Extract Firefox browser artifacts."""
        
        profiles_dir = os.path.join(base_path, "Mozilla", "Firefox", "Profiles")
        if not os.path.exists(profiles_dir):
            return
        
        for profile in os.listdir(profiles_dir):
            profile_path = os.path.join(profiles_dir, profile)
            if not os.path.isdir(profile_path):
                continue
            
            places_db = os.path.join(profile_path, "places.sqlite")
            if os.path.exists(places_db):
                if copy_first and output_dir:
                    os.makedirs(output_dir, exist_ok=True)
                    tmp_path = os.path.join(output_dir, f"firefox_{profile}_places.sqlite")
                    shutil.copy2(places_db, tmp_path)
                    places_db = tmp_path
                
                history = self._parse_firefox_history(places_db)
                if history:
                    results["history"] = history
            
            cookies_db = os.path.join(profile_path, "cookies.sqlite")
            if os.path.exists(cookies_db):
                cookies = self._parse_firefox_cookies(cookies_db)
                if cookies:
                    results["cookies"] = cookies
    
    def _parse_chrome_history(self, db_path: str) -> List[Dict]:
        """Parse Chrome/Chromium history database."""
        entries = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT 500
            """)
            
            for row in cursor.fetchall():
                # Chrome timestamp: microseconds since 1601-01-01
                try:
                    ts = datetime(1601, 1, 1) + timedelta(microseconds=row["last_visit_time"])
                except:
                    ts = None
                
                entries.append({
                    "url": row["url"],
                    "title": row["title"],
                    "visit_count": row["visit_count"],
                    "last_visit": ts.isoformat() if ts else "N/A"
                })
            
            conn.close()
        except Exception as e:
            self.logger.debug(f"Chrome history parse error: {e}")
        
        return entries
    
    def _parse_chrome_cookies(self, db_path: str) -> List[Dict]:
        """Parse Chrome/Chromium cookies database."""
        entries = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT host_key, name, value, creation_utc, expires_utc, last_access_utc
                FROM cookies
                ORDER BY last_access_utc DESC
                LIMIT 200
            """)
            
            for row in cursor.fetchall():
                entries.append({
                    "host": row["host_key"],
                    "name": row["name"],
                    "value": row["value"][:50] if row["value"] else "",
                    "created": self._chrome_time(row["creation_utc"]),
                    "expires": self._chrome_time(row["expires_utc"]),
                    "last_access": self._chrome_time(row["last_access_utc"])
                })
            
            conn.close()
        except Exception as e:
            self.logger.debug(f"Chrome cookies parse error: {e}")
        
        return entries
    
    def _parse_chrome_passwords(self, db_path: str) -> List[Dict]:
        """Parse Chrome/Chromium passwords database."""
        entries = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT origin_url, username_value, password_value, date_created, times_used
                FROM logins
                ORDER BY times_used DESC
            """)
            
            for row in cursor.fetchall():
                entries.append({
                    "url": row["origin_url"],
                    "username": row["username_value"],
                    "password_encrypted": "Yes" if row["password_value"] else "No",
                    "times_used": row["times_used"]
                })
            
            conn.close()
        except Exception as e:
            self.logger.debug(f"Chrome passwords parse error: {e}")
        
        return entries
    
    def _parse_chrome_bookmarks(self, filepath: str) -> Dict:
        """Parse Chrome/Chromium bookmarks JSON."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            bookmarks = []
            
            def extract_bookmarks(node, path=""):
                if node.get("type") == "url":
                    bookmarks.append({
                        "name": node.get("name", ""),
                        "url": node.get("url", ""),
                        "path": path
                    })
                elif node.get("type") == "folder":
                    folder_name = node.get("name", "")
                    new_path = f"{path}/{folder_name}" if path else folder_name
                    for child in node.get("children", []):
                        extract_bookmarks(child, new_path)
            
            roots = data.get("roots", {})
            for root_name, root_node in roots.items():
                extract_bookmarks(root_node, root_name)
            
            return {"count": len(bookmarks), "bookmarks": bookmarks[:100]}
        except:
            return {}
    
    def _parse_firefox_history(self, db_path: str) -> List[Dict]:
        """Parse Firefox places.sqlite."""
        entries = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT url, title, visit_count, last_visit_date
                FROM moz_places
                WHERE last_visit_date IS NOT NULL
                ORDER BY last_visit_date DESC
                LIMIT 500
            """)
            
            for row in cursor.fetchall():
                # Firefox timestamp: microseconds since 1970-01-01
                try:
                    ts = datetime(1970, 1, 1) + timedelta(microseconds=row["last_visit_date"])
                except:
                    ts = None
                
                entries.append({
                    "url": row["url"],
                    "title": row["title"],
                    "visit_count": row["visit_count"],
                    "last_visit": ts.isoformat() if ts else "N/A"
                })
            
            conn.close()
        except Exception as e:
            self.logger.debug(f"Firefox history parse error: {e}")
        
        return entries
    
    def _parse_firefox_cookies(self, db_path: str) -> List[Dict]:
        """Parse Firefox cookies.sqlite."""
        entries = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT host, name, value, expiry, lastAccessed
                FROM moz_cookies
                ORDER BY lastAccessed DESC
                LIMIT 200
            """)
            
            for row in cursor.fetchall():
                entries.append({
                    "host": row["host"],
                    "name": row["name"],
                    "value": row["value"][:50] if row["value"] else "",
                    "expiry": row["expiry"],
                    "last_access": row["lastAccessed"]
                })
            
            conn.close()
        except Exception as e:
            self.logger.debug(f"Firefox cookies parse error: {e}")
        
        return entries
    
    def _chrome_time(self, timestamp):
        """Convert Chrome timestamp to datetime."""
        if not timestamp or timestamp == 0:
            return "N/A"
        try:
            return (datetime(1601, 1, 1) + timedelta(microseconds=timestamp)).isoformat()
        except:
            return "N/A"
    
    def get_summary(self) -> Dict:
        """Get extraction summary."""
        summary = {}
        for user, browsers in self.results.items():
            summary[user] = {}
            for browser, artifacts in browsers.items():
                summary[user][browser] = {
                    k: len(v) if isinstance(v, list) else "1" 
                    for k, v in artifacts.items()
                }
        return summary
    
    def display_summary(self):
        """Display extraction summary."""
        summary = self.get_summary()
        if not summary:
            print("\n[!] No browser data extracted.\n")
            return
        
        print(f"\n[Browser Forensics Summary]")
        print(f"{'='*60}")
        for user, browsers in summary.items():
            print(f"\n  User: {user}")
            for browser, artifacts in browsers.items():
                print(f"    {browser.title()}:")
                for artifact, count in artifacts.items():
                    print(f"      - {artifact}: {count} entries")
        print(f"\n{'='*60}\n")
