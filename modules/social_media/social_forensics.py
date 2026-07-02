#!/usr/bin/env python3
"""HyperTraceX Social Media Forensics - Extract social media artifacts from browsers and apps."""

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


class SocialForensics:
    """
    Social Media Forensic Analysis Module.
    
    Extracts artifacts from:
        - Facebook (browser cache, messages)
        - Instagram (browser cache, app data)
        - Twitter/X (browser cache)
        - LinkedIn (browser cache)
        - TikTok (browser cache, app data)
        - YouTube (history, searches)
    """
    
    # Social media domains and their patterns
    SOCIAL_PATTERNS = {
        "facebook": {
            "domains": ["facebook.com", "fb.com", "messenger.com"],
            "db_patterns": ["*facebook*.db", "*fb*.db", "*messenger*.db"]
        },
        "instagram": {
            "domains": ["instagram.com", "cdninstagram.com"],
            "db_patterns": ["*instagram*.db", "*insta*.db"]
        },
        "twitter": {
            "domains": ["twitter.com", "x.com", "twimg.com"],
            "db_patterns": ["*twitter*.db", "*tweet*.db"]
        },
        "linkedin": {
            "domains": ["linkedin.com", "licdn.com"],
            "db_patterns": ["*linkedin*.db"]
        },
        "tiktok": {
            "domains": ["tiktok.com", "tiktokcdn.com"],
            "db_patterns": ["*tiktok*.db", "*musical*.db"]
        },
        "youtube": {
            "domains": ["youtube.com", "youtu.be", "ytimg.com"],
            "db_patterns": ["*youtube*.db", "*yt*.db"]
        }
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "facebook": [],
            "instagram": [],
            "twitter": [],
            "linkedin": [],
            "tiktok": [],
            "youtube": [],
            "other": []
        }
    
    def extract_from_browser_history(self, history_data: List[Dict]) -> Dict:
        """
        Extract social media activity from browser history.
        
        Args:
            history_data: List of browser history entries with 'url' and 'last_visit' keys
        
        Returns:
            Dict with categorized social media visits
        """
        print(f"\n[*] Extracting social media from browser history...")
        
        for entry in history_data:
            url = entry.get("url", "")
            if not url:
                continue
            
            url_lower = url.lower()
            
            for platform, patterns in self.SOCIAL_PATTERNS.items():
                for domain in patterns["domains"]:
                    if domain in url_lower:
                        visit = {
                            "url": url,
                            "title": entry.get("title", ""),
                            "last_visit": entry.get("last_visit", ""),
                            "visit_count": entry.get("visit_count", 0),
                            "platform": platform
                        }
                        self.results[platform].append(visit)
                        break
        
        total_found = sum(len(v) for v in self.results.values())
        print(f"[+] Found {total_found} social media visits")
        
        return self.results
    
    def extract_from_cookies(self, cookies_data: List[Dict]) -> Dict:
        """
        Extract social media session data from cookies.
        
        Args:
            cookies_data: List of cookie entries with 'host' and 'name' keys
        """
        print(f"[*] Extracting social media from cookies...")
        
        for cookie in cookies_data:
            host = cookie.get("host", "").lower()
            
            for platform, patterns in self.SOCIAL_PATTERNS.items():
                for domain in patterns["domains"]:
                    if domain in host:
                        cookie["platform"] = platform
                        self.results[platform].append(cookie)
                        break
        
        return self.results
    
    def extract_from_databases(self, directory: str) -> Dict:
        """
        Scan directory for social media database files.
        
        Args:
            directory: Directory to scan for database files
        """
        if not os.path.exists(directory):
            return self.results
        
        print(f"[*] Scanning for social media databases...")
        
        for platform, patterns in self.SOCIAL_PATTERNS.items():
            for db_pattern in patterns["db_patterns"]:
                import glob
                search_pattern = os.path.join(directory, "**", db_pattern)
                matching_files = glob.glob(search_pattern, recursive=True)
                
                for db_file in matching_files[:5]:
                    self._parse_social_database(db_file, platform)
        
        return self.results
    
    def _parse_social_database(self, db_file: str, platform: str):
        """Parse a social media database file."""
        if not os.path.exists(db_file):
            return
        
        try:
            conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM {table} LIMIT 10")
                    rows = [dict(row) for row in cursor.fetchall()]
                    
                    for row in rows:
                        row["_platform"] = platform
                        row["_source_db"] = db_file
                        row["_table"] = table
                        self.results[platform].append(row)
                except:
                    pass
            
            conn.close()
            
        except Exception as e:
            self.logger.debug(f"Social DB parse error: {e}")
    
    def extract_from_search_history(self, search_data: List[Dict]) -> Dict:
        """Extract social media searches from search history."""
        search_keywords = {
            "facebook": ["facebook", "fb login", "messenger"],
            "instagram": ["instagram", "insta"],
            "twitter": ["twitter", "tweet", "x.com"],
            "youtube": ["youtube", "yt", "video"],
            "tiktok": ["tiktok", "tik tok"],
        }
        
        for entry in search_data:
            query = entry.get("query", entry.get("term", "")).lower()
            
            for platform, keywords in search_keywords.items():
                for kw in keywords:
                    if kw in query:
                        self.results[platform].append({
                            "query": query,
                            "timestamp": entry.get("timestamp", ""),
                            "platform": platform,
                            "type": "search"
                        })
                        break
        
        return self.results
    
    def find_private_messages(self) -> List[Dict]:
        """Find potential private message data."""
        messages = []
        
        for platform, data in self.results.items():
            for entry in data:
                if isinstance(entry, dict):
                    text = str(entry).lower()
                    if any(kw in text for kw in ["message", "chat", "conversation", "inbox", "thread"]):
                        messages.append({
                            "platform": platform,
                            "data": entry
                        })
        
        return messages
    
    def find_contacts(self) -> List[Dict]:
        """Find potential contact/friend lists."""
        contacts = []
        
        for platform, data in self.results.items():
            for entry in data:
                if isinstance(entry, dict):
                    text = str(entry).lower()
                    if any(kw in text for kw in ["friend", "contact", "follower", "following", "connection"]):
                        contacts.append({
                            "platform": platform,
                            "data": entry
                        })
        
        return contacts
    
    def get_statistics(self) -> Dict:
        """Get social media analysis statistics."""
        stats = {}
        total = 0
        
        for platform, data in self.results.items():
            count = len(data)
            stats[platform] = count
            total += count
        
        stats["total"] = total
        return stats
    
    def display_summary(self):
        """Display social media analysis summary."""
        stats = self.get_statistics()
        
        print(f"\n[Social Media Forensics Summary]")
        print(f"{'='*45}")
        print(f"  Facebook:   {stats.get('facebook', 0)}")
        print(f"  Instagram:  {stats.get('instagram', 0)}")
        print(f"  Twitter/X:  {stats.get('twitter', 0)}")
        print(f"  LinkedIn:   {stats.get('linkedin', 0)}")
        print(f"  TikTok:     {stats.get('tiktok', 0)}")
        print(f"  YouTube:    {stats.get('youtube', 0)}")
        print(f"  Other:      {stats.get('other', 0)}")
        print(f"  {'─'*35}")
        print(f"  TOTAL:      {stats.get('total', 0)}")
        print(f"{'='*45}\n")
    
    def export_json(self, output_file: str):
        """Export results to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Social media analysis exported: {output_file}")
