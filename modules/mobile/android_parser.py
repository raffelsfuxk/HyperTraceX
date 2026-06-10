#!/usr/bin/env python3
"""FORENSIX Android Parser - Extract forensic artifacts from Android devices and backups."""

import os
import re
import sqlite3
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class AndroidParser:
    """
    Android Forensic Artifact Parser.
    
    Extracts data from:
        - ADB backups (.ab files)
        - APK files
        - Android file system dumps
        - SQLite databases (contacts, SMS, call logs)
        - Shared preferences XML
    """
    
    # Common Android database paths
    ANDROID_DB_PATHS = {
        "contacts": "com.android.providers.contacts/databases/contacts2.db",
        "sms_mms": "com.android.providers.telephony/databases/mmssms.db",
        "call_logs": "com.android.providers.contacts/databases/calllog.db",
        "calendar": "com.android.providers.calendar/databases/calendar.db",
        "browser_history": "com.android.browser/databases/browser2.db",
        "chrome_history": "com.android.chrome/app_chrome/Default/History",
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "contacts": [],
            "sms": [],
            "call_logs": [],
            "calendar": [],
            "browser": [],
            "apps": [],
            "wifi": [],
            "accounts": []
        }
    
    def parse_contacts_db(self, db_path: str) -> List[Dict]:
        """Extract contacts from Android contacts database."""
        contacts = []
        
        if not os.path.exists(db_path):
            self.logger.error(f"Contacts DB not found: {db_path}")
            return contacts
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    c._id,
                    c.display_name,
                    c.times_contacted,
                    c.last_time_contacted,
                    d.data1 as phone_number,
                    d.data2 as phone_type,
                    e.data1 as email
                FROM contacts c
                LEFT JOIN data d ON c._id = d.raw_contact_id AND d.mimetype_id = (
                    SELECT _id FROM mimetypes WHERE mimetype = 'vnd.android.cursor.item/phone_v2'
                )
                LEFT JOIN data e ON c._id = e.raw_contact_id AND e.mimetype_id = (
                    SELECT _id FROM mimetypes WHERE mimetype = 'vnd.android.cursor.item/email_v2'
                )
                ORDER BY c.display_name
            """)
            
            for row in cursor.fetchall():
                contact = {
                    "id": row["_id"],
                    "name": row["display_name"],
                    "phone": row["phone_number"],
                    "phone_type": row["phone_type"],
                    "email": row["email"],
                    "times_contacted": row["times_contacted"],
                    "last_contacted": row["last_time_contacted"]
                }
                contacts.append(contact)
            
            conn.close()
            self.logger.info(f"Extracted {len(contacts)} contacts")
            
        except Exception as e:
            self.logger.error(f"Contacts extraction failed: {e}")
        
        self.results["contacts"] = contacts
        return contacts
    
    def parse_sms_db(self, db_path: str) -> List[Dict]:
        """Extract SMS/MMS messages from Android SMS database."""
        messages = []
        
        if not os.path.exists(db_path):
            self.logger.error(f"SMS DB not found: {db_path}")
            return messages
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    _id,
                    address,
                    date,
                    date_sent,
                    read,
                    type,
                    body,
                    seen
                FROM sms
                ORDER BY date DESC
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                msg_type = "INBOX" if row["type"] == 1 else "SENT" if row["type"] == 2 else "DRAFT"
                
                msg = {
                    "id": row["_id"],
                    "address": row["address"],
                    "date": datetime.fromtimestamp(row["date"] / 1000).isoformat() if row["date"] else None,
                    "read": bool(row["read"]),
                    "type": msg_type,
                    "body": row["body"],
                    "seen": bool(row["seen"])
                }
                messages.append(msg)
            
            conn.close()
            self.logger.info(f"Extracted {len(messages)} messages")
            
        except Exception as e:
            self.logger.error(f"SMS extraction failed: {e}")
        
        self.results["sms"] = messages
        return messages
    
    def parse_call_logs(self, db_path: str) -> List[Dict]:
        """Extract call logs from Android call log database."""
        calls = []
        
        if not os.path.exists(db_path):
            self.logger.error(f"Call log DB not found: {db_path}")
            return calls
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    _id,
                    number,
                    date,
                    duration,
                    type,
                    name
                FROM calls
                ORDER BY date DESC
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                call_type_map = {1: "INCOMING", 2: "OUTGOING", 3: "MISSED"}
                
                call = {
                    "id": row["_id"],
                    "number": row["number"],
                    "name": row["name"],
                    "date": datetime.fromtimestamp(row["date"] / 1000).isoformat() if row["date"] else None,
                    "duration_seconds": row["duration"],
                    "type": call_type_map.get(row["type"], "UNKNOWN")
                }
                calls.append(call)
            
            conn.close()
            self.logger.info(f"Extracted {len(calls)} call logs")
            
        except Exception as e:
            self.logger.error(f"Call log extraction failed: {e}")
        
        self.results["call_logs"] = calls
        return calls
    
    def parse_wifi_configs(self, wifi_path: str) -> List[Dict]:
        """Extract saved WiFi networks from Android."""
        networks = []
        
        wifi_file = os.path.join(wifi_path, "wpa_supplicant.conf")
        if not os.path.exists(wifi_file):
            return networks
        
        try:
            with open(wifi_file, 'r') as f:
                content = f.read()
            
            # Parse network blocks
            network_blocks = re.findall(r'network=\{([^}]+)\}', content)
            
            for block in network_blocks:
                ssid_match = re.search(r'ssid="([^"]+)"', block)
                psk_match = re.search(r'psk="([^"]+)"', block)
                key_match = re.search(r'key_mgmt=(\S+)', block)
                
                network = {
                    "ssid": ssid_match.group(1) if ssid_match else "Unknown",
                    "password": psk_match.group(1) if psk_match else None,
                    "key_management": key_match.group(1) if key_match else "N/A"
                }
                networks.append(network)
            
            self.logger.info(f"Extracted {len(networks)} WiFi networks")
            
        except Exception as e:
            self.logger.error(f"WiFi extraction failed: {e}")
        
        self.results["wifi"] = networks
        return networks
    
    def parse_installed_apps(self, apps_path: str) -> List[Dict]:
        """Extract installed application list."""
        apps = []
        
        # Try package list file
        packages_file = os.path.join(apps_path, "packages.list")
        if os.path.exists(packages_file):
            try:
                with open(packages_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 1:
                            apps.append({
                                "package": parts[0],
                                "uid": parts[1] if len(parts) > 1 else "",
                                "source": "packages.list"
                            })
            except:
                pass
        
        self.results["apps"] = apps
        return apps
    
    def get_all_results(self) -> Dict:
        """Get all extracted results."""
        return self.results
    
    def display_summary(self):
        """Display extraction summary."""
        print(f"\n[Android Forensic Summary]")
        print(f"{'='*50}")
        print(f"  Contacts:   {len(self.results.get('contacts', []))}")
        print(f"  SMS:        {len(self.results.get('sms', []))}")
        print(f"  Call Logs:  {len(self.results.get('call_logs', []))}")
        print(f"  Calendar:   {len(self.results.get('calendar', []))}")
        print(f"  WiFi Nets:  {len(self.results.get('wifi', []))}")
        print(f"  Apps:       {len(self.results.get('apps', []))}")
        print(f"  Accounts:   {len(self.results.get('accounts', []))}")
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        """Export all results to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Results exported: {output_file}")
