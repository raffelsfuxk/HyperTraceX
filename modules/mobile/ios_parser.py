#!/usr/bin/env python3
"""HyperTraceX iOS Parser - Extract forensic artifacts from iOS backups and file systems."""

import os
import re
import sqlite3
import json
import plistlib
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class iOSParser:
    """
    iOS Forensic Artifact Parser.
    
    Extracts data from:
        - iTunes backups (plist, SQLite)
        - iOS file system dumps
        - iCloud backups
        - Keychain data
        - Health data
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "contacts": [],
            "sms": [],
            "calls": [],
            "notes": [],
            "photos": [],
            "safari": [],
            "wifi": [],
            "accounts": [],
            "keychain": []
        }
    
    def parse_backup_info(self, backup_path: str) -> Optional[Dict]:
        """Parse iTunes backup manifest."""
        manifest_file = os.path.join(backup_path, "Manifest.plist")
        info_file = os.path.join(backup_path, "Info.plist")
        
        backup_info = {
            "backup_path": backup_path,
            "device_info": {},
            "installed_apps": [],
            "backup_date": None
        }
        
        if os.path.exists(info_file):
            try:
                with open(info_file, 'rb') as f:
                    info = plistlib.load(f)
                    backup_info["device_info"] = {
                        "device_name": info.get("Device Name", "Unknown"),
                        "product_type": info.get("Product Type", "Unknown"),
                        "ios_version": info.get("Product Version", "Unknown"),
                        "serial": info.get("Serial Number", "Unknown"),
                        "imei": info.get("IMEI", "Unknown"),
                        "phone_number": info.get("Phone Number", "Unknown"),
                        "last_backup": info.get("Last Backup Date", None)
                    }
                    if backup_info["device_info"]["last_backup"]:
                        backup_info["backup_date"] = backup_info["device_info"]["last_backup"].isoformat()
            except Exception as e:
                self.logger.error(f"Info.plist parse error: {e}")
        
        if os.path.exists(manifest_file):
            try:
                with open(manifest_file, 'rb') as f:
                    manifest = plistlib.load(f)
                    apps = manifest.get("Applications", {})
                    for app_key, app_data in apps.items():
                        backup_info["installed_apps"].append({
                            "bundle_id": app_key,
                            "container": app_data.get("ApplicationContainer", ""),
                            "app_path": app_data.get("AppPath", "")
                        })
            except Exception as e:
                self.logger.error(f"Manifest.plist parse error: {e}")
        
        return backup_info
    
    def parse_contacts(self, backup_path: str) -> List[Dict]:
        """Extract contacts from iOS backup."""
        contacts = []
        
        # Contacts database
        contacts_db = os.path.join(backup_path, "31bb7ba8914766d4ba40d6dfb6113c8b614be442")
        if not os.path.exists(contacts_db):
            self.logger.warning("Contacts DB not found in backup")
            return contacts
        
        try:
            conn = sqlite3.connect(f"file:{contacts_db}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    ABPerson.ROWID,
                    ABPerson.first,
                    ABPerson.last,
                    ABPerson.organization,
                    ABPerson.department,
                    ABPerson.note,
                    ABPerson.birthday,
                    ABMultiValue.property_id,
                    ABMultiValue.value as contact_value,
                    ABMultiValue.label
                FROM ABPerson
                LEFT JOIN ABMultiValue ON ABPerson.ROWID = ABMultiValue.record_id
                ORDER BY ABPerson.last, ABPerson.first
            """)
            
            current_contact = None
            for row in cursor.fetchall():
                if current_contact is None or current_contact["rowid"] != row["ROWID"]:
                    if current_contact:
                        contacts.append(current_contact)
                    
                    current_contact = {
                        "rowid": row["ROWID"],
                        "first_name": row["first"],
                        "last_name": row["last"],
                        "organization": row["organization"],
                        "department": row["department"],
                        "note": row["note"],
                        "birthday": row["birthday"],
                        "phones": [],
                        "emails": []
                    }
                
                if row["property_id"] == 3:  # Phone
                    current_contact["phones"].append({
                        "number": row["contact_value"],
                        "label": row["label"]
                    })
                elif row["property_id"] == 4:  # Email
                    current_contact["emails"].append({
                        "email": row["contact_value"],
                        "label": row["label"]
                    })
            
            if current_contact:
                contacts.append(current_contact)
            
            conn.close()
            self.logger.info(f"Extracted {len(contacts)} iOS contacts")
            
        except Exception as e:
            self.logger.error(f"iOS contacts extraction failed: {e}")
        
        self.results["contacts"] = contacts
        return contacts
    
    def parse_sms(self, backup_path: str) -> List[Dict]:
        """Extract SMS/iMessage from iOS backup."""
        messages = []
        
        sms_db = os.path.join(backup_path, "3d0d7e5fb2ce288813306e4d4636395e047a3d28")
        if not os.path.exists(sms_db):
            self.logger.warning("SMS DB not found in backup")
            return messages
        
        try:
            conn = sqlite3.connect(f"file:{sms_db}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    message.ROWID,
                    message.guid,
                    message.text,
                    message.handle_id,
                    message.service,
                    message.date,
                    message.date_read,
                    message.is_from_me,
                    message.is_read,
                    handle.id as contact_number,
                    handle.country
                FROM message
                LEFT JOIN handle ON message.handle_id = handle.ROWID
                ORDER BY message.date DESC
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                msg = {
                    "id": row["ROWID"],
                    "guid": row["guid"],
                    "text": row["text"],
                    "contact": row["contact_number"],
                    "service": "iMessage" if row["service"] == "iMessage" else "SMS",
                    "date": datetime.fromtimestamp(row["date"] / 1000000000 + 978307200).isoformat() if row["date"] else None,
                    "read": bool(row["is_read"]),
                    "from_me": bool(row["is_from_me"]),
                    "country": row["country"]
                }
                messages.append(msg)
            
            conn.close()
            self.logger.info(f"Extracted {len(messages)} iOS messages")
            
        except Exception as e:
            self.logger.error(f"iOS SMS extraction failed: {e}")
        
        self.results["sms"] = messages
        return messages
    
    def parse_safari_history(self, backup_path: str) -> List[Dict]:
        """Extract Safari browser history."""
        history = []
        
        safari_db = os.path.join(backup_path, "e7413f185d679b3698d5e7488c8e4e6e1f85c8b1")
        if not os.path.exists(safari_db):
            return history
        
        try:
            conn = sqlite3.connect(f"file:{safari_db}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    history_item.ROWID,
                    history_item.url,
                    history_item.title,
                    history_item.visit_count,
                    history_visits.visit_time
                FROM history_items history_item
                LEFT JOIN history_visits ON history_item.ROWID = history_visits.history_item
                ORDER BY history_visits.visit_time DESC
                LIMIT 500
            """)
            
            for row in cursor.fetchall():
                entry = {
                    "id": row["ROWID"],
                    "url": row["url"],
                    "title": row["title"],
                    "visit_count": row["visit_count"],
                    "last_visit": datetime.fromtimestamp(row["visit_time"] + 978307200).isoformat() if row["visit_time"] else None
                }
                history.append(entry)
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Safari history extraction failed: {e}")
        
        self.results["safari"] = history
        return history
    
    def parse_notes(self, backup_path: str) -> List[Dict]:
        """Extract Notes from iOS backup."""
        notes = []
        
        notes_db = os.path.join(backup_path, "4f98687d8ab0d6d1a371110e6b7300f2e465b984")
        if not os.path.exists(notes_db):
            return notes
        
        try:
            conn = sqlite3.connect(f"file:{notes_db}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    Z_PK,
                    ZTITLE,
                    ZSNIPPET,
                    ZCREATIONDATE,
                    ZMODIFICATIONDATE
                FROM ZNOTE
                ORDER BY ZMODIFICATIONDATE DESC
                LIMIT 200
            """)
            
            for row in cursor.fetchall():
                note = {
                    "id": row["Z_PK"],
                    "title": row["ZTITLE"],
                    "snippet": row["ZSNIPPET"][:100] if row["ZSNIPPET"] else "",
                    "created": row["ZCREATIONDATE"],
                    "modified": row["ZMODIFICATIONDATE"]
                }
                notes.append(note)
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Notes extraction failed: {e}")
        
        self.results["notes"] = notes
        return notes
    
    def parse_wifi_networks(self, backup_path: str) -> List[Dict]:
        """Extract known WiFi networks."""
        networks = []
        
        # Search for com.apple.wifi.plist
        for root, _, files in os.walk(backup_path):
            for file in files:
                if file == "com.apple.wifi.plist":
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'rb') as f:
                            wifi_data = plistlib.load(f)
                            if "List of known networks" in wifi_data:
                                for net in wifi_data["List of known networks"]:
                                    networks.append({
                                        "ssid": str(net.get("SSID_STR", "Unknown")),
                                        "bssid": net.get("BSSID", ""),
                                        "last_joined": net.get("lastJoined", None)
                                    })
                    except:
                        pass
        
        self.results["wifi"] = networks
        return networks
    
    def get_all_results(self) -> Dict:
        return self.results
    
    def display_summary(self):
        print(f"\n[iOS Forensic Summary]")
        print(f"{'='*50}")
        print(f"  Contacts:   {len(self.results.get('contacts', []))}")
        print(f"  SMS/iMsg:   {len(self.results.get('sms', []))}")
        print(f"  Safari:     {len(self.results.get('safari', []))}")
        print(f"  Notes:      {len(self.results.get('notes', []))}")
        print(f"  WiFi:       {len(self.results.get('wifi', []))}")
        print(f"  Accounts:   {len(self.results.get('accounts', []))}")
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Results exported: {output_file}")
