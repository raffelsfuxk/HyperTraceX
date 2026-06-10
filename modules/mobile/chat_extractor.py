#!/usr/bin/env python3
"""FORENSIX Chat Extractor - Extract messages from WhatsApp, Telegram, Signal, Discord, Slack."""

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
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class ChatExtractor:
    """
    Chat Application Forensic Extractor.
    
    Extracts conversations from:
        - WhatsApp (Android + iOS)
        - Telegram
        - Signal
        - Discord
        - Slack
        - Facebook Messenger
    """
    
    CHAT_DB_PATHS = {
        "whatsapp_android": "com.whatsapp/databases/msgstore.db",
        "whatsapp_ios": "ChatStorage.sqlite",
        "telegram": "org.telegram.messenger/databases/cache4.db",
        "signal": "org.thoughtcrime.securesms/databases/signal.db",
        "discord": "com.discord/databases/discord.db",
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "whatsapp": [],
            "telegram": [],
            "signal": [],
            "discord": [],
            "slack": []
        }
    
    def extract_whatsapp(self, db_path: str) -> List[Dict]:
        """Extract WhatsApp messages from database."""
        messages = []
        
        if not os.path.exists(db_path):
            self.logger.warning(f"WhatsApp DB not found: {db_path}")
            return messages
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    _id,
                    key_remote_jid,
                    key_from_me,
                    data,
                    timestamp,
                    received_timestamp,
                    message_type,
                    media_url,
                    latitude,
                    longitude,
                    duration
                FROM messages
                ORDER BY timestamp DESC
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                msg_type_map = {0: "TEXT", 1: "IMAGE", 2: "AUDIO", 3: "VIDEO", 4: "CONTACT", 5: "LOCATION"}
                
                msg = {
                    "id": row["_id"],
                    "chat_jid": row["key_remote_jid"],
                    "from_me": bool(row["key_from_me"]),
                    "text": row["data"],
                    "timestamp": datetime.fromtimestamp(row["timestamp"] / 1000).isoformat() if row["timestamp"] else None,
                    "received_at": datetime.fromtimestamp(row["received_timestamp"] / 1000).isoformat() if row["received_timestamp"] else None,
                    "type": msg_type_map.get(row["message_type"], "UNKNOWN"),
                    "media_url": row["media_url"],
                    "latitude": row["latitude"],
                    "longitude": row["longitude"],
                    "duration": row["duration"]
                }
                messages.append(msg)
            
            conn.close()
            self.logger.info(f"Extracted {len(messages)} WhatsApp messages")
            
        except Exception as e:
            self.logger.error(f"WhatsApp extraction failed: {e}")
        
        self.results["whatsapp"] = messages
        return messages
    
    def extract_telegram(self, db_path: str) -> List[Dict]:
        """Extract Telegram messages."""
        messages = []
        
        if not os.path.exists(db_path):
            self.logger.warning(f"Telegram DB not found: {db_path}")
            return messages
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    _id,
                    uid,
                    date,
                    message,
                    type,
                    read_state,
                    out
                FROM messages
                ORDER BY date DESC
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                msg = {
                    "id": row["_id"],
                    "user_id": row["uid"],
                    "text": row["message"],
                    "date": datetime.fromtimestamp(row["date"]).isoformat() if row["date"] else None,
                    "type": row["type"],
                    "read": bool(row["read_state"]),
                    "outgoing": bool(row["out"])
                }
                messages.append(msg)
            
            conn.close()
            self.logger.info(f"Extracted {len(messages)} Telegram messages")
            
        except Exception as e:
            self.logger.error(f"Telegram extraction failed: {e}")
        
        self.results["telegram"] = messages
        return messages
    
    def extract_signal(self, db_path: str) -> List[Dict]:
        """Extract Signal messages."""
        messages = []
        
        if not os.path.exists(db_path):
            return messages
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    _id,
                    thread_id,
                    address,
                    date_sent,
                    date_received,
                    body,
                    type,
                    read
                FROM sms
                ORDER BY date_sent DESC
                LIMIT 500
            """)
            
            for row in cursor.fetchall():
                msg = {
                    "id": row["_id"],
                    "thread_id": row["thread_id"],
                    "address": row["address"],
                    "sent_date": datetime.fromtimestamp(row["date_sent"] / 1000).isoformat() if row["date_sent"] else None,
                    "received_date": datetime.fromtimestamp(row["date_received"] / 1000).isoformat() if row["date_received"] else None,
                    "body": row["body"],
                    "type": row["type"],
                    "read": bool(row["read"])
                }
                messages.append(msg)
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Signal extraction failed: {e}")
        
        self.results["signal"] = messages
        return messages
    
    def extract_discord(self, db_path: str) -> List[Dict]:
        """Extract Discord messages from cache."""
        messages = []
        
        if not os.path.exists(db_path):
            return messages
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    message_id,
                    channel_id,
                    author_id,
                    content,
                    timestamp,
                    edited_timestamp,
                    tts,
                    pinned
                FROM messages
                ORDER BY timestamp DESC
                LIMIT 500
            """)
            
            for row in cursor.fetchall():
                msg = {
                    "message_id": row["message_id"],
                    "channel_id": row["channel_id"],
                    "author_id": row["author_id"],
                    "content": row["content"],
                    "timestamp": row["timestamp"],
                    "edited": row["edited_timestamp"],
                    "tts": bool(row["tts"]),
                    "pinned": bool(row["pinned"])
                }
                messages.append(msg)
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Discord extraction failed: {e}")
        
        self.results["discord"] = messages
        return messages
    
    def search_all(self, keyword: str) -> Dict[str, List]:
        """Search all chat platforms for keyword."""
        results = {}
        keyword_lower = keyword.lower()
        
        for platform, messages in self.results.items():
            matched = []
            for msg in messages:
                text = msg.get("text", msg.get("body", msg.get("content", "")))
                if text and keyword_lower in str(text).lower():
                    matched.append(msg)
            if matched:
                results[platform] = matched
        
        return results
    
    def search_by_date(self, start_date: str, end_date: str) -> Dict[str, List]:
        """Search messages by date range."""
        results = {}
        
        for platform, messages in self.results.items():
            matched = []
            for msg in messages:
                msg_date = msg.get("timestamp") or msg.get("date") or msg.get("sent_date")
                if msg_date and start_date <= str(msg_date)[:19] <= end_date:
                    matched.append(msg)
            if matched:
                results[platform] = matched
        
        return results
    
    def get_contact_list(self) -> Dict[str, List[str]]:
        """Get unique contacts from all platforms."""
        contacts = {}
        
        for platform, messages in self.results.items():
            unique_contacts = set()
            for msg in messages:
                contact = msg.get("chat_jid") or msg.get("address") or msg.get("author_id")
                if contact:
                    unique_contacts.add(contact)
            contacts[platform] = list(unique_contacts)
        
        return contacts
    
    def get_statistics(self) -> Dict:
        """Get chat extraction statistics."""
        stats = {}
        total_messages = 0
        
        for platform, messages in self.results.items():
            count = len(messages)
            stats[platform] = count
            total_messages += count
        
        stats["total"] = total_messages
        return stats
    
    def display_summary(self):
        """Display extraction summary."""
        stats = self.get_statistics()
        
        print(f"\n[Chat Extraction Summary]")
        print(f"{'='*45}")
        print(f"  WhatsApp:  {stats.get('whatsapp', 0)}")
        print(f"  Telegram:  {stats.get('telegram', 0)}")
        print(f"  Signal:    {stats.get('signal', 0)}")
        print(f"  Discord:   {stats.get('discord', 0)}")
        print(f"  Slack:     {stats.get('slack', 0)}")
        print(f"  {'─'*35}")
        print(f"  TOTAL:     {stats.get('total', 0)}")
        print(f"{'='*45}\n")
    
    def export_json(self, output_file: str):
        """Export all results to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Results exported: {output_file}")
    
    def export_csv(self, output_file: str):
        """Export to CSV format."""
        import csv
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Platform", "ID", "Contact", "Text", "Date", "Type"])
            
            for platform, messages in self.results.items():
                for msg in messages:
                    writer.writerow([
                        platform,
                        msg.get("id", ""),
                        msg.get("chat_jid") or msg.get("address") or msg.get("author_id", ""),
                        msg.get("text") or msg.get("body") or msg.get("content", ""),
                        msg.get("timestamp") or msg.get("date") or msg.get("sent_date", ""),
                        msg.get("type", "TEXT")
                    ])
        print(f"[+] CSV exported: {output_file}")
