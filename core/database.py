#!/usr/bin/env python3
"""Database Manager for HyperTraceX Framework - SQLite Case & Evidence Management."""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional, Any

class DatabaseManager:
    """Handle case management, evidence tracking, and audit logging."""
    
    def __init__(self, db_path: str = "tracex.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_tables()
    
    def _init_tables(self):
        cursor = self.conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT UNIQUE NOT NULL,
                investigator TEXT NOT NULL,
                organization TEXT DEFAULT '',
                description TEXT DEFAULT '',
                status TEXT DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                closed_at TEXT
            );
            
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                original_path TEXT,
                file_size INTEGER DEFAULT 0,
                md5_hash TEXT DEFAULT '',
                sha1_hash TEXT DEFAULT '',
                sha256_hash TEXT DEFAULT '',
                file_type TEXT DEFAULT '',
                acquired_at TEXT NOT NULL,
                source_drive TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS custody_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                handler TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                location TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                hash_before TEXT DEFAULT '',
                hash_after TEXT DEFAULT '',
                FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                action TEXT NOT NULL,
                user TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT DEFAULT '',
                ip_address TEXT DEFAULT '',
                FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL
            );
            
            CREATE TABLE IF NOT EXISTS acquisition_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                task_type TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                progress INTEGER DEFAULT 0,
                started_at TEXT,
                completed_at TEXT,
                error_message TEXT DEFAULT '',
                FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
            );
        """)
        self.conn.commit()
    
    # Case Management
    def create_case(self, case_id: str, investigator: str, 
                    organization: str = "", description: str = "") -> int:
        now = datetime.now().isoformat()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO cases (case_id, investigator, organization, description, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (case_id, investigator, organization, description, now, now))
        self.conn.commit()
        return cursor.lastrowid
    
    def close_case(self, case_id: str):
        now = datetime.now().isoformat()
        self.conn.execute("""
            UPDATE cases SET status = 'closed', updated_at = ?, closed_at = ?
            WHERE case_id = ?
        """, (now, now, case_id))
        self.conn.commit()
    
    def get_case(self, case_id: str) -> Optional[Dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_all_cases(self) -> List[Dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cases ORDER BY created_at DESC")
        return [dict(row) for row in cursor.fetchall()]
    
    # Evidence Management
    def add_evidence(self, case_id: int, file_path: str, original_path: str = "",
                     file_size: int = 0, md5: str = "", sha1: str = "", 
                     sha256: str = "", file_type: str = "", source_drive: str = "") -> int:
        now = datetime.now().isoformat()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO evidence (case_id, file_path, original_path, file_size, 
                                 md5_hash, sha1_hash, sha256_hash, file_type, 
                                 acquired_at, source_drive)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (case_id, file_path, original_path, file_size, md5, sha1, sha256, file_type, now, source_drive))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_case_evidence(self, case_id: int) -> List[Dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY acquired_at DESC", (case_id,))
        return [dict(row) for row in cursor.fetchall()]
    
    def search_evidence(self, case_id: int, keyword: str) -> List[Dict]:
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM evidence 
            WHERE case_id = ? AND (
                file_path LIKE ? OR original_path LIKE ? OR notes LIKE ?
            )
        """, (case_id, f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'))
        return [dict(row) for row in cursor.fetchall()]
    
    # Chain of Custody
    def add_custody_entry(self, evidence_id: int, action: str, handler: str,
                          location: str = "", notes: str = "",
                          hash_before: str = "", hash_after: str = "") -> int:
        now = datetime.now().isoformat()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO custody_chain (evidence_id, action, handler, timestamp, 
                                       location, notes, hash_before, hash_after)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (evidence_id, action, handler, now, location, notes, hash_before, hash_after))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_custody_chain(self, evidence_id: int) -> List[Dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM custody_chain WHERE evidence_id = ? ORDER BY timestamp", (evidence_id,))
        return [dict(row) for row in cursor.fetchall()]
    
    # Audit Logging
    def log_audit(self, case_id: int, action: str, user: str, 
                  details: str = "", ip_address: str = ""):
        now = datetime.now().isoformat()
        self.conn.execute("""
            INSERT INTO audit_log (case_id, action, user, timestamp, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (case_id, action, user, now, details, ip_address))
        self.conn.commit()
    
    def get_audit_log(self, case_id: int = None) -> List[Dict]:
        cursor = self.conn.cursor()
        if case_id:
            cursor.execute("SELECT * FROM audit_log WHERE case_id = ? ORDER BY timestamp DESC", (case_id,))
        else:
            cursor.execute("SELECT * FROM audit_log ORDER BY timestamp DESC")
        return [dict(row) for row in cursor.fetchall()]
    
    # Statistics
    def get_case_stats(self, case_id: int) -> Dict:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM evidence WHERE case_id = ?", (case_id,))
        evidence_count = cursor.fetchone()["count"]
        
        cursor.execute("SELECT SUM(file_size) as total FROM evidence WHERE case_id = ?", (case_id,))
        total_size = cursor.fetchone()["total"] or 0
        
        cursor.execute("SELECT COUNT(*) as count FROM custody_chain c JOIN evidence e ON c.evidence_id = e.id WHERE e.case_id = ?", (case_id,))
        custody_count = cursor.fetchone()["count"]
        
        return {
            "evidence_count": evidence_count,
            "total_size_bytes": total_size,
            "total_size_gb": round(total_size / (1024**3), 2),
            "custody_entries": custody_count
        }
    
    def close(self):
        if self.conn:
            self.conn.close()
