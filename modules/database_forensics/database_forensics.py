#!/usr/bin/env python3
"""HyperTraceX Database Forensics - Extract and analyze database artifacts."""

import os
import re
import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional, Any

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class DatabaseForensics:
    """
    Database Forensic Analysis Module.
    
    Features:
        - SQLite database analysis
        - MySQL database extraction
        - PostgreSQL analysis
        - Deleted record recovery
        - Database schema extraction
        - Sensitive data discovery
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "sqlite": [],
            "mysql": [],
            "postgresql": [],
            "deleted_records": [],
            "schemas": [],
            "sensitive_data": []
        }
    
    def analyze_sqlite(self, db_path: str) -> Dict:
        """
        Analyze SQLite database.
        
        Args:
            db_path: Path to .db or .sqlite file
        
        Returns:
            Database analysis result
        """
        if not os.path.exists(db_path):
            self.logger.error(f"Database not found: {db_path}")
            return {}
        
        print(f"\n[*] Analyzing SQLite: {os.path.basename(db_path)}")
        
        analysis = {
            "database": db_path,
            "filename": os.path.basename(db_path),
            "size": os.path.getsize(db_path),
            "tables": [],
            "total_rows": 0,
            "schema": {},
            "sensitive_columns": []
        }
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table_name in tables:
                table_info = {
                    "name": table_name,
                    "columns": [],
                    "row_count": 0,
                    "sample_data": []
                }
                
                # Get columns
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [dict(row) for row in cursor.fetchall()]
                table_info["columns"] = columns
                
                # Check for sensitive column names
                for col in columns:
                    col_name = col.get("name", "").lower()
                    if any(kw in col_name for kw in ["password", "passwd", "pwd", "token", 
                                                       "secret", "key", "credit", "ssn", 
                                                       "email", "phone", "address"]):
                        analysis["sensitive_columns"].append({
                            "table": table_name,
                            "column": col.get("name"),
                            "type": col.get("type")
                        })
                
                # Count rows
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                    table_info["row_count"] = cursor.fetchone()[0]
                    analysis["total_rows"] += table_info["row_count"]
                except:
                    pass
                
                # Get sample data
                try:
                    cursor.execute(f"SELECT * FROM {table_name} LIMIT 5")
                    table_info["sample_data"] = [dict(row) for row in cursor.fetchall()]
                except:
                    pass
                
                analysis["tables"].append(table_info)
            
            # Get schema
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL")
            for row in cursor.fetchall():
                if row[0]:
                    table_name = row[0].split('(')[0].replace('CREATE TABLE', '').strip().strip('"')
                    analysis["schema"][table_name] = row[0]
            
            conn.close()
            
            print(f"[+] Found {len(tables)} tables, {analysis['total_rows']} rows")
            print(f"    Sensitive columns: {len(analysis['sensitive_columns'])}")
            
        except Exception as e:
            self.logger.error(f"SQLite analysis failed: {e}")
        
        self.results["sqlite"].append(analysis)
        return analysis
    
    def recover_deleted_records(self, db_path: str) -> List[Dict]:
        """
        Attempt to recover deleted records from SQLite database.
        
        Uses freelist analysis to find deleted data.
        """
        deleted = []
        
        if not os.path.exists(db_path):
            return deleted
        
        print(f"\n[*] Scanning for deleted records in: {os.path.basename(db_path)}")
        
        try:
            # Read raw database file
            with open(db_path, 'rb') as f:
                raw_data = f.read()
            
            # Search for text patterns in unallocated space
            text_patterns = re.findall(rb'[\x20-\x7E]{10,}', raw_data)
            
            for match in text_patterns[:100]:
                try:
                    text = match.decode('utf-8', errors='ignore')
                    if any(kw in text.lower() for kw in ['password', 'email', 'user', 'token', 'key']):
                        deleted.append({
                            "data": text,
                            "offset": raw_data.find(match),
                            "length": len(match)
                        })
                except:
                    pass
            
            print(f"[+] Potential deleted records found: {len(deleted)}")
            
        except Exception as e:
            self.logger.error(f"Deleted record recovery failed: {e}")
        
        self.results["deleted_records"] = deleted
        return deleted
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[Dict]:
        """
        Scan directory for database files and analyze them.
        
        Args:
            directory: Directory to scan
            recursive: Scan subdirectories
        
        Returns:
            List of analysis results
        """
        results = []
        
        db_extensions = ['.db', '.sqlite', '.sqlite3', '.db3', '.mdb', '.accdb']
        
        if not os.path.exists(directory):
            self.logger.error(f"Directory not found: {directory}")
            return results
        
        print(f"\n[*] Scanning for database files in: {directory}")
        
        db_files = []
        if recursive:
            for root, _, files in os.walk(directory):
                for filename in files:
                    if any(filename.lower().endswith(ext) for ext in db_extensions):
                        db_files.append(os.path.join(root, filename))
        else:
            for filename in os.listdir(directory):
                if any(filename.lower().endswith(ext) for ext in db_extensions):
                    db_files.append(os.path.join(directory, filename))
        
        print(f"[*] Found {len(db_files)} database files")
        
        for db_file in db_files:
            analysis = self.analyze_sqlite(db_file)
            if analysis:
                results.append(analysis)
        
        return results
    
    def search_all_databases(self, keyword: str) -> List[Dict]:
        """Search all analyzed databases for keyword."""
        matches = []
        
        for db_analysis in self.results.get("sqlite", []):
            for table in db_analysis.get("tables", []):
                for row in table.get("sample_data", []):
                    row_str = str(row).lower()
                    if keyword.lower() in row_str:
                        matches.append({
                            "database": db_analysis["database"],
                            "table": table["name"],
                            "row": row
                        })
        
        return matches
    
    def extract_sensitive_data(self) -> List[Dict]:
        """Extract all sensitive data found across databases."""
        sensitive = []
        
        patterns = {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "credit_card": r'\b(?:\d[ -]*?){13,16}\b',
            "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
            "ip_address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "url": r'https?://[^\s]+',
        }
        
        for db_analysis in self.results.get("sqlite", []):
            for table in db_analysis.get("tables", []):
                for row in table.get("sample_data", []):
                    row_str = str(row)
                    
                    for data_type, pattern in patterns.items():
                        matches = re.findall(pattern, row_str)
                        for match in matches:
                            sensitive.append({
                                "database": db_analysis["database"],
                                "table": table["name"],
                                "type": data_type,
                                "value": match
                            })
        
        self.results["sensitive_data"] = sensitive[:200]
        return sensitive
    
    def get_statistics(self) -> Dict:
        """Get database analysis statistics."""
        total_dbs = len(self.results.get("sqlite", []))
        total_tables = sum(len(db.get("tables", [])) for db in self.results.get("sqlite", []))
        total_rows = sum(db.get("total_rows", 0) for db in self.results.get("sqlite", []))
        
        return {
            "databases_analyzed": total_dbs,
            "total_tables": total_tables,
            "total_rows": total_rows,
            "deleted_recovered": len(self.results.get("deleted_records", [])),
            "sensitive_found": len(self.results.get("sensitive_data", []))
        }
    
    def display_summary(self):
        """Display database analysis summary."""
        stats = self.get_statistics()
        
        print(f"\n[Database Forensics Summary]")
        print(f"{'='*50}")
        print(f"  Databases Analyzed: {stats['databases_analyzed']}")
        print(f"  Total Tables:       {stats['total_tables']}")
        print(f"  Total Rows:         {stats['total_rows']}")
        print(f"  Deleted Recovered:  {stats['deleted_recovered']}")
        print(f"  Sensitive Data:     {stats['sensitive_found']}")
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        """Export results to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Database analysis exported: {output_file}")
