#!/usr/bin/env python3
"""FORENSIX Hash Manager - Multi-algorithm hashing with NSRL lookup."""

import os
import hashlib
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class HashManager:
    """
    Forensic Hash Management System.
    
    Features:
        - Multi-algorithm hashing (MD5, SHA1, SHA256, SHA512, BLAKE2)
        - Parallel hashing for large files
        - Hash database for known files (NSRL-compatible)
        - Hash comparison and verification
        - Hash set management
    """
    
    HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512", "blake2b", "blake2s"]
    
    def __init__(self, db_path: str = "hashes.db", logger=None):
        self.logger = logger or get_logger()
        self.db_path = db_path
        self._init_hash_db()
    
    def _init_hash_db(self):
        """Initialize hash database."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS known_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash_value TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                file_name TEXT,
                file_size INTEGER,
                category TEXT DEFAULT 'unknown',
                source TEXT DEFAULT 'custom',
                added_at TEXT NOT NULL,
                UNIQUE(hash_value, algorithm)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hash_sets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hash_set_members (
                set_id INTEGER,
                hash_id INTEGER,
                FOREIGN KEY (set_id) REFERENCES hash_sets(id),
                FOREIGN KEY (hash_id) REFERENCES known_hashes(id),
                PRIMARY KEY (set_id, hash_id)
            )
        """)
        conn.commit()
        conn.close()
    
    def calculate_hash(self, filepath: str, algorithms: List[str] = None) -> Dict[str, str]:
        """
        Calculate multiple hash values for a file.
        
        Args:
            filepath: Path to file
            algorithms: List of algorithms (default: all)
        
        Returns:
            Dict mapping algorithm to hash value
        """
        if not os.path.exists(filepath):
            self.logger.error(f"File not found: {filepath}")
            return {}
        
        if not algorithms:
            algorithms = self.HASH_ALGORITHMS
        
        results = {}
        
        try:
            # Open file once, calculate all hashes
            hashers = {}
            for algo in algorithms:
                try:
                    hashers[algo] = hashlib.new(algo)
                except ValueError:
                    self.logger.warning(f"Algorithm not available: {algo}")
            
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    for hasher in hashers.values():
                        hasher.update(chunk)
            
            for algo, hasher in hashers.items():
                results[algo] = hasher.hexdigest()
            
            return results
            
        except Exception as e:
            self.logger.error(f"Hash calculation failed: {e}")
            return {}
    
    def calculate_hash_batch(self, file_list: List[str], 
                             algorithms: List[str] = None) -> List[Dict]:
        """Calculate hashes for multiple files."""
        results = []
        total = len(file_list)
        
        for i, filepath in enumerate(file_list):
            if os.path.isfile(filepath):
                hashes = self.calculate_hash(filepath, algorithms)
                hashes["file"] = filepath
                hashes["size"] = os.path.getsize(filepath)
                results.append(hashes)
                
                if total > 10:
                    print(f"  [{i+1}/{total}] {os.path.basename(filepath)}")
        
        return results
    
    def verify_file(self, filepath: str, expected_hash: str, 
                    algorithm: str = "sha256") -> bool:
        """Verify file integrity against expected hash."""
        hashes = self.calculate_hash(filepath, [algorithm])
        if algorithm in hashes:
            match = hashes[algorithm].lower() == expected_hash.lower()
            if match:
                self.logger.info(f"Hash verified: {filepath}")
            else:
                self.logger.warning(f"Hash mismatch: {filepath}")
            return match
        return False
    
    def compare_files(self, file1: str, file2: str, 
                      algorithm: str = "sha256") -> bool:
        """Compare two files by hash."""
        hash1 = self.calculate_hash(file1, [algorithm])
        hash2 = self.calculate_hash(file2, [algorithm])
        
        if algorithm in hash1 and algorithm in hash2:
            return hash1[algorithm] == hash2[algorithm]
        return False
    
    def add_known_hash(self, hash_value: str, algorithm: str,
                       file_name: str = "", file_size: int = 0,
                       category: str = "unknown", source: str = "custom"):
        """Add hash to known hash database."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                INSERT OR IGNORE INTO known_hashes 
                (hash_value, algorithm, file_name, file_size, category, source, added_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (hash_value.lower(), algorithm.lower(), file_name, file_size, 
                  category, source, datetime.now().isoformat()))
            conn.commit()
            return True
        except Exception as e:
            self.logger.error(f"Failed to add known hash: {e}")
            return False
        finally:
            conn.close()
    
    def lookup_hash(self, hash_value: str) -> List[Dict]:
        """Search for hash in known database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM known_hashes WHERE hash_value = ?",
            (hash_value.lower(),)
        )
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def is_known_file(self, filepath: str, algorithm: str = "sha256") -> Tuple[bool, List[Dict]]:
        """Check if file hash exists in known database."""
        hashes = self.calculate_hash(filepath, [algorithm])
        if algorithm in hashes:
            matches = self.lookup_hash(hashes[algorithm])
            return len(matches) > 0, matches
        return False, []
    
    def filter_known_files(self, file_list: List[str], 
                           algorithm: str = "sha256") -> Tuple[List[str], List[str]]:
        """
        Filter files into known and unknown.
        
        Returns:
            Tuple of (known_files, unknown_files)
        """
        known = []
        unknown = []
        
        for filepath in file_list:
            is_known, _ = self.is_known_file(filepath, algorithm)
            if is_known:
                known.append(filepath)
            else:
                unknown.append(filepath)
        
        return known, unknown
    
    def create_hash_set(self, name: str, description: str = "") -> int:
        """Create a new hash set."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                "INSERT INTO hash_sets (name, description, created_at) VALUES (?, ?, ?)",
                (name, description, datetime.now().isoformat())
            )
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            self.logger.error(f"Failed to create hash set: {e}")
            return -1
        finally:
            conn.close()
    
    def add_to_hash_set(self, set_id: int, hash_ids: List[int]):
        """Add hashes to a hash set."""
        conn = sqlite3.connect(self.db_path)
        try:
            for hid in hash_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO hash_set_members (set_id, hash_id) VALUES (?, ?)",
                    (set_id, hid)
                )
            conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to add to hash set: {e}")
        finally:
            conn.close()
    
    def import_nsrl(self, nsrl_file: str) -> int:
        """
        Import NSRL (National Software Reference Library) hash file.
        
        NSRL format: SHA256,FileName,FileSize,ProductCode,OpSystemCode
        """
        count = 0
        try:
            with open(nsrl_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split(',')
                    if len(parts) >= 3:
                        sha256 = parts[0].strip('"')
                        file_name = parts[1].strip('"') if len(parts) > 1 else ""
                        file_size = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
                        
                        if len(sha256) == 64:
                            self.add_known_hash(sha256, "sha256", file_name, file_size, "nsrl", "nsrl_import")
                            count += 1
                            
                            if count % 1000 == 0:
                                print(f"  Imported {count} hashes...")
            
            self.logger.info(f"NSRL import complete: {count} hashes")
            return count
            
        except Exception as e:
            self.logger.error(f"NSRL import failed: {e}")
            return count
    
    def export_hash_list(self, output_file: str, algorithm: str = "sha256",
                         category: str = None):
        """Export hashes to text file."""
        conn = sqlite3.connect(self.db_path)
        try:
            query = "SELECT hash_value FROM known_hashes WHERE algorithm = ?"
            params = [algorithm.lower()]
            
            if category:
                query += " AND category = ?"
                params.append(category)
            
            cursor = conn.execute(query, params)
            
            with open(output_file, 'w') as f:
                for row in cursor:
                    f.write(row[0] + '\n')
            
            self.logger.info(f"Hash list exported: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
        finally:
            conn.close()
    
    def get_statistics(self) -> Dict:
        """Get hash database statistics."""
        conn = sqlite3.connect(self.db_path)
        stats = {}
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM known_hashes")
            stats["total_hashes"] = cursor.fetchone()[0]
            
            cursor = conn.execute(
                "SELECT algorithm, COUNT(*) FROM known_hashes GROUP BY algorithm"
            )
            stats["by_algorithm"] = dict(cursor.fetchall())
            
            cursor = conn.execute(
                "SELECT category, COUNT(*) FROM known_hashes GROUP BY category"
            )
            stats["by_category"] = dict(cursor.fetchall())
            
        except Exception as e:
            self.logger.error(f"Statistics error: {e}")
        finally:
            conn.close()
        
        return stats
    
    def display_statistics(self):
        """Display hash database statistics."""
        stats = self.get_statistics()
        
        print(f"\n[Hash Database Statistics]")
        print(f"  Total Hashes: {stats.get('total_hashes', 0)}")
        
        if 'by_algorithm' in stats:
            print(f"\n  By Algorithm:")
            for algo, count in stats['by_algorithm'].items():
                print(f"    {algo.upper():<10} {count}")
        
        if 'by_category' in stats:
            print(f"\n  By Category:")
            for cat, count in stats['by_category'].items():
                print(f"    {cat:<20} {count}")
