#!/usr/bin/env python3
"""FORENSIX Unit Tests - Core Module Tests."""

import os
import sys
import json
import unittest
import tempfile
import hashlib
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import ConfigManager, DEFAULT_CONFIG
from core.database import DatabaseManager
from core.logger import setup_logging, get_logger


class TestConfigManager(unittest.TestCase):
    """Test ConfigManager class."""
    
    def setUp(self):
        self.config = ConfigManager()
    
    def test_default_config(self):
        """Test default configuration values."""
        config = self.config.load_default()
        self.assertEqual(config["version"], "1.0.0")
        self.assertIn("case", config)
        self.assertIn("storage", config)
        self.assertIn("logging", config)
    
    def test_get_set(self):
        """Test get and set operations."""
        self.config.set("test_key", "test_value")
        self.assertEqual(self.config.get("test_key"), "test_value")
    
    def test_load_from_file(self):
        """Test loading config from JSON file."""
        test_config = {"custom_key": "custom_value"}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            temp_path = f.name
        
        try:
            self.config.load_from_file(temp_path)
            self.assertEqual(self.config.get("custom_key"), "custom_value")
        finally:
            os.unlink(temp_path)
    
    def test_save_to_file(self):
        """Test saving config to file."""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            self.config.save_to_file(temp_path)
            self.assertTrue(os.path.exists(temp_path))
            
            with open(temp_path, 'r') as f:
                data = json.load(f)
                self.assertIsInstance(data, dict)
        finally:
            os.unlink(temp_path)
    
    def test_contains(self):
        """Test __contains__ method."""
        self.assertIn("version", self.config)
        self.assertNotIn("nonexistent_key", self.config)


class TestDatabaseManager(unittest.TestCase):
    """Test DatabaseManager class."""
    
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False).name
        self.db = DatabaseManager(self.temp_db)
    
    def tearDown(self):
        self.db.close()
        if os.path.exists(self.temp_db):
            os.unlink(self.temp_db)
    
    def test_create_case(self):
        """Test case creation."""
        case_id = self.db.create_case(
            "TEST001",
            "Investigator",
            "Test Org",
            "Test case"
        )
        self.assertIsNotNone(case_id)
        self.assertGreater(case_id, 0)
    
    def test_get_case(self):
        """Test case retrieval."""
        self.db.create_case("TEST002", "Investigator")
        case = self.db.get_case("TEST002")
        self.assertIsNotNone(case)
        self.assertEqual(case["investigator"], "Investigator")
    
    def test_close_case(self):
        """Test case closure."""
        self.db.create_case("TEST003", "Investigator")
        self.db.close_case("TEST003")
        case = self.db.get_case("TEST003")
        self.assertEqual(case["status"], "closed")
    
    def test_add_evidence(self):
        """Test evidence addition."""
        self.db.create_case("TEST004", "Investigator")
        case = self.db.get_case("TEST004")
        
        ev_id = self.db.add_evidence(
            case["id"],
            "/tmp/test.txt",
            "/original/test.txt",
            1024,
            "abc123",
            "def456",
            "789ghi"
        )
        self.assertIsNotNone(ev_id)
        self.assertGreater(ev_id, 0)
    
    def test_get_case_evidence(self):
        """Test evidence retrieval."""
        self.db.create_case("TEST005", "Investigator")
        case = self.db.get_case("TEST005")
        
        self.db.add_evidence(case["id"], "/tmp/test1.txt", "", 100)
        self.db.add_evidence(case["id"], "/tmp/test2.txt", "", 200)
        
        evidence = self.db.get_case_evidence(case["id"])
        self.assertEqual(len(evidence), 2)
    
    def test_add_custody(self):
        """Test chain of custody logging."""
        self.db.create_case("TEST006", "Investigator")
        case = self.db.get_case("TEST006")
        
        ev_id = self.db.add_evidence(case["id"], "/tmp/evidence.txt", "", 500)
        
        custody_id = self.db.add_custody_entry(
            ev_id,
            "COLLECTED",
            "Officer",
            "Lab Room 1",
            "Collected from suspect PC"
        )
        self.assertIsNotNone(custody_id)
        
        chain = self.db.get_custody_chain(ev_id)
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["action"], "COLLECTED")
    
    def test_audit_logging(self):
        """Test audit logging."""
        self.db.create_case("TEST007", "Investigator")
        case = self.db.get_case("TEST007")
        
        self.db.log_audit(case["id"], "TEST_ACTION", "User", "Test details")
        
        audit = self.db.get_audit_log(case["id"])
        self.assertGreaterEqual(len(audit), 1)
    
    def test_search_evidence(self):
        """Test evidence search."""
        self.db.create_case("TEST008", "Investigator")
        case = self.db.get_case("TEST008")
        
        self.db.add_evidence(case["id"], "/tmp/passwords.txt", "", 100)
        self.db.add_evidence(case["id"], "/tmp/documents.pdf", "", 200)
        
        results = self.db.search_evidence(case["id"], "password")
        self.assertEqual(len(results), 1)
        self.assertIn("passwords", results[0]["file_path"])
    
    def test_case_stats(self):
        """Test case statistics."""
        self.db.create_case("TEST009", "Investigator")
        case = self.db.get_case("TEST009")
        
        self.db.add_evidence(case["id"], "/tmp/file1.txt", "", 100)
        self.db.add_evidence(case["id"], "/tmp/file2.txt", "", 200)
        
        stats = self.db.get_case_stats(case["id"])
        self.assertEqual(stats["evidence_count"], 2)
        self.assertEqual(stats["total_size_bytes"], 300)


class TestLogger(unittest.TestCase):
    """Test logging setup."""
    
    def test_setup_logging(self):
        """Test logger setup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logging(Path(tmpdir), "DEBUG")
            self.assertIsNotNone(logger)
            self.assertEqual(logger.level, 10)  # DEBUG level
            
            # Test logging
            logger.info("Test message")
            
            # Check log file created
            log_files = list(Path(tmpdir).glob("*.log"))
            self.assertGreater(len(log_files), 0)
    
    def test_get_logger(self):
        """Test get_logger function."""
        logger = get_logger("TEST_LOGGER")
        self.assertIsNotNone(logger)
        self.assertEqual(logger.name, "TEST_LOGGER")


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions."""
    
    def test_hash_calculation(self):
        """Test hash calculation."""
        test_content = b"FORENSIX Test Data"
        expected_md5 = hashlib.md5(test_content).hexdigest()
        expected_sha256 = hashlib.sha256(test_content).hexdigest()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_content)
            temp_path = f.name
        
        try:
            from core.engine import ForensixEngine
            engine = ForensixEngine()
            
            md5_result = engine.calculate_hash(temp_path, "md5")
            sha256_result = engine.calculate_hash(temp_path, "sha256")
            
            self.assertEqual(md5_result, expected_md5)
            self.assertEqual(sha256_result, expected_sha256)
        finally:
            os.unlink(temp_path)
    
    def test_hash_verification(self):
        """Test hash verification."""
        test_content = b"Verification Test"
        expected_hash = hashlib.sha256(test_content).hexdigest()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_content)
            temp_path = f.name
        
        try:
            from core.engine import ForensixEngine
            engine = ForensixEngine()
            
            self.assertTrue(engine.verify_file_integrity(temp_path, expected_hash, "sha256"))
            self.assertFalse(engine.verify_file_integrity(temp_path, "wronghash", "sha256"))
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
