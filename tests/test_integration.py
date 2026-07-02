#!/usr/bin/env python3
"""HyperTraceX Integration Tests - End-to-end workflow testing."""

import os
import sys
import json
import unittest
import tempfile
import sqlite3
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestFullWorkflow(unittest.TestCase):
    """Test complete forensic workflow from case creation to report generation."""
    
    @classmethod
    def setUpClass(cls):
        from core.engine import ForensixEngine
        cls.ForensixEngine = ForensixEngine
        cls.temp_dir = tempfile.mkdtemp()
    
    def setUp(self):
        self.engine = self.ForensixEngine()
    
    def test_full_case_lifecycle(self):
        """Test complete case lifecycle."""
        # 1. Create case
        case_id = self.engine.create_case(
            "INTEGRATION_TEST",
            "Test Investigator",
            "Test Org",
            "Integration test case"
        )
        self.assertIsNotNone(case_id)
        
        # 2. Verify case exists
        case = self.engine.db.get_case("INTEGRATION_TEST")
        self.assertIsNotNone(case)
        self.assertEqual(case["investigator"], "Test Investigator")
        
        # 3. Add evidence
        ev_id = self.engine.db.add_evidence(
            case["id"],
            "/tmp/test_file.txt",
            "/original/test_file.txt",
            1024,
            "abc123",
            "def456",
            "789ghi"
        )
        self.assertIsNotNone(ev_id)
        
        # 4. Verify evidence
        evidence = self.engine.db.get_case_evidence(case["id"])
        self.assertEqual(len(evidence), 1)
        
        # 5. Log chain of custody
        custody_id = self.engine.db.add_custody_entry(
            ev_id,
            "COLLECTED",
            "Officer",
            "Server Room",
            "Collected during investigation"
        )
        self.assertIsNotNone(custody_id)
        
        # 6. Verify custody chain
        chain = self.engine.db.get_custody_chain(ev_id)
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["action"], "COLLECTED")
        
        # 7. Log audit
        self.engine.db.log_audit(case["id"], "CASE_CREATED", "testuser", "Test audit")
        
        # 8. Generate report
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            report_path = f.name
        
        try:
            self.engine.export_report_json(report_path)
            self.assertTrue(os.path.exists(report_path))
            with open(report_path, 'r') as f:
                report = json.load(f)
            self.assertIn("case", report)
        finally:
            os.unlink(report_path)
        
        # 9. Close case
        self.engine.db.close_case("INTEGRATION_TEST")
        case = self.engine.db.get_case("INTEGRATION_TEST")
        self.assertEqual(case["status"], "closed")
        
        print("[✓] Full case lifecycle test passed")
    
    def test_multi_case_management(self):
        """Test managing multiple cases simultaneously."""
        # Create multiple cases
        case_ids = []
        for i in range(3):
            case_id = self.engine.create_case(
                f"MULTI_TEST_{i}",
                f"Investigator {i}",
                f"Org {i}",
                f"Test case {i}"
            )
            case_ids.append(case_id)
        
        # Verify all cases
        all_cases = self.engine.db.get_all_cases()
        self.assertGreaterEqual(len(all_cases), 3)
        
        # Close one case
        self.engine.db.close_case("MULTI_TEST_0")
        case = self.engine.db.get_case("MULTI_TEST_0")
        self.assertEqual(case["status"], "closed")
        
        print("[✓] Multi-case management test passed")
    
    def test_evidence_search(self):
        """Test evidence search functionality."""
        case_id = self.engine.create_case("SEARCH_TEST", "Tester")
        case = self.engine.db.get_case("SEARCH_TEST")
        
        # Add multiple evidence items
        self.engine.db.add_evidence(case["id"], "/tmp/passwords.txt", "", 100)
        self.engine.db.add_evidence(case["id"], "/tmp/documents.pdf", "", 200)
        self.engine.db.add_evidence(case["id"], "/tmp/photos.zip", "", 300)
        
        # Search
        results = self.engine.db.search_evidence(case["id"], "password")
        self.assertEqual(len(results), 1)
        
        results = self.engine.db.search_evidence(case["id"], "tmp")
        self.assertEqual(len(results), 3)
        
        results = self.engine.db.search_evidence(case["id"], "nonexistent")
        self.assertEqual(len(results), 0)
        
        print("[✓] Evidence search test passed")


class TestDatabasePersistence(unittest.TestCase):
    """Test database persistence and data integrity."""
    
    @classmethod
    def setUpClass(cls):
        from core.database import DatabaseManager
        cls.DatabaseManager = DatabaseManager
        cls.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False).name
    
    def setUp(self):
        self.db = self.DatabaseManager(self.temp_db)
    
    def tearDown(self):
        self.db.close()
    
    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.temp_db):
            os.unlink(cls.temp_db)
    
    def test_data_persistence(self):
        """Test that data persists after close and reopen."""
        # Create case
        self.db.create_case("PERSIST_TEST", "Tester")
        
        # Close and reopen
        self.db.close()
        self.db = self.DatabaseManager(self.temp_db)
        
        # Verify case still exists
        case = self.db.get_case("PERSIST_TEST")
        self.assertIsNotNone(case)
        self.assertEqual(case["investigator"], "Tester")
        
        print("[✓] Data persistence test passed")
    
    def test_bulk_evidence_insertion(self):
        """Test inserting many evidence items."""
        self.db.create_case("BULK_TEST", "Tester")
        case = self.db.get_case("BULK_TEST")
        
        # Insert 100 evidence items
        for i in range(100):
            self.db.add_evidence(
                case["id"],
                f"/tmp/file_{i}.txt",
                f"/original/file_{i}.txt",
                i * 100,
                f"md5_{i}",
                f"sha1_{i}",
                f"sha256_{i}"
            )
        
        # Verify count
        evidence = self.db.get_case_evidence(case["id"])
        self.assertEqual(len(evidence), 100)
        
        # Check stats
        stats = self.db.get_case_stats(case["id"])
        self.assertEqual(stats["evidence_count"], 100)
        self.assertEqual(stats["total_size_bytes"], sum(i * 100 for i in range(100)))
        
        print("[✓] Bulk evidence insertion test passed")


class TestConfigManager(unittest.TestCase):
    """Test configuration management."""
    
    @classmethod
    def setUpClass(cls):
        from core.config import ConfigManager
        cls.ConfigManager = ConfigManager
    
    def test_load_save_config(self):
        """Test loading and saving configuration."""
        config = self.ConfigManager()
        
        # Set custom values
        config.set("custom_key", "custom_value")
        config.set("nested", {"key": "value"})
        
        # Save to file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            config.save_to_file(temp_path)
            self.assertTrue(os.path.exists(temp_path))
            
            # Load new config from file
            new_config = self.ConfigManager(temp_path)
            new_config.load_from_file()
            
            self.assertEqual(new_config.get("custom_key"), "custom_value")
            self.assertEqual(new_config.get("nested"), {"key": "value"})
        finally:
            os.unlink(temp_path)
        
        print("[✓] Config load/save test passed")


class TestHashOperations(unittest.TestCase):
    """Test hash calculation and verification."""
    
    def test_hash_consistency(self):
        """Test that hash calculation is consistent."""
        from core.engine import ForensixEngine
        engine = ForensixEngine()
        
        test_data = b"HyperTraceX Integration Test Data"
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_data)
            temp_path = f.name
        
        try:
            # Calculate hashes multiple times
            hash1 = engine.calculate_hash(temp_path, "sha256")
            hash2 = engine.calculate_hash(temp_path, "sha256")
            hash3 = engine.calculate_hash(temp_path, "sha256")
            
            # Should all be identical
            self.assertEqual(hash1, hash2)
            self.assertEqual(hash2, hash3)
            
            # Verification should pass
            self.assertTrue(engine.verify_file_integrity(temp_path, hash1, "sha256"))
            
            # Wrong hash should fail
            self.assertFalse(engine.verify_file_integrity(temp_path, "wrong_hash", "sha256"))
        finally:
            os.unlink(temp_path)
        
        print("[✓] Hash consistency test passed")


class TestErrorHandling(unittest.TestCase):
    """Test error handling and graceful failure."""
    
    @classmethod
    def setUpClass(cls):
        from core.engine import ForensixEngine
        cls.ForensixEngine = ForensixEngine
    
    def setUp(self):
        self.engine = self.ForensixEngine()
    
    def test_file_not_found(self):
        """Test handling of non-existent files."""
        # Hash non-existent file
        result = self.engine.calculate_hash("/nonexistent/file.txt")
        self.assertIsNone(result)
        
        # Verify non-existent file
        result = self.engine.verify_file_integrity("/nonexistent/file.txt", "hash")
        self.assertFalse(result)
        
        print("[✓] File not found test passed")
    
    def test_invalid_database_operations(self):
        """Test handling of invalid database operations."""
        # Get non-existent case
        case = self.engine.db.get_case("NONEXISTENT")
        self.assertIsNone(case)
        
        # Close non-existent case
        self.engine.db.close_case("NONEXISTENT")
        
        print("[✓] Invalid database operations test passed")


class TestPerformance(unittest.TestCase):
    """Test system performance under load."""
    
    def test_rapid_case_creation(self):
        """Test creating many cases rapidly."""
        from core.database import DatabaseManager
        
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            temp_db = f.name
        
        try:
            db = DatabaseManager(temp_db)
            
            start = datetime.now()
            
            for i in range(50):
                db.create_case(f"PERF_TEST_{i}", f"Tester {i}")
            
            elapsed = (datetime.now() - start).total_seconds()
            
            cases = db.get_all_cases()
            self.assertGreaterEqual(len(cases), 50)
            
            db.close()
            
            print(f"[✓] Rapid case creation test: 50 cases in {elapsed:.2f}s")
        finally:
            os.unlink(temp_db)


if __name__ == '__main__':
    unittest.main(verbosity=2)
