#!/usr/bin/env python3
"""FORENSIX Module Unit Tests."""

import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import DatabaseManager


class TestFileCarver(unittest.TestCase):
    """Test FileCarver module."""
    
    @classmethod
    def setUpClass(cls):
        from modules.analysis.file_carver import FileCarver
        cls.FileCarver = FileCarver
    
    def test_signature_database(self):
        """Test that file signatures are defined."""
        carver = self.FileCarver()
        sigs = carver.list_signatures()
        self.assertGreater(len(sigs), 0)
        self.assertIn("jpg", sigs)
        self.assertIn("pdf", sigs)
        self.assertIn("png", sigs)
    
    def test_add_custom_signature(self):
        """Test adding custom signatures."""
        carver = self.FileCarver()
        carver.add_signature(
            "CUSTOM", 
            [b"TEST"], 
            [b"END"],
            "Custom test file"
        )
        self.assertIn("custom", carver.FILE_SIGNATURES)
    
    def test_list_signatures(self):
        """Test listing signatures."""
        carver = self.FileCarver()
        sigs = carver.list_signatures()
        self.assertIsInstance(sigs, dict)
        self.assertIn("jpg", sigs)


class TestHashManager(unittest.TestCase):
    """Test HashManager module."""
    
    @classmethod
    def setUpClass(cls):
        from modules.analysis.hash_manager import HashManager
        cls.HashManager = HashManager
        cls.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False).name
    
    def setUp(self):
        self.hm = self.HashManager(self.temp_db)
    
    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.temp_db):
            os.unlink(cls.temp_db)
    
    def test_hash_calculation(self):
        """Test hash calculation."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"FORENSIX Test Data for Hashing")
            temp_path = f.name
        
        try:
            hashes = self.hm.calculate_hash(temp_path, ["md5", "sha256"])
            self.assertIn("md5", hashes)
            self.assertIn("sha256", hashes)
            self.assertEqual(len(hashes["md5"]), 32)
            self.assertEqual(len(hashes["sha256"]), 64)
        finally:
            os.unlink(temp_path)
    
    def test_hash_verification(self):
        """Test hash verification."""
        test_data = b"Verification Test Data"
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_data)
            temp_path = f.name
        
        try:
            import hashlib
            expected = hashlib.sha256(test_data).hexdigest()
            
            self.assertTrue(self.hm.verify_file(temp_path, expected, "sha256"))
            self.assertFalse(self.hm.verify_file(temp_path, "wrong", "sha256"))
        finally:
            os.unlink(temp_path)
    
    def test_add_known_hash(self):
        """Test adding known hash."""
        result = self.hm.add_known_hash(
            "abc123def456",
            "sha256",
            "test_file.txt",
            1024,
            "test",
            "unittest"
        )
        self.assertTrue(result)
    
    def test_lookup_hash(self):
        """Test hash lookup."""
        self.hm.add_known_hash("lookup_test_hash", "sha256", "test.txt")
        results = self.hm.lookup_hash("lookup_test_hash")
        self.assertGreater(len(results), 0)
    
    def test_hash_algorithms(self):
        """Test available hash algorithms."""
        self.assertIn("md5", self.hm.HASH_ALGORITHMS)
        self.assertIn("sha256", self.hm.HASH_ALGORITHMS)


class TestTimelineGenerator(unittest.TestCase):
    """Test TimelineGenerator module."""
    
    @classmethod
    def setUpClass(cls):
        from modules.analysis.timeline_generator import TimelineGenerator
        cls.TimelineGenerator = TimelineGenerator
    
    def test_empty_timeline(self):
        """Test empty timeline."""
        tl = self.TimelineGenerator()
        self.assertEqual(len(tl.events), 0)
    
    def test_add_custom_event(self):
        """Test adding custom event."""
        tl = self.TimelineGenerator()
        tl.add_custom_event(
            "2024-01-15T10:30:00",
            "TEST_EVENT",
            "Test description",
            "unittest"
        )
        self.assertEqual(len(tl.events), 1)
        self.assertEqual(tl.events[0]["type"], "TEST_EVENT")
    
    def test_sort_timeline(self):
        """Test timeline sorting."""
        tl = self.TimelineGenerator()
        tl.add_custom_event("2024-01-15T10:00:00", "EVENT_A", "First")
        tl.add_custom_event("2024-01-14T10:00:00", "EVENT_B", "Second")
        
        tl.sort_timeline()
        self.assertEqual(tl.events[0]["type"], "EVENT_B")  # Earlier first
    
    def test_filter_by_type(self):
        """Test filtering by event type."""
        tl = self.TimelineGenerator()
        tl.add_custom_event("2024-01-15T10:00:00", "TYPE_A", "A")
        tl.add_custom_event("2024-01-15T11:00:00", "TYPE_B", "B")
        tl.add_custom_event("2024-01-15T12:00:00", "TYPE_A", "C")
        
        type_a = tl.filter_by_type("TYPE_A")
        self.assertEqual(len(type_a), 2)


class TestPartitionScanner(unittest.TestCase):
    """Test PartitionScanner module."""
    
    @classmethod
    def setUpClass(cls):
        from modules.acquisition.partition_scanner import PartitionScanner
        cls.PartitionScanner = PartitionScanner
    
    def test_filesystem_details(self):
        """Test filesystem detail lookup."""
        scanner = self.PartitionScanner()
        details = scanner._get_fs_details("ntfs")
        self.assertIsInstance(details, dict)
        self.assertTrue(details.get("readable"))
    
    def test_summary_empty(self):
        """Test summary with no partitions."""
        scanner = self.PartitionScanner()
        summary = scanner.get_summary()
        self.assertEqual(summary["total_partitions"], 0)


class TestSignatureAnalyzer(unittest.TestCase):
    """Test SignatureAnalyzer module."""
    
    @classmethod
    def setUpClass(cls):
        from modules.analysis.signature_analyzer import SignatureAnalyzer
        cls.SignatureAnalyzer = SignatureAnalyzer
    
    def test_magic_database(self):
        """Test magic signature database."""
        analyzer = self.SignatureAnalyzer()
        self.assertGreater(len(analyzer.MAGIC_SIGNATURES), 0)
        self.assertIn("FFD8FF", analyzer.MAGIC_SIGNATURES)
        self.assertEqual(analyzer.MAGIC_SIGNATURES["FFD8FF"]["extension"], "jpg")
    
    def test_add_signature(self):
        """Test adding custom signature."""
        analyzer = self.SignatureAnalyzer()
        analyzer.add_signature("TEST00", "test", "application/test", "Test file")
        self.assertIn("TEST00", analyzer.MAGIC_SIGNATURES)


if __name__ == '__main__':
    unittest.main(verbosity=2)
