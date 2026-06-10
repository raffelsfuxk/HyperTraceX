#!/usr/bin/env python3
"""FORENSIX Performance Tests - Benchmarking and load testing."""

import os
import sys
import time
import unittest
import tempfile
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestHashPerformance(unittest.TestCase):
    """Test hash calculation performance."""
    
    @classmethod
    def setUpClass(cls):
        from core.engine import ForensixEngine
        cls.engine = ForensixEngine()
        cls.test_file = None
    
    @classmethod
    def setUpClass(cls):
        """Create test files of various sizes."""
        cls.test_files = {}
        sizes = {
            "1MB": 1024 * 1024,
            "10MB": 10 * 1024 * 1024,
            "100MB": 100 * 1024 * 1024
        }
        
        for name, size in sizes.items():
            fd, path = tempfile.mkstemp(suffix=f"_{name}.bin")
            with os.fdopen(fd, 'wb') as f:
                f.write(os.urandom(size))
            cls.test_files[name] = path
    
    @classmethod
    def tearDownClass(cls):
        for path in cls.test_files.values():
            if os.path.exists(path):
                os.unlink(path)
    
    def test_hash_speed_1mb(self):
        """Test hashing 1MB file."""
        start = time.time()
        result = self.engine.calculate_hash(self.test_files["1MB"], "sha256")
        elapsed = time.time() - start
        
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 64)
        
        speed = 1 / elapsed if elapsed > 0 else 0
        print(f"\n[Benchmark] 1MB hash: {elapsed:.4f}s ({speed:.1f} MB/s)")
        
        self.assertLess(elapsed, 1.0, "1MB hash too slow")
    
    def test_hash_speed_10mb(self):
        """Test hashing 10MB file."""
        start = time.time()
        result = self.engine.calculate_hash(self.test_files["10MB"], "sha256")
        elapsed = time.time() - start
        
        self.assertIsNotNone(result)
        
        speed = 10 / elapsed if elapsed > 0 else 0
        print(f"\n[Benchmark] 10MB hash: {elapsed:.4f}s ({speed:.1f} MB/s)")
        
        self.assertLess(elapsed, 3.0, "10MB hash too slow")
    
    def test_hash_algorithms_comparison(self):
        """Compare speed of different hash algorithms."""
        algorithms = ["md5", "sha1", "sha256", "sha512", "blake2b"]
        
        print(f"\n[Hash Algorithm Comparison on 10MB file]")
        print(f"{'Algorithm':<10} {'Time':<12} {'Speed'}")
        print("-" * 40)
        
        for algo in algorithms:
            start = time.time()
            result = self.engine.calculate_hash(self.test_files["10MB"], algo)
            elapsed = time.time() - start
            
            if result:
                speed = 10 / elapsed if elapsed > 0 else 0
                print(f"{algo:<10} {elapsed:.4f}s{'':<4} {speed:.1f} MB/s")


class TestDatabasePerformance(unittest.TestCase):
    """Test database operation performance."""
    
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
    
    def test_bulk_insert_performance(self):
        """Test bulk evidence insertion speed."""
        self.db.create_case("BULK_PERF", "Tester")
        case = self.db.get_case("BULK_PERF")
        
        # Insert 1000 evidence items
        start = time.time()
        
        for i in range(1000):
            self.db.add_evidence(
                case["id"],
                f"/tmp/file_{i}.txt",
                f"/original/file_{i}.txt",
                i * 100,
                f"md5_{i}",
                f"sha1_{i}",
                f"sha256_{i}"
            )
        
        elapsed = time.time() - start
        rate = 1000 / elapsed if elapsed > 0 else 0
        
        print(f"\n[Benchmark] 1000 evidence inserts: {elapsed:.2f}s ({rate:.0f} inserts/s)")
        
        self.assertLess(elapsed, 10.0, "Bulk insert too slow")
    
    def test_search_performance(self):
        """Test search performance."""
        self.db.create_case("SEARCH_PERF", "Tester")
        case = self.db.get_case("SEARCH_PERF")
        
        # Add varied evidence
        keywords = ["password", "document", "photo", "email", "database"]
        for i in range(500):
            kw = keywords[i % len(keywords)]
            self.db.add_evidence(
                case["id"],
                f"/tmp/{kw}_{i}.txt",
                f"/original/{kw}_{i}.txt",
                i * 100
            )
        
        # Measure search time
        start = time.time()
        results = self.db.search_evidence(case["id"], "password")
        elapsed = time.time() - start
        
        print(f"\n[Benchmark] Evidence search: {elapsed:.4f}s ({len(results)} results)")
        
        self.assertLess(elapsed, 1.0, "Search too slow")
    
    def test_case_stats_performance(self):
        """Test case statistics calculation performance."""
        self.db.create_case("STATS_PERF", "Tester")
        case = self.db.get_case("STATS_PERF")
        
        # Add lots of evidence
        for i in range(500):
            self.db.add_evidence(case["id"], f"/tmp/file_{i}.txt", "", i * 100)
        
        # Measure stats time
        start = time.time()
        stats = self.db.get_case_stats(case["id"])
        elapsed = time.time() - start
        
        print(f"\n[Benchmark] Case stats: {elapsed:.4f}s")
        self.assertEqual(stats["evidence_count"], 500)
        self.assertLess(elapsed, 1.0, "Stats calculation too slow")


class TestFileCarvingPerformance(unittest.TestCase):
    """Test file carving performance."""
    
    def test_carving_speed(self):
        """Test file carving speed on sample data."""
        from modules.analysis.file_carver import FileCarver
        
        carver = FileCarver()
        
        # Create test data with embedded files
        test_data = bytearray()
        
        # Embed some JPEG-like data
        jpeg_header = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01"
        jpeg_footer = b"\xFF\xD9"
        
        for i in range(100):
            test_data.extend(jpeg_header)
            test_data.extend(os.urandom(1024))
            test_data.extend(jpeg_footer)
        
        # Embed some PDF-like data
        pdf_header = b"%PDF-1.4"
        pdf_footer = b"%%EOF"
        
        for i in range(50):
            test_data.extend(pdf_header)
            test_data.extend(os.urandom(2048))
            test_data.extend(pdf_footer)
        
        fd, path = tempfile.mkstemp(suffix='.bin')
        with os.fdopen(fd, 'wb') as f:
            f.write(test_data)
        
        try:
            with tempfile.TemporaryDirectory() as output_dir:
                start = time.time()
                results = carver.carve_from_file(path, output_dir, file_types=["jpg", "pdf"])
                elapsed = time.time() - start
                
                print(f"\n[Benchmark] File carving: {elapsed:.2f}s ({len(results)} files)")
                
                self.assertGreater(len(results), 0)
                self.assertLess(elapsed, 30.0, "Carving too slow")
        finally:
            os.unlink(path)


class TestConcurrentOperations(unittest.TestCase):
    """Test concurrent operation performance."""
    
    def test_concurrent_hashing(self):
        """Test concurrent hash calculations."""
        from core.engine import ForensixEngine
        
        engine = ForensixEngine()
        
        # Create test files
        test_files = []
        for i in range(20):
            fd, path = tempfile.mkstemp(suffix=f'_concurrent_{i}.bin')
            with os.fdopen(fd, 'wb') as f:
                f.write(os.urandom(1024 * 1024))  # 1MB each
            test_files.append(path)
        
        try:
            # Single thread
            start = time.time()
            for path in test_files:
                engine.calculate_hash(path, "sha256")
            single_time = time.time() - start
            
            # Multi thread
            start = time.time()
            with ThreadPoolExecutor(max_workers=4) as executor:
                list(executor.map(
                    lambda p: engine.calculate_hash(p, "sha256"),
                    test_files
                ))
            multi_time = time.time() - start
            
            print(f"\n[Benchmark] 20 files hashing:")
            print(f"    Single thread: {single_time:.2f}s")
            print(f"    Multi thread:  {multi_time:.2f}s")
            print(f"    Speedup:       {single_time/multi_time:.1f}x" if multi_time > 0 else "")
            
        finally:
            for path in test_files:
                os.unlink(path)


class TestMemoryUsage(unittest.TestCase):
    """Test memory usage patterns."""
    
    def test_large_file_hash_memory(self):
        """Test memory usage when hashing large files."""
        import resource
        
        from core.engine import ForensixEngine
        engine = ForensixEngine()
        
        # Create 50MB test file
        fd, path = tempfile.mkstemp(suffix='_50mb.bin')
        with os.fdopen(fd, 'wb') as f:
            f.write(os.urandom(50 * 1024 * 1024))
        
        try:
            mem_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            
            result = engine.calculate_hash(path, "sha256")
            
            mem_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            mem_diff = (mem_after - mem_before) / 1024  # KB to MB
            
            self.assertIsNotNone(result)
            
            print(f"\n[Benchmark] 50MB file hash memory usage: {mem_diff:.1f} MB")
            
            self.assertLess(mem_diff, 200, "Memory usage too high")
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
