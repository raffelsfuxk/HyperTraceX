#!/usr/bin/env python3
"""HyperTraceX Comprehensive Unit Tests - Testing all modules thoroughly."""

import os
import sys
import json
import unittest
import tempfile
import sqlite3
from datetime import datetime
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestBrowserForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.artifacts.browser_forensics import BrowserForensics
        cls.BrowserForensics = BrowserForensics
    
    def setUp(self):
        self.bf = self.BrowserForensics()
    
    def test_init(self):
        self.assertIsNotNone(self.bf.results)
        self.assertIsNotNone(self.bf.BROWSER_PATHS)
        self.assertIn("chrome", self.bf.BROWSER_PATHS)
        self.assertIn("firefox", self.bf.BROWSER_PATHS)
    
    def test_empty_extraction(self):
        results = self.bf.extract_all("/nonexistent/path")
        self.assertEqual(results, {})
    
    def test_browser_list(self):
        browsers = list(self.bf.BROWSER_PATHS.keys())
        self.assertIn("chrome", browsers)
        self.assertIn("firefox", browsers)
        self.assertIn("edge", browsers)


class TestRegistryParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.artifacts.registry_parser import RegistryParser
        cls.RegistryParser = RegistryParser
    
    def setUp(self):
        self.rp = self.RegistryParser()
    
    def test_init(self):
        self.assertIsNotNone(self.rp._parsed_data)
        self.assertIsNotNone(self.rp.FORENSIC_PATHS)
    
    def test_empty_sam(self):
        users = self.rp.parse_sam_hive("/nonexistent/SAM")
        self.assertEqual(users, [])
    
    def test_empty_system(self):
        info = self.rp.parse_system_hive("/nonexistent/SYSTEM")
        self.assertIsInstance(info, dict)
    
    def test_filetime_conversion(self):
        result = self.rp._filetime_to_datetime(0)
        self.assertIsNone(result)
        
        result = self.rp._filetime_to_datetime(132500000000000000)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, datetime)


class TestFileCarver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.analysis.file_carver import FileCarver
        cls.FileCarver = FileCarver
    
    def setUp(self):
        self.carver = self.FileCarver()
    
    def test_init(self):
        self.assertIsNotNone(self.carver.FILE_SIGNATURES)
        self.assertIn("jpg", self.carver.FILE_SIGNATURES)
        self.assertIn("pdf", self.carver.FILE_SIGNATURES)
    
    def test_add_signature(self):
        self.carver.add_signature("test", [b"TEST"], [b"END"], "Test")
        self.assertIn("test", self.carver.FILE_SIGNATURES)
    
    def test_carve_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            temp_path = f.name
        
        try:
            with tempfile.TemporaryDirectory() as output_dir:
                results = self.carver.carve_from_file(temp_path, output_dir)
                self.assertEqual(len(results), 0)
        finally:
            os.unlink(temp_path)
    
    def test_list_signatures(self):
        sigs = self.carver.list_signatures()
        self.assertIsInstance(sigs, dict)
        self.assertGreater(len(sigs), 10)


class TestHashManager(unittest.TestCase):
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
    
    def test_init(self):
        self.assertIsNotNone(self.hm.HASH_ALGORITHMS)
        self.assertIn("sha256", self.hm.HASH_ALGORITHMS)
    
    def test_hash_calculation(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"HyperTraceX Hash Test Data")
            temp_path = f.name
        
        try:
            hashes = self.hm.calculate_hash(temp_path, ["md5", "sha256"])
            self.assertIn("md5", hashes)
            self.assertIn("sha256", hashes)
            self.assertEqual(len(hashes["md5"]), 32)
            self.assertEqual(len(hashes["sha256"]), 64)
        finally:
            os.unlink(temp_path)
    
    def test_empty_file_hash(self):
        result = self.hm.calculate_hash("/nonexistent/file.txt")
        self.assertEqual(result, {})
    
    def test_add_known_hash(self):
        result = self.hm.add_known_hash("test123", "sha256", "test.txt", 100)
        self.assertTrue(result)
    
    def test_lookup_nonexistent(self):
        results = self.hm.lookup_hash("nonexistent_hash_12345")
        self.assertEqual(results, [])
    
    def test_hash_algorithms_list(self):
        self.assertIn("md5", self.hm.HASH_ALGORITHMS)
        self.assertIn("sha1", self.hm.HASH_ALGORITHMS)
        self.assertIn("sha256", self.hm.HASH_ALGORITHMS)
        self.assertIn("sha512", self.hm.HASH_ALGORITHMS)


class TestTimelineGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.analysis.timeline_generator import TimelineGenerator
        cls.TimelineGenerator = TimelineGenerator
    
    def setUp(self):
        self.tl = self.TimelineGenerator()
    
    def test_init(self):
        self.assertEqual(len(self.tl.events), 0)
    
    def test_add_event(self):
        self.tl.add_custom_event("2024-01-01T00:00:00", "TEST", "Test event")
        self.assertEqual(len(self.tl.events), 1)
    
    def test_sort_timeline(self):
        self.tl.add_custom_event("2024-01-02T00:00:00", "B", "Second")
        self.tl.add_custom_event("2024-01-01T00:00:00", "A", "First")
        self.tl.sort_timeline()
        self.assertEqual(self.tl.events[0]["type"], "A")
    
    def test_filter_by_type(self):
        self.tl.add_custom_event("2024-01-01T00:00:00", "TYPE_A", "A")
        self.tl.add_custom_event("2024-01-01T00:00:00", "TYPE_B", "B")
        filtered = self.tl.filter_by_type("TYPE_A")
        self.assertEqual(len(filtered), 1)
    
    def test_statistics_empty(self):
        stats = self.tl.get_statistics()
        self.assertEqual(stats["total_events"], 0)


class TestSignatureAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.analysis.signature_analyzer import SignatureAnalyzer
        cls.SignatureAnalyzer = SignatureAnalyzer
    
    def setUp(self):
        self.sa = self.SignatureAnalyzer()
    
    def test_init(self):
        self.assertIsNotNone(self.sa.MAGIC_SIGNATURES)
        self.assertIn("FFD8FF", self.sa.MAGIC_SIGNATURES)
    
    def test_identify_nonexistent(self):
        result = self.sa.identify_file("/nonexistent/file.bin")
        self.assertIsNone(result)
    
    def test_add_signature(self):
        self.sa.add_signature("TEST00", "test", "application/test", "Test")
        self.assertIn("TEST00", self.sa.MAGIC_SIGNATURES)
    
    def test_empty_directory(self):
        results = self.sa.analyze_directory("/nonexistent/path")
        self.assertEqual(results, [])


class TestEmailExtractor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.artifacts.email_extractor import EmailExtractor
        cls.EmailExtractor = EmailExtractor
    
    def setUp(self):
        self.extractor = self.EmailExtractor()
    
    def test_init(self):
        self.assertIsNotNone(self.extractor.extracted_emails)
    
    def test_empty_pst(self):
        emails = self.extractor.extract_pst("/nonexistent/mail.pst")
        self.assertEqual(emails, [])
    
    def test_empty_mbox(self):
        emails = self.extractor.extract_mbox("/nonexistent/mail.mbox")
        self.assertEqual(emails, [])
    
    def test_search_empty(self):
        results = self.extractor.search_emails("test")
        self.assertEqual(results, [])
    
    def test_statistics_empty(self):
        stats = self.extractor.get_statistics()
        self.assertEqual(stats["total_emails"], 0)


class TestWiFiExtractor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.artifacts.wifi_extractor import WiFiExtractor
        cls.WiFiExtractor = WiFiExtractor
    
    def setUp(self):
        self.wifi = self.WiFiExtractor()
    
    def test_init(self):
        self.assertIsNotNone(self.wifi.extracted_profiles)
    
    def test_empty_mount(self):
        profiles = self.wifi.extract_from_mount("/nonexistent/mount")
        self.assertEqual(profiles, [])
    
    def test_open_networks(self):
        open_nets = self.wifi.get_open_networks()
        self.assertEqual(open_nets, [])
    
    def test_statistics(self):
        stats = self.wifi.get_statistics()
        self.assertEqual(stats["total_profiles"], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)



class TestDiskImager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.acquisition.disk_imager import DiskImager
        cls.DiskImager = DiskImager
    
    def setUp(self):
        self.imager = self.DiskImager()
    
    def test_init(self):
        self.assertIsNotNone(self.imager)
        self.assertFalse(self.imager.running)
    
    def test_empty_device(self):
        result = self.imager.create_raw_image("/nonexistent/device", "/tmp/output.img")
        self.assertIsNone(result)
    
    def test_verify_nonexistent(self):
        result = self.imager.verify_image("/nonexistent/img", "/nonexistent/hash")
        self.assertFalse(result)
    
    def test_progress_initial(self):
        self.assertEqual(self.imager.get_progress(), 0)


class TestPartitionScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.acquisition.partition_scanner import PartitionScanner
        cls.PartitionScanner = PartitionScanner
    
    def setUp(self):
        self.scanner = self.PartitionScanner()
    
    def test_init(self):
        self.assertIsNotNone(self.scanner._partitions)
    
    def test_empty_scan(self):
        partitions = self.scanner.scan_all()
        self.assertIsInstance(partitions, list)
    
    def test_windows_partitions(self):
        windows = self.scanner.get_windows_partitions()
        self.assertIsInstance(windows, list)
    
    def test_summary(self):
        summary = self.scanner.get_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn("total_partitions", summary)


class TestMemoryDumper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.acquisition.memory_dumper import MemoryDumper
        cls.MemoryDumper = MemoryDumper
    
    def setUp(self):
        self.dumper = self.MemoryDumper()
    
    def test_init(self):
        self.assertIsNotNone(self.dumper)
    
    def test_memory_info(self):
        info = self.dumper.get_memory_info()
        self.assertIsInstance(info, dict)
        self.assertIn("total_ram", info)


class TestMalwareAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.malware.malware_analyzer import MalwareAnalyzer
        cls.MalwareAnalyzer = MalwareAnalyzer
    
    def setUp(self):
        self.ma = self.MalwareAnalyzer()
    
    def test_init(self):
        self.assertIsNotNone(self.ma.results)
        self.assertIn("yara_matches", self.ma.results)
        self.assertIn("suspicious_strings", self.ma.results)
    
    def test_empty_yara(self):
        matches = self.ma.scan_with_yara("/nonexistent/path")
        self.assertEqual(matches, [])
    
    def test_empty_pe(self):
        result = self.ma.analyze_pe_file("/nonexistent/file.exe")
        self.assertIsNone(result)
    
    def test_suspicious_files_empty(self):
        result = self.ma.get_suspicious_files("/nonexistent/dir")
        self.assertEqual(result, [])
    
    def test_statistics(self):
        stats = self.ma.get_statistics()
        self.assertIsInstance(stats, dict)


class TestNetworkForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.network.network_forensics import NetworkForensics
        cls.NetworkForensics = NetworkForensics
    
    def setUp(self):
        self.nf = self.NetworkForensics()
    
    def test_init(self):
        self.assertIsNotNone(self.nf.results)
        self.assertIn("connections", self.nf.results)
        self.assertIn("dns_cache", self.nf.results)
    
    def test_empty_pcap(self):
        packets = self.nf.analyze_pcap("/nonexistent/file.pcap")
        self.assertEqual(packets, [])
    
    def test_statistics(self):
        stats = self.nf.get_statistics()
        self.assertIsInstance(stats, dict)


class TestDatabaseForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.database_forensics.database_forensics import DatabaseForensics
        cls.DatabaseForensics = DatabaseForensics
    
    def setUp(self):
        self.df = self.DatabaseForensics()
    
    def test_init(self):
        self.assertIsNotNone(self.df.results)
        self.assertIn("sqlite", self.df.results)
    
    def test_empty_db(self):
        result = self.df.analyze_sqlite("/nonexistent/db")
        self.assertEqual(result, {})
    
    def test_empty_recover(self):
        deleted = self.df.recover_deleted_records("/nonexistent/db")
        self.assertEqual(deleted, [])


class TestCloudScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.cloud.cloud_scanner import CloudScanner
        cls.CloudScanner = CloudScanner
    
    def setUp(self):
        self.cs = self.CloudScanner()
    
    def test_init(self):
        self.assertIsNotNone(self.cs.results)
        self.assertIn("onedrive", self.cs.results)
        self.assertIn("google_drive", self.cs.results)
    
    def test_empty_scan(self):
        results = self.cs.scan_user_directory("/nonexistent/path")
        self.assertIsNotNone(results)


class TestSocialForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.social_media.social_forensics import SocialForensics
        cls.SocialForensics = SocialForensics
    
    def setUp(self):
        self.sf = self.SocialForensics()
    
    def test_init(self):
        self.assertIsNotNone(self.sf.results)
        self.assertIn("facebook", self.sf.results)
        self.assertIn("instagram", self.sf.results)
    
    def test_empty_history(self):
        results = self.sf.extract_from_browser_history([])
        self.assertIsNotNone(results)


class TestBlockchainForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.blockchain.blockchain_forensics import BlockchainForensics
        cls.BlockchainForensics = BlockchainForensics
    
    def setUp(self):
        self.bf = self.BlockchainForensics()
    
    def test_init(self):
        self.assertIsNotNone(self.bf.results)
        self.assertIn("wallets_found", self.bf.results)
        self.assertIn("addresses_extracted", self.bf.results)
    
    def test_empty_scan(self):
        results = self.bf.scan_directory("/nonexistent/path")
        self.assertIsNotNone(results)
    
    def test_crypto_patterns(self):
        self.assertIn("bitcoin", self.bf.CRYPTO_PATTERNS)
        self.assertIn("ethereum", self.bf.CRYPTO_PATTERNS)


class TestVideoForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.multimedia.video_forensics import VideoForensics
        cls.VideoForensics = VideoForensics
    
    def setUp(self):
        self.vf = self.VideoForensics()
    
    def test_init(self):
        self.assertIsNotNone(self.vf.results)
    
    def test_empty_video(self):
        result = self.vf.analyze_video("/nonexistent/video.mp4")
        self.assertIsNone(result)


class TestAudioForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.multimedia.audio_forensics import AudioForensics
        cls.AudioForensics = AudioForensics
    
    def setUp(self):
        self.af = self.AudioForensics()
    
    def test_init(self):
        self.assertIsNotNone(self.af.results)
    
    def test_empty_audio(self):
        result = self.af.analyze_audio("/nonexistent/audio.mp3")
        self.assertIsNone(result)


class TestAdvancedErrorHandler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from core.advanced_error import AdvancedErrorHandler
        cls.AdvancedErrorHandler = AdvancedErrorHandler
    
    def setUp(self):
        self.handler = self.AdvancedErrorHandler()
    
    def test_health_report(self):
        report = self.handler.health_report()
        self.assertIsNotNone(report)
        self.assertIn("overall_status", report)
        self.assertIn("components", report)
    
    def test_retry_decorator_success(self):
        calls = [0]
        
        @self.handler.retry(max_attempts=3, delay=0.01)
        def succeed_on_second_try():
            calls[0] += 1
            if calls[0] < 2:
                raise ValueError("Fail")
            return "success"
        
        result = succeed_on_second_try()
        self.assertEqual(result, "success")
        self.assertEqual(calls[0], 2)
    
    def test_retry_decorator_fail(self):
        @self.handler.retry(max_attempts=2, delay=0.01)
        def always_fail():
            raise ValueError("Always fail")
        
        with self.assertRaises(ValueError):
            always_fail()
    
    def test_safe_execute_success(self):
        def func(x):
            return x * 2
        
        result = self.handler.safe_execute(func, 5)
        self.assertEqual(result, 10)
    
    def test_safe_execute_fallback(self):
        def fail_func():
            raise Exception("Fail")
        
        def fallback():
            return "fallback"
        
        result = self.handler.safe_execute(fail_func, fallback=fallback)
        self.assertEqual(result, "fallback")
    
    def test_safe_execute_default(self):
        def fail_func():
            raise Exception("Fail")
        
        result = self.handler.safe_execute(fail_func, default="default_value")
        self.assertEqual(result, "default_value")


class TestAdvancedLogger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from core.advanced_logger import AdvancedLogger
        cls.AdvancedLogger = AdvancedLogger
        cls.temp_dir = tempfile.mkdtemp()
    
    def setUp(self):
        self.logger = self.AdvancedLogger(self.temp_dir)
    
    def test_log_event(self):
        event = self.logger.log_event("TEST_TYPE", "Test message", "INFO")
        self.assertEqual(event["event_type"], "TEST_TYPE")
        self.assertEqual(event["level"], "INFO")
    
    def test_log_performance(self):
        self.logger.log_performance("test_op", 2.5, True, "Test details")
        self.assertIn("performance", self.logger.metrics)
    
    def test_log_audit(self):
        entry = self.logger.log_audit("user1", "TEST", "resource1")
        self.assertEqual(entry["user"], "user1")
        self.assertEqual(entry["result"], "success")
    
    def test_log_error(self):
        try:
            raise ValueError("Test error")
        except Exception as e:
            error_event = self.logger.log_error(e, "test_component")
            self.assertEqual(error_event["severity"], "ERROR")
            self.assertEqual(error_event["component"], "test_component")
    
    def test_metrics_summary(self):
        self.logger.log_performance("op1", 1.0, True)
        self.logger.log_performance("op2", 2.0, True)
        summary = self.logger.get_metrics_summary()
        self.assertGreater(summary.get("total_operations", 0), 0)
    
    def test_error_summary(self):
        try:
            raise RuntimeError("Test")
        except Exception as e:
            self.logger.log_error(e, "test")
        summary = self.logger.get_error_summary()
        self.assertIsInstance(summary, dict)


class TestPluginMarketplace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from plugins.marketplace import PluginMarketplace
        cls.PluginMarketplace = PluginMarketplace
    
    def setUp(self):
        self.pm = self.PluginMarketplace()
    
    def test_init(self):
        self.assertIsNotNone(self.pm.PLUGIN_REGISTRY)
        self.assertGreater(len(self.pm.PLUGIN_REGISTRY), 0)
    
    def test_list_available(self):
        plugins = self.pm.list_available()
        self.assertIsInstance(plugins, list)
        self.assertGreater(len(plugins), 0)
    
    def test_search_found(self):
        results = self.pm.search("forensic")
        self.assertIsInstance(results, list)
    
    def test_search_not_found(self):
        results = self.pm.search("xyznonexistent123")
        self.assertEqual(results, [])
    
    def test_get_plugin_info(self):
        info = self.pm.get_plugin_info("forensic_timeline")
        self.assertIsNotNone(info)
        self.assertEqual(info["name"], "Advanced Timeline Generator")
    
    def test_get_plugin_info_nonexistent(self):
        info = self.pm.get_plugin_info("nonexistent_plugin")
        self.assertIsNone(info)
    
    def test_statistics(self):
        stats = self.pm.get_statistics()
        self.assertGreater(stats["available_plugins"], 0)
        self.assertGreater(stats["total_downloads"], 0)


class TestMultiUserManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from enterprise.multi_user import MultiUserManager
        cls.MultiUserManager = MultiUserManager
        cls.temp_file = tempfile.NamedTemporaryFile(suffix='.json', delete=False).name
    
    def setUp(self):
        self.users = self.MultiUserManager(self.temp_file)
    
    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.temp_file):
            os.unlink(cls.temp_file)
    
    def test_default_admin(self):
        self.assertIn("admin", self.users.users)
        self.assertEqual(self.users.users["admin"]["role"], "admin")
    
    def test_create_user(self):
        result = self.users.create_user("testuser", "password123", "investigator", "Test User")
        self.assertTrue(result)
        self.assertIn("testuser", self.users.users)
    
    def test_authenticate_success(self):
        self.users.create_user("authuser", "pass123", "investigator")
        session = self.users.authenticate("authuser", "pass123")
        self.assertIsNotNone(session)
        self.assertEqual(session["username"], "authuser")
    
    def test_authenticate_fail(self):
        session = self.users.authenticate("nonexistent", "wrong")
        self.assertIsNone(session)
    
    def test_check_permission(self):
        self.users.create_user("permuser", "pass", "investigator")
        session = self.users.authenticate("permuser", "pass")
        self.assertTrue(self.users.check_permission(session["session_id"], "create_case"))
        self.assertFalse(self.users.check_permission(session["session_id"], "manage_users"))
    
    def test_list_users(self):
        user_list = self.users.list_users()
        self.assertIsInstance(user_list, list)
        self.assertGreater(len(user_list), 0)
    
    def test_delete_user(self):
        self.users.create_user("deleteuser", "pass", "viewer")
        result = self.users.delete_user("deleteuser")
        self.assertTrue(result)


class TestChainOfCustody(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from enterprise.chain_of_custody import ChainOfCustody
        cls.ChainOfCustody = ChainOfCustody
    
    def setUp(self):
        self.coc = self.ChainOfCustody("TEST_CASE")
    
    def test_init(self):
        self.assertEqual(self.coc.case_id, "TEST_CASE")
        self.assertIsNotNone(self.coc.evidence_items)
    
    def test_register_evidence(self):
        item = self.coc.register_evidence(
            "EVID001", "Test evidence", "/tmp/test.txt", "Officer", "Lab"
        )
        self.assertIsNotNone(item)
        self.assertEqual(item["evidence_id"], "EVID001")
    
    def test_log_transfer(self):
        self.coc.register_evidence("EVID002", "Test", "/tmp/test.txt", "Officer", "Lab")
        entry = self.coc.log_transfer("EVID002", "TRANSFERRED", "Handler", "Lab2")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["action"], "TRANSFERRED")
    
    def test_verify_missing(self):
        result = self.coc.verify_integrity("NONEXISTENT")
        self.assertEqual(result["status"], "NOT_FOUND")
    
    def test_get_history(self):
        self.coc.register_evidence("EVID003", "Test", "/tmp/test.txt", "Officer", "Lab")
        history = self.coc.get_evidence_history("EVID003")
        self.assertGreater(len(history), 0)
    
    def test_statistics(self):
        stats = self.coc.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn("total_evidence_items", stats)


class TestAuditLogger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from enterprise.audit_logging import AuditLogger
        cls.AuditLogger = AuditLogger
        cls.temp_dir = tempfile.mkdtemp()
    
    def setUp(self):
        self.audit = self.AuditLogger(self.temp_dir)
    
    def test_log_event(self):
        event = self.audit.log_event("user1", "TEST_ACTION", "Test details")
        self.assertEqual(event["user"], "user1")
        self.assertEqual(event["action"], "TEST_ACTION")
    
    def test_log_login(self):
        event = self.audit.log_user_login("admin", True, "192.168.1.1")
        self.assertEqual(event["user"], "admin")
        self.assertEqual(event["action"], "USER_LOGIN")
    
    def test_log_login_fail(self):
        event = self.audit.log_user_login("hacker", False, "10.0.0.1")
        self.assertEqual(event["action"], "ACCESS_DENIED")
    
    def test_statistics(self):
        self.audit.log_event("user1", "TEST", "Test")
        stats = self.audit.get_statistics()
        self.assertGreater(stats["total_events"], 0)
    
    def test_compliance_report(self):
        self.audit.log_event("user1", "CASE_CREATED", "Test", case_id="C001")
        report = self.audit.generate_compliance_report("ISO27001")
        self.assertIsNotNone(report)


if __name__ == '__main__':
    unittest.main(verbosity=2)
