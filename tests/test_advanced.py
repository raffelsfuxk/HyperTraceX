#!/usr/bin/env python3
"""HyperTraceX Advanced Unit Tests - Testing all modules."""

import os
import sys
import unittest
import tempfile
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestMobileModules(unittest.TestCase):
    """Test Mobile Forensics modules."""
    
    @classmethod
    def setUpClass(cls):
        from modules.mobile.android_parser import AndroidParser
        from modules.mobile.ios_parser import iOSParser
        from modules.mobile.chat_extractor import ChatExtractor
        cls.AndroidParser = AndroidParser
        cls.iOSParser = iOSParser
        cls.ChatExtractor = ChatExtractor
    
    def test_android_parser_init(self):
        parser = self.AndroidParser()
        self.assertIsNotNone(parser.results)
        self.assertIn("contacts", parser.results)
        self.assertIn("sms", parser.results)
        self.assertIn("call_logs", parser.results)
    
    def test_android_parser_empty_db(self):
        parser = self.AndroidParser()
        contacts = parser.parse_contacts_db("/nonexistent/db")
        self.assertEqual(len(contacts), 0)
    
    def test_ios_parser_init(self):
        parser = self.iOSParser()
        self.assertIsNotNone(parser.results)
        self.assertIn("contacts", parser.results)
        self.assertIn("sms", parser.results)
    
    def test_chat_extractor_init(self):
        extractor = self.ChatExtractor()
        self.assertIsNotNone(extractor.results)
        self.assertIn("whatsapp", extractor.results)
        self.assertIn("telegram", extractor.results)
    
    def test_chat_extractor_empty_db(self):
        extractor = self.ChatExtractor()
        messages = extractor.extract_whatsapp("/nonexistent/db")
        self.assertEqual(len(messages), 0)


class TestCloudModules(unittest.TestCase):
    """Test Cloud Forensics modules."""
    
    @classmethod
    def setUpClass(cls):
        from modules.cloud.cloud_scanner import CloudScanner
        cls.CloudScanner = CloudScanner
    
    def test_cloud_scanner_init(self):
        scanner = self.CloudScanner()
        self.assertIsNotNone(scanner.results)
        self.assertIn("onedrive", scanner.results)
        self.assertIn("google_drive", scanner.results)
    
    def test_empty_directory(self):
        scanner = self.CloudScanner()
        results = scanner.scan_user_directory("/nonexistent/path")
        self.assertIsNotNone(results)


class TestNetworkModules(unittest.TestCase):
    """Test Network Forensics modules."""
    
    @classmethod
    def setUpClass(cls):
        from modules.network.network_forensics import NetworkForensics
        cls.NetworkForensics = NetworkForensics
    
    def test_network_forensics_init(self):
        nf = self.NetworkForensics()
        self.assertIsNotNone(nf.results)
        self.assertIn("connections", nf.results)
        self.assertIn("dns_cache", nf.results)
    
    def test_empty_pcap(self):
        nf = self.NetworkForensics()
        packets = nf.analyze_pcap("/nonexistent/file.pcap")
        self.assertEqual(len(packets), 0)


class TestMalwareModules(unittest.TestCase):
    """Test Malware Analysis modules."""
    
    @classmethod
    def setUpClass(cls):
        from modules.malware.malware_analyzer import MalwareAnalyzer
        cls.MalwareAnalyzer = MalwareAnalyzer
    
    def test_malware_analyzer_init(self):
        analyzer = self.MalwareAnalyzer()
        self.assertIsNotNone(analyzer.results)
        self.assertIn("yara_matches", analyzer.results)
        self.assertIn("pe_analysis", analyzer.results)
    
    def test_empty_yara_scan(self):
        analyzer = self.MalwareAnalyzer()
        matches = analyzer.scan_with_yara("/nonexistent/path")
        self.assertEqual(len(matches), 0)
    
    def test_hash_calculation(self):
        analyzer = self.MalwareAnalyzer()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data")
            temp_path = f.name
        
        try:
            md5 = analyzer._calculate_hash(temp_path, "md5")
            sha256 = analyzer._calculate_hash(temp_path, "sha256")
            self.assertEqual(len(md5), 32)
            self.assertEqual(len(sha256), 64)
        finally:
            os.unlink(temp_path)


class TestMemoryModules(unittest.TestCase):
    """Test Memory Forensics modules."""
    
    @classmethod
    def setUpClass(cls):
        from modules.memory.memory_forensics import MemoryForensics
        cls.MemoryForensics = MemoryForensics
    
    def test_memory_forensics_init(self):
        mf = self.MemoryForensics()
        self.assertIsNotNone(mf.results)
        self.assertIn("processes", mf.results)
        self.assertIn("connections", mf.results)


class TestDatabaseModules(unittest.TestCase):
    """Test Database Forensics modules."""
    
    @classmethod
    def setUpClass(cls):
        from modules.database_forensics.database_forensics import DatabaseForensics
        cls.DatabaseForensics = DatabaseForensics
    
    def test_database_forensics_init(self):
        df = self.DatabaseForensics()
        self.assertIsNotNone(df.results)
        self.assertIn("sqlite", df.results)
    
    def test_empty_db_analysis(self):
        df = self.DatabaseForensics()
        result = df.analyze_sqlite("/nonexistent/db")
        self.assertEqual(result, {})


class TestSocialModules(unittest.TestCase):
    """Test Social Media Forensics modules."""
    
    @classmethod
    def setUpClass(cls):
        from modules.social_media.social_forensics import SocialForensics
        cls.SocialForensics = SocialForensics
    
    def test_social_forensics_init(self):
        sf = self.SocialForensics()
        self.assertIsNotNone(sf.results)
        self.assertIn("facebook", sf.results)
        self.assertIn("instagram", sf.results)
    
    def test_empty_history(self):
        sf = self.SocialForensics()
        results = sf.extract_from_browser_history([])
        self.assertIsNotNone(results)


class TestBlockchainModules(unittest.TestCase):
    """Test Blockchain Forensics modules."""
    
    @classmethod
    def setUpClass(cls):
        from modules.blockchain.blockchain_forensics import BlockchainForensics
        cls.BlockchainForensics = BlockchainForensics
    
    def test_blockchain_forensics_init(self):
        bf = self.BlockchainForensics()
        self.assertIsNotNone(bf.results)
        self.assertIn("wallets_found", bf.results)
        self.assertIn("addresses_extracted", bf.results)
    
    def test_empty_directory_scan(self):
        bf = self.BlockchainForensics()
        results = bf.scan_directory("/nonexistent/path")
        self.assertIsNotNone(results)


class TestEnterpriseModules(unittest.TestCase):
    """Test Enterprise modules."""
    
    def test_multi_user_init(self):
        from enterprise.multi_user import MultiUserManager
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            users = MultiUserManager(temp_path)
            self.assertIn("admin", users.users)
            self.assertEqual(users.users["admin"]["role"], "admin")
        finally:
            os.unlink(temp_path)
    
    def test_chain_of_custody_init(self):
        from enterprise.chain_of_custody import ChainOfCustody
        coc = ChainOfCustody("TEST")
        self.assertEqual(coc.case_id, "TEST")
    
    def test_audit_logger_init(self):
        from enterprise.audit_logging import AuditLogger
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLogger(tmpdir)
            event = audit.log_event("testuser", "TEST_ACTION", "Test details")
            self.assertEqual(event["user"], "testuser")
            self.assertEqual(event["action"], "TEST_ACTION")


class TestAIModules(unittest.TestCase):
    """Test AI modules."""
    
    def test_image_classifier_init(self):
        from ai.image_classifier import ImageClassifier
        classifier = ImageClassifier()
        self.assertIsNotNone(classifier.IMAGE_CATEGORIES)
        self.assertIn("photo", classifier.IMAGE_CATEGORIES)
    
    def test_document_analyzer_init(self):
        from ai.document_analyzer import DocumentAnalyzer
        analyzer = DocumentAnalyzer()
        self.assertIsNotNone(analyzer.PII_PATTERNS)
        self.assertIn("email", analyzer.PII_PATTERNS)
    
    def test_anomaly_detector_init(self):
        from ai.anomaly_detector import AnomalyDetector
        detector = AnomalyDetector()
        self.assertIsNotNone(detector.SUSPICIOUS_PATTERNS)


class TestReportingModules(unittest.TestCase):
    """Test Reporting modules."""
    
    def test_html_reporter_init(self):
        from reporting.html_reporter import HTMLReporter
        reporter = HTMLReporter()
        self.assertIsNotNone(reporter._report_data)
    
    def test_html_reporter_generate(self):
        from reporting.html_reporter import HTMLReporter
        
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            temp_path = f.name
        
        try:
            reporter = HTMLReporter()
            reporter.set_case_info("TEST001", "Tester")
            reporter.generate(temp_path)
            self.assertTrue(os.path.exists(temp_path))
            self.assertGreater(os.path.getsize(temp_path), 0)
        finally:
            os.unlink(temp_path)


class TestDashboardModules(unittest.TestCase):
    """Test Dashboard modules."""
    
    def test_dashboard_init(self):
        from dashboard.web_interface import WebDashboard
        dashboard = WebDashboard()
        self.assertIsNotNone(dashboard)
        self.assertFalse(dashboard.running)


if __name__ == '__main__':
    unittest.main(verbosity=2)
