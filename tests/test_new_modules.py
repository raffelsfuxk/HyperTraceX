#!/usr/bin/env python3
"""HyperTraceX New Module Tests - Testing newly added forensic modules."""

import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestVideoForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.multimedia.video_forensics import VideoForensics
        cls.VideoForensics = VideoForensics
    
    def test_init(self):
        vf = self.VideoForensics()
        self.assertIsNotNone(vf.results)
    
    def test_empty_video(self):
        vf = self.VideoForensics()
        result = vf.analyze_video("/nonexistent/video.mp4")
        self.assertIsNone(result)
    
    def test_detect_editing_empty(self):
        vf = self.VideoForensics()
        result = vf.detect_editing("/nonexistent/video.mp4")
        self.assertIsNotNone(result)


class TestAudioForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.multimedia.audio_forensics import AudioForensics
        cls.AudioForensics = AudioForensics
    
    def test_init(self):
        af = self.AudioForensics()
        self.assertIsNotNone(af.results)
    
    def test_empty_audio(self):
        af = self.AudioForensics()
        result = af.analyze_audio("/nonexistent/audio.mp3")
        self.assertIsNone(result)
    
    def test_voice_detection_empty(self):
        af = self.AudioForensics()
        result = af.detect_voice("/nonexistent/audio.wav")
        self.assertIsNotNone(result)
        self.assertFalse(result.get("has_voice", True))


class TestIoTForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.iot.iot_forensics import IoTForensics
        cls.IoTForensics = IoTForensics
    
    def test_init(self):
        iot = self.IoTForensics()
        self.assertIsNotNone(iot.results)
        self.assertIn("devices_found", iot.results)
    
    def test_empty_scan(self):
        iot = self.IoTForensics()
        results = iot.scan_directory("/nonexistent/path")
        self.assertIsNotNone(results)


class TestDroneForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.drone.drone_forensics import DroneForensics
        cls.DroneForensics = DroneForensics
    
    def test_init(self):
        df = self.DroneForensics()
        self.assertIsNotNone(df.results)
        self.assertIn("flight_logs", df.results)
    
    def test_empty_scan(self):
        df = self.DroneForensics()
        results = df.scan_directory("/nonexistent/path")
        self.assertIsNotNone(results)


class TestVehicleForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.vehicle.vehicle_forensics import VehicleForensics
        cls.VehicleForensics = VehicleForensics
    
    def test_init(self):
        vf = self.VehicleForensics()
        self.assertIsNotNone(vf.results)
        self.assertIn("infotainment", vf.results)
    
    def test_empty_scan(self):
        vf = self.VehicleForensics()
        results = vf.scan_directory("/nonexistent/path")
        self.assertIsNotNone(results)


class TestSCADAForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules.scada.scada_forensics import SCADAForensics
        cls.SCADAForensics = SCADAForensics
    
    def test_init(self):
        sf = self.SCADAForensics()
        self.assertIsNotNone(sf.results)
        self.assertIn("plc_files", sf.results)
    
    def test_empty_scan(self):
        sf = self.SCADAForensics()
        results = sf.scan_directory("/nonexistent/path")
        self.assertIsNotNone(results)


class TestAdvancedErrorHandler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from core.advanced_error import AdvancedErrorHandler, ResourceGuard
        cls.AdvancedErrorHandler = AdvancedErrorHandler
        cls.ResourceGuard = ResourceGuard
    
    def test_init(self):
        handler = self.AdvancedErrorHandler()
        self.assertIsNotNone(handler)
        self.assertEqual(handler.max_retries, 3)
    
    def test_health_check(self):
        handler = self.AdvancedErrorHandler()
        report = handler.health_report()
        self.assertIsNotNone(report)
        self.assertIn("overall_status", report)
        self.assertIn("components", report)
    
    def test_resource_guard(self):
        acquired = False
        released = False
        
        def acquire():
            nonlocal acquired
            acquired = True
            return "resource"
        
        def release(resource):
            nonlocal released
            released = True
        
        with self.ResourceGuard(acquire, release) as res:
            self.assertEqual(res, "resource")
            self.assertTrue(acquired)
        
        self.assertTrue(released)
    
    def test_retry_decorator(self):
        handler = self.AdvancedErrorHandler()
        attempts = [0]
        
        @handler.retry(max_attempts=3, delay=0.1, exceptions=(ValueError,))
        def flaky_function():
            attempts[0] += 1
            if attempts[0] < 3:
                raise ValueError("Not ready")
            return "success"
        
        result = flaky_function()
        self.assertEqual(result, "success")
        self.assertEqual(attempts[0], 3)


class TestAdvancedLogger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from core.advanced_logger import AdvancedLogger
        cls.AdvancedLogger = AdvancedLogger
        cls.temp_dir = tempfile.mkdtemp()
    
    def test_init(self):
        logger = self.AdvancedLogger(self.temp_dir)
        self.assertIsNotNone(logger)
    
    def test_log_event(self):
        logger = self.AdvancedLogger(self.temp_dir)
        event = logger.log_event("TEST", "Test message", "INFO")
        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "TEST")
        self.assertEqual(event["level"], "INFO")
    
    def test_log_performance(self):
        logger = self.AdvancedLogger(self.temp_dir)
        logger.log_performance("test_op", 1.5, True, "Test")
        self.assertIn("performance", logger.metrics)
    
    def test_log_audit(self):
        logger = self.AdvancedLogger(self.temp_dir)
        entry = logger.log_audit("testuser", "TEST_ACTION", "test_resource")
        self.assertEqual(entry["user"], "testuser")
        self.assertEqual(entry["action"], "TEST_ACTION")
    
    def test_metrics_summary(self):
        logger = self.AdvancedLogger(self.temp_dir)
        logger.log_performance("op1", 1.0, True)
        logger.log_performance("op2", 2.0, True)
        summary = logger.get_metrics_summary()
        self.assertGreater(summary.get("total_operations", 0), 0)


class TestPluginMarketplace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from plugins.marketplace import PluginMarketplace
        cls.PluginMarketplace = PluginMarketplace
    
    def test_init(self):
        pm = self.PluginMarketplace()
        self.assertIsNotNone(pm.installed_plugins)
    
    def test_list_available(self):
        pm = self.PluginMarketplace()
        plugins = pm.list_available()
        self.assertIsInstance(plugins, list)
        self.assertGreater(len(plugins), 0)
    
    def test_search(self):
        pm = self.PluginMarketplace()
        results = pm.search("forensic")
        self.assertIsInstance(results, list)
    
    def test_statistics(self):
        pm = self.PluginMarketplace()
        stats = pm.get_statistics()
        self.assertIn("available_plugins", stats)
        self.assertGreater(stats["available_plugins"], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
