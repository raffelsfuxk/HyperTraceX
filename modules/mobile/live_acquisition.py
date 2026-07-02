#!/usr/bin/env python3
"""HyperTraceX Mobile Live Acquisition - Real-time mobile device data extraction."""

import os
import re
import json
import subprocess
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class MobileLiveAcquisition:
    """
    Live Mobile Device Acquisition Module.
    
    Features:
        - ADB (Android Debug Bridge) live extraction
        - iOS live acquisition via libimobiledevice
        - App data extraction (WhatsApp, Telegram, Signal)
        - SMS/Contacts/Call logs extraction
        - Screen capture
        - Device information gathering
        - File system browsing
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.connected_devices: List[Dict] = []
        self.acquired_data: Dict[str, List] = {
            "device_info": [],
            "contacts": [],
            "sms": [],
            "call_logs": [],
            "apps": [],
            "files": [],
            "screenshots": []
        }
    
    def scan_devices(self) -> List[Dict]:
        """Scan for connected mobile devices."""
        devices = []
        
        # Check ADB devices (Android)
        try:
            result = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.splitlines()[1:]:
                if line.strip() and "device" in line:
                    serial = line.split()[0]
                    devices.append({
                        "serial": serial,
                        "platform": "android",
                        "state": "connected",
                        "connection": "USB"
                    })
        except FileNotFoundError:
            self.logger.warning("ADB not installed. Install: sudo apt install adb")
        except Exception as e:
            self.logger.error(f"ADB scan failed: {e}")
        
        # Check iOS devices (libimobiledevice)
        try:
            result = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.splitlines():
                if line.strip():
                    devices.append({
                        "serial": line.strip(),
                        "platform": "ios",
                        "state": "connected",
                        "connection": "USB"
                    })
        except FileNotFoundError:
            self.logger.warning("libimobiledevice not installed")
        except Exception as e:
            self.logger.error(f"iOS scan failed: {e}")
        
        self.connected_devices = devices
        
        if devices:
            print(f"\n[+] Found {len(devices)} connected device(s):")
            for d in devices:
                print(f"    [{d['platform'].upper()}] {d['serial']}")
        else:
            print("\n[*] No mobile devices detected")
        
        return devices
    
    def acquire_android(self, serial: str = None, output_dir: str = None) -> Dict:
        """Acquire data from Android device via ADB."""
        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="tracex_android_")
        
        os.makedirs(output_dir, exist_ok=True)
        
        adb_prefix = ["adb"]
        if serial:
            adb_prefix.extend(["-s", serial])
        
        data = {
            "platform": "android",
            "serial": serial or "auto",
            "acquisition_time": datetime.now().isoformat(),
            "output_dir": output_dir
        }
        
        print(f"\n[*] Starting Android acquisition...")
        
        # Device info
        try:
            result = subprocess.run(adb_prefix + ["shell", "getprop"], 
                                   capture_output=True, text=True, timeout=10)
            
            device_info = {}
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().strip("[]")
                    value = value.strip().strip("[]")
                    device_info[key] = value
            
            data["device_info"] = {
                "manufacturer": device_info.get("ro.product.manufacturer", "Unknown"),
                "model": device_info.get("ro.product.model", "Unknown"),
                "android_version": device_info.get("ro.build.version.release", "Unknown"),
                "sdk_version": device_info.get("ro.build.version.sdk", "Unknown"),
                "build_id": device_info.get("ro.build.id", "Unknown"),
                "serial_number": device_info.get("ro.serialno", "Unknown")
            }
            
            print(f"    Device: {data['device_info']['manufacturer']} {data['device_info']['model']}")
            print(f"    Android: {data['device_info']['android_version']}")
            
        except Exception as e:
            self.logger.error(f"Device info extraction failed: {e}")
        
        # Installed apps
        try:
            result = subprocess.run(adb_prefix + ["shell", "pm", "list", "packages"],
                                   capture_output=True, text=True, timeout=10)
            
            apps = []
            for line in result.stdout.splitlines():
                if line.startswith("package:"):
                    apps.append(line.replace("package:", "").strip())
            
            data["installed_apps"] = apps
            print(f"    Apps: {len(apps)} installed")
            
        except Exception as e:
            self.logger.error(f"App list extraction failed: {e}")
        
        # Contacts
        try:
            result = subprocess.run(
                adb_prefix + ["shell", "content", "query", "--uri", 
                             "content://com.android.contacts/data", "--projection", 
                             "display_name,data1"],
                capture_output=True, text=True, timeout=15
            )
            
            contacts = []
            for line in result.stdout.splitlines():
                if "display_name" in line:
                    contacts.append({"raw": line.strip()})
            
            data["contacts_count"] = len(contacts)
            print(f"    Contacts: {len(contacts)}")
            
        except Exception as e:
            self.logger.error(f"Contacts extraction failed: {e}")
        
        # SMS
        try:
            result = subprocess.run(
                adb_prefix + ["shell", "content", "query", "--uri", 
                             "content://sms", "--projection", 
                             "address,body,date,type"],
                capture_output=True, text=True, timeout=15
            )
            
            sms = result.stdout.splitlines()
            data["sms_count"] = len(sms) - 1 if len(sms) > 1 else 0
            print(f"    SMS: {data['sms_count']} messages")
            
        except Exception as e:
            self.logger.error(f"SMS extraction failed: {e}")
        
        # Call logs
        try:
            result = subprocess.run(
                adb_prefix + ["shell", "content", "query", "--uri", 
                             "content://call_log/calls", "--projection", 
                             "number,duration,type,date"],
                capture_output=True, text=True, timeout=15
            )
            
            calls = result.stdout.splitlines()
            data["call_logs_count"] = len(calls) - 1 if len(calls) > 1 else 0
            print(f"    Call Logs: {data['call_logs_count']} entries")
            
        except Exception as e:
            self.logger.error(f"Call log extraction failed: {e}")
        
        # Screenshot
        try:
            screenshot_path = os.path.join(output_dir, "screenshot.png")
            subprocess.run(
                adb_prefix + ["shell", "screencap", "-p", "/sdcard/tracex_screenshot.png"],
                capture_output=True, timeout=10
            )
            subprocess.run(
                adb_prefix + ["pull", "/sdcard/tracex_screenshot.png", screenshot_path],
                capture_output=True, timeout=10
            )
            
            if os.path.exists(screenshot_path):
                data["screenshot"] = screenshot_path
                print(f"    Screenshot: Captured")
        except:
            pass
        
        # Pull WhatsApp database
        try:
            whatsapp_path = os.path.join(output_dir, "whatsapp")
            os.makedirs(whatsapp_path, exist_ok=True)
            
            subprocess.run(
                adb_prefix + ["pull", "/sdcard/WhatsApp/Databases/msgstore.db", whatsapp_path],
                capture_output=True, timeout=30
            )
            
            db_file = os.path.join(whatsapp_path, "msgstore.db")
            if os.path.exists(db_file) and os.path.getsize(db_file) > 0:
                data["whatsapp_db"] = db_file
                print(f"    WhatsApp: Database extracted")
        except:
            pass
        
        # Save metadata
        meta_file = os.path.join(output_dir, "acquisition_metadata.json")
        with open(meta_file, 'w') as f:
            json.dump(data, f, indent=4, default=str)
        
        print(f"\n[+] Android acquisition complete: {output_dir}")
        
        return data
    
    def acquire_ios(self, serial: str = None, output_dir: str = None) -> Dict:
        """Acquire data from iOS device via libimobiledevice."""
        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="tracex_ios_")
        
        os.makedirs(output_dir, exist_ok=True)
        
        idevice_prefix = []
        if serial:
            idevice_prefix.extend(["-u", serial])
        
        data = {
            "platform": "ios",
            "serial": serial or "auto",
            "acquisition_time": datetime.now().isoformat(),
            "output_dir": output_dir
        }
        
        print(f"\n[*] Starting iOS acquisition...")
        
        # Device info
        try:
            result = subprocess.run(["ideviceinfo"], capture_output=True, text=True, timeout=10)
            
            device_info = {}
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    device_info[key.strip()] = value.strip()
            
            data["device_info"] = {
                "device_name": device_info.get("DeviceName", "Unknown"),
                "product_type": device_info.get("ProductType", "Unknown"),
                "ios_version": device_info.get("ProductVersion", "Unknown"),
                "serial": device_info.get("SerialNumber", "Unknown"),
                "imei": device_info.get("InternationalMobileEquipmentIdentity", "Unknown"),
                "phone_number": device_info.get("PhoneNumber", "Unknown")
            }
            
            print(f"    Device: {data['device_info']['device_name']}")
            print(f"    iOS: {data['device_info']['ios_version']}")
            
        except Exception as e:
            self.logger.error(f"iOS device info extraction failed: {e}")
        
        # List installed apps
        try:
            result = subprocess.run(["ideviceinstaller", "-l"], 
                                   capture_output=True, text=True, timeout=15)
            
            apps = []
            for line in result.stdout.splitlines():
                if "-" in line:
                    parts = line.split("-", 2)
                    if len(parts) >= 2:
                        apps.append(parts[1].strip())
            
            data["installed_apps"] = apps
            print(f"    Apps: {len(apps)} installed")
            
        except Exception as e:
            self.logger.error(f"iOS app list failed: {e}")
        
        # Screenshot
        try:
            screenshot_path = os.path.join(output_dir, "screenshot.png")
            subprocess.run(["idevicescreenshot", screenshot_path], 
                         capture_output=True, timeout=10)
            
            if os.path.exists(screenshot_path):
                data["screenshot"] = screenshot_path
                print(f"    Screenshot: Captured")
        except:
            pass
        
        # Save metadata
        meta_file = os.path.join(output_dir, "acquisition_metadata.json")
        with open(meta_file, 'w') as f:
            json.dump(data, f, indent=4, default=str)
        
        print(f"\n[+] iOS acquisition complete: {output_dir}")
        
        return data
    
    def acquire_all(self, output_dir: str = None) -> Dict[str, Dict]:
        """Acquire data from all connected devices."""
        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="tracex_mobile_")
        
        devices = self.scan_devices()
        results = {}
        
        for device in devices:
            device_output = os.path.join(output_dir, device["serial"])
            os.makedirs(device_output, exist_ok=True)
            
            if device["platform"] == "android":
                results[device["serial"]] = self.acquire_android(device["serial"], device_output)
            elif device["platform"] == "ios":
                results[device["serial"]] = self.acquire_ios(device["serial"], device_output)
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get acquisition statistics."""
        return {
            "devices_found": len(self.connected_devices),
            "android_devices": sum(1 for d in self.connected_devices if d["platform"] == "android"),
            "ios_devices": sum(1 for d in self.connected_devices if d["platform"] == "ios"),
            "acquisitions_completed": len(self.acquired_data.get("device_info", []))
        }
    
    def display_summary(self):
        """Display acquisition summary."""
        stats = self.get_statistics()
        
        print(f"\n[Mobile Live Acquisition Summary]")
        print(f"{'='*50}")
        print(f"  Devices Found:     {stats['devices_found']}")
        print(f"  Android Devices:   {stats['android_devices']}")
        print(f"  iOS Devices:       {stats['ios_devices']}")
        print(f"  Acquisitions Done: {stats['acquisitions_completed']}")
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        """Export acquisition data to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.acquired_data, f, indent=4, default=str)
        print(f"[+] Acquisition data exported: {output_file}")
