#!/usr/bin/env python3
"""HyperTraceX Registry Parser - Windows Registry Hive Analysis."""

import os
import struct
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class RegistryParser:
    """
    Windows Registry Hive Parser.
    
    Parses SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT hives
    for forensic evidence extraction.
    """
    
    # Common registry paths for forensic artifacts
    FORENSIC_PATHS = {
        "sam_users": r"SAM\Domains\Account\Users",
        "system_info": r"ControlSet001\Control\ComputerName\ComputerName",
        "timezone": r"ControlSet001\Control\TimeZoneInformation",
        "network_interfaces": r"ControlSet001\Services\Tcpip\Parameters\Interfaces",
        "usb_devices": r"ControlSet001\Enum\USB",
        "installed_software": r"Microsoft\Windows\CurrentVersion\Uninstall",
        "recent_docs": r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        "run_keys": r"Software\Microsoft\Windows\CurrentVersion\Run",
        "user_assist": r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        "typed_urls": r"Software\Microsoft\Internet Explorer\TypedURLs",
        "shellbags": r"Software\Microsoft\Windows\Shell\Bags",
        "wireless_profiles": r"Software\Microsoft\WlanSvc\Interfaces",
        "startup_programs": r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self._parsed_data: Dict[str, Any] = {}
    
    def parse_sam_hive(self, hive_path: str) -> List[Dict]:
        """
        Parse SAM hive for user account information.
        
        Extracts:
            - Username
            - RID (Relative Identifier)
            - Account creation time
            - Last login time
            - Password reset date
            - Account flags (disabled, locked, etc.)
            - Login count
        """
        users = []
        
        if not os.path.exists(hive_path):
            self.logger.error(f"SAM hive not found: {hive_path}")
            return users
        
        try:
            # Read SAM hive raw bytes
            with open(hive_path, 'rb') as f:
                data = f.read()
            
            # Parse using python-registry if available
            try:
                from Registry import Registry
                reg = Registry.Registry(hive_path)
                
                # Navigate to Users key
                try:
                    users_key = reg.open(r"SAM\Domains\Account\Users")
                    
                    for subkey in users_key.subkeys():
                        if subkey.name() == "Names":
                            continue
                        
                        user_info = {
                            "rid": subkey.name(),
                            "username": "",
                            "last_login": None,
                            "password_set": None,
                            "account_created": None,
                            "login_count": 0,
                            "flags": []
                        }
                        
                        # Get F value (contains user info)
                        try:
                            f_value = subkey.value("F")
                            if f_value and len(f_value.value()) >= 80:
                                raw = f_value.value()
                                
                                # Parse login count (offset 64, 2 bytes)
                                user_info["login_count"] = struct.unpack_from("<H", raw, 64)[0]
                                
                                # Parse dates (Windows FILETIME)
                                try:
                                    # Last login (offset 8, 8 bytes)
                                    ft = struct.unpack_from("<Q", raw, 8)[0]
                                    if ft > 0:
                                        user_info["last_login"] = self._filetime_to_datetime(ft)
                                    
                                    # Password set (offset 24, 8 bytes)
                                    ft = struct.unpack_from("<Q", raw, 24)[0]
                                    if ft > 0:
                                        user_info["password_set"] = self._filetime_to_datetime(ft)
                                    
                                    # Account created (offset 32, 8 bytes)
                                    ft = struct.unpack_from("<Q", raw, 32)[0]
                                    if ft > 0:
                                        user_info["account_created"] = self._filetime_to_datetime(ft)
                                except:
                                    pass
                                
                                # Parse flags (offset 56, 2 bytes)
                                flags = struct.unpack_from("<H", raw, 56)[0]
                                if flags & 0x0001:
                                    user_info["flags"].append("Account Disabled")
                                if flags & 0x0002:
                                    user_info["flags"].append("Password Not Required")
                                if flags & 0x0004:
                                    user_info["flags"].append("Temporary Duplicate Account")
                                if flags & 0x0008:
                                    user_info["flags"].append("Normal Account")
                                if flags & 0x0010:
                                    user_info["flags"].append("Password Does Not Expire")
                                if flags & 0x0040:
                                    user_info["flags"].append("Smart Card Required")
                                if flags & 0x0080:
                                    user_info["flags"].append("Trusted for Delegation")
                                if flags & 0x0200:
                                    user_info["flags"].append("Password Expired")
                        except:
                            pass
                        
                        users.append(user_info)
                    
                    # Get usernames from Names subkey
                    try:
                        names_key = reg.open(r"SAM\Domains\Account\Users\Names")
                        for name_subkey in names_key.subkeys():
                            username = name_subkey.name()
                            # Default value contains RID reference
                            try:
                                dv = name_subkey.value("")
                                if dv:
                                    rid_ref = dv.value()
                                    # Match username to user by RID
                                    for user in users:
                                        if user["rid"] == str(rid_ref):
                                            user["username"] = username
                                            break
                            except:
                                pass
                    except:
                        pass
                    
                except:
                    pass
                
            except ImportError:
                # Basic parsing without python-registry
                self.logger.warning("python-registry not installed. Using basic parsing.")
                users = self._basic_sam_parse(data)
            
        except Exception as e:
            self.logger.error(f"SAM parsing failed: {e}")
        
        self._parsed_data["sam_users"] = users
        return users
    
    def parse_system_hive(self, hive_path: str) -> Dict:
        """Parse SYSTEM hive for system information."""
        info = {
            "computer_name": "",
            "install_date": None,
            "timezone": "",
            "current_version": "",
            "product_name": ""
        }
        
        if not os.path.exists(hive_path):
            return info
        
        try:
            from Registry import Registry
            reg = Registry.Registry(hive_path)
            
            # Computer Name
            try:
                key = reg.open(r"ControlSet001\Control\ComputerName\ComputerName")
                info["computer_name"] = key.value("ComputerName").value()
            except:
                pass
            
            # Windows Version
            try:
                key = reg.open(r"ControlSet001\Control\Windows")
                info["current_version"] = key.value("CurrentVersion").value()
            except:
                pass
            
            # Product Name
            try:
                key = reg.open(r"ControlSet001\Control\ProductOptions")
                info["product_name"] = key.value("ProductName").value()
            except:
                pass
            
            # Timezone
            try:
                key = reg.open(r"ControlSet001\Control\TimeZoneInformation")
                info["timezone"] = key.value("TimeZoneKeyName").value()
            except:
                pass
            
        except ImportError:
            pass
        
        self._parsed_data["system_info"] = info
        return info
    
    def parse_usb_history(self, system_hive_path: str) -> List[Dict]:
        """Extract USB device connection history from SYSTEM hive."""
        devices = []
        
        if not os.path.exists(system_hive_path):
            return devices
        
        try:
            from Registry import Registry
            reg = Registry.Registry(system_hive_path)
            
            # USBSTOR enumeration
            try:
                usb_key = reg.open(r"ControlSet001\Enum\USBSTOR")
                
                for disk in usb_key.subkeys():
                    for serial in disk.subkeys():
                        device_info = {
                            "device_name": disk.name(),
                            "serial_number": serial.name(),
                            "friendly_name": "",
                            "first_connected": None,
                            "last_connected": None
                        }
                        
                        try:
                            # Get friendly name
                            friendly = serial.value("FriendlyName")
                            if friendly:
                                device_info["friendly_name"] = friendly.value()
                            
                            # Get properties subkey for timestamps
                            props = serial.subkey("Properties")
                            if props:
                                for prop in props.subkeys():
                                    if "0064" in prop.name():  # First install
                                        try:
                                            ts = prop.value("00000064")
                                            if ts and len(ts.value()) >= 8:
                                                ft = struct.unpack_from("<Q", ts.value(), 0)[0]
                                                device_info["first_connected"] = self._filetime_to_datetime(ft)
                                        except:
                                            pass
                                    elif "0066" in prop.name():  # Last connected
                                        try:
                                            ts = prop.value("00000066")
                                            if ts and len(ts.value()) >= 8:
                                                ft = struct.unpack_from("<Q", ts.value(), 0)[0]
                                                device_info["last_connected"] = self._filetime_to_datetime(ft)
                                        except:
                                            pass
                        except:
                            pass
                        
                        devices.append(device_info)
            except:
                pass
            
        except ImportError:
            pass
        
        self._parsed_data["usb_devices"] = devices
        return devices
    
    def parse_software_hive(self, hive_path: str) -> List[Dict]:
        """Extract installed software list from SOFTWARE hive."""
        software = []
        
        if not os.path.exists(hive_path):
            return software
        
        try:
            from Registry import Registry
            reg = Registry.Registry(hive_path)
            
            # Microsoft Uninstall
            for uninstall_path in [
                r"Microsoft\Windows\CurrentVersion\Uninstall",
                r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]:
                try:
                    uninstall_key = reg.open(uninstall_path)
                    
                    for app in uninstall_key.subkeys():
                        app_info = {
                            "name": "",
                            "publisher": "",
                            "version": "",
                            "install_date": "",
                            "uninstall_string": ""
                        }
                        
                        try:
                            app_info["name"] = app.value("DisplayName").value()
                        except:
                            pass
                        try:
                            app_info["publisher"] = app.value("Publisher").value()
                        except:
                            pass
                        try:
                            app_info["version"] = app.value("DisplayVersion").value()
                        except:
                            pass
                        try:
                            app_info["install_date"] = app.value("InstallDate").value()
                        except:
                            pass
                        
                        if app_info["name"]:
                            software.append(app_info)
                except:
                    pass
            
        except ImportError:
            pass
        
        self._parsed_data["installed_software"] = software
        return software
    
    def _filetime_to_datetime(self, filetime: int) -> Optional[datetime]:
        """Convert Windows FILETIME (100-nanosecond intervals since 1601-01-01) to datetime."""
        if filetime == 0:
            return None
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
        except:
            return None
    
    def _basic_sam_parse(self, data: bytes) -> List[Dict]:
        """Basic SAM parsing without external libraries."""
        users = []
        # Search for potential usernames (ASCII strings near RID values)
        # This is a simplified approach
        import re
        
        # Find potential usernames
        username_pattern = re.compile(rb'([A-Za-z0-9_\- ]{3,32})\x00\x00')
        matches = username_pattern.findall(data)
        
        for match in matches[:50]:  # Limit to 50
            try:
                username = match.decode('utf-8', errors='ignore')
                if username and username not in [u.get('username', '') for u in users]:
                    users.append({
                        "username": username,
                        "rid": "unknown",
                        "last_login": None,
                        "flags": ["basic_parse"]
                    })
            except:
                pass
        
        return users
    
    def get_all_data(self) -> Dict:
        """Return all parsed data."""
        return self._parsed_data
    
    def display_users(self):
        """Display parsed user accounts."""
        users = self._parsed_data.get("sam_users", [])
        if not users:
            print("\n[!] No user data parsed. Run parse_sam_hive() first.\n")
            return
        
        print(f"\n[User Accounts]")
        print(f"{'='*70}")
        print(f"{'Username':<20} {'RID':<8} {'Last Login':<20} {'Flags'}")
        print(f"{'='*70}")
        
        for user in users:
            flags = ', '.join(user.get('flags', [])) or 'None'
            last_login = user.get('last_login', 'N/A')
            if last_login and not isinstance(last_login, str):
                last_login = last_login.strftime('%Y-%m-%d %H:%M:%S') if last_login else 'N/A'
            
            print(f"{user.get('username', '?'):<20} "
                  f"{user.get('rid', '?'):<8} "
                  f"{str(last_login):<20} "
                  f"{flags}")
        
        print(f"{'='*70}")
        print(f"Total: {len(users)} users\n")
    
    def display_usb_history(self):
        """Display USB device history."""
        devices = self._parsed_data.get("usb_devices", [])
        if not devices:
            print("\n[!] No USB data parsed.\n")
            return
        
        print(f"\n[USB Device History]")
        print(f"{'='*80}")
        for i, dev in enumerate(devices[:20]):
            print(f"  [{i+1}] {dev.get('friendly_name', dev.get('device_name', 'Unknown'))}")
            print(f"      Serial: {dev.get('serial_number', 'N/A')}")
            first = dev.get('first_connected')
            last = dev.get('last_connected')
            if first:
                print(f"      First:  {first}")
            if last:
                print(f"      Last:   {last}")
        print(f"{'='*80}")
        print(f"Total: {len(devices)} devices\n")
