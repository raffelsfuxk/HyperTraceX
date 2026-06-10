#!/usr/bin/env python3
"""FORENSIX WiFi Extractor - Extract saved WiFi credentials from Windows."""

import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class WiFiExtractor:
    """
    WiFi Credential Extractor.
    
    Extracts saved WiFi profiles and passwords from Windows:
        - XML profiles (WlanSvc)
        - Registry wireless keys
        - netsh-equivalent extraction
    """
    
    # Windows WiFi profiles path
    WIFI_PROFILES_PATH = "ProgramData/Microsoft/Wlansvc/Profiles/Interfaces"
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.extracted_profiles: List[Dict] = []
    
    def extract_from_mount(self, mount_point: str) -> List[Dict]:
        """
        Extract WiFi profiles from mounted Windows drive.
        
        Args:
            mount_point: Mount point of Windows partition
        
        Returns:
            List of WiFi profile dictionaries
        """
        profiles_path = os.path.join(mount_point, self.WIFI_PROFILES_PATH)
        
        if not os.path.exists(profiles_path):
            self.logger.warning(f"WiFi profiles path not found: {profiles_path}")
            return []
        
        print(f"\n[*] Extracting WiFi Profiles")
        print(f"    Path: {profiles_path}\n")
        
        self.extracted_profiles.clear()
        
        # Find all interface GUID folders
        try:
            for interface_guid in os.listdir(profiles_path):
                interface_path = os.path.join(profiles_path, interface_guid)
                
                if not os.path.isdir(interface_path):
                    continue
                
                # Process each WiFi profile XML
                for filename in os.listdir(interface_path):
                    if not filename.endswith('.xml'):
                        continue
                    
                    xml_path = os.path.join(interface_path, filename)
                    profile = self._parse_wifi_xml(xml_path)
                    
                    if profile:
                        profile["interface_guid"] = interface_guid
                        profile["xml_file"] = filename
                        self.extracted_profiles.append(profile)
                        
                        print(f"  [{len(self.extracted_profiles)}] {profile['ssid']:<25} "
                              f"Auth: {profile['authentication']:<10} "
                              f"Enc: {profile['encryption']:<10}")
            
            print(f"\n[+] Extracted {len(self.extracted_profiles)} WiFi profiles")
            
        except Exception as e:
            self.logger.error(f"WiFi extraction failed: {e}")
        
        return self.extracted_profiles
    
    def _parse_wifi_xml(self, xml_path: str) -> Optional[Dict]:
        """Parse Windows WiFi profile XML."""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # Namespace handling
            ns = {'wlan': 'http://www.microsoft.com/networking/WLAN/profile/v1'}
            
            # Basic info
            name_elem = root.find('.//wlan:name', ns)
            ssid_elem = root.find('.//wlan:SSID/wlan:name', ns)
            
            ssid = ""
            if name_elem is not None:
                ssid = name_elem.text or ""
            if not ssid and ssid_elem is not None:
                # SSID might be hex-encoded
                hex_ssid = ssid_elem.text or ""
                if hex_ssid:
                    try:
                        ssid = bytes.fromhex(hex_ssid).decode('utf-8', errors='ignore')
                    except:
                        ssid = f"[hex:{hex_ssid}]"
            
            if not ssid:
                return None
            
            profile = {
                "ssid": ssid,
                "authentication": "Unknown",
                "encryption": "Unknown",
                "password": None,
                "protected": False,
                "auto_connect": False,
                "hidden": False
            }
            
            # Authentication
            auth_elem = root.find('.//wlan:authentication', ns)
            if auth_elem is not None:
                profile["authentication"] = auth_elem.text or "Unknown"
            
            # Encryption
            enc_elem = root.find('.//wlan:encryption', ns)
            if enc_elem is not None:
                profile["encryption"] = enc_elem.text or "Unknown"
            
            # Protected (password required)
            protected_elem = root.find('.//wlan:protected', ns)
            if protected_elem is not None:
                profile["protected"] = protected_elem.text.lower() == "true"
            
            # Auto-connect
            conn_elem = root.find('.//wlan:connectionMode', ns)
            if conn_elem is not None:
                profile["auto_connect"] = conn_elem.text == "auto"
            
            # Hidden network
            hidden_elem = root.find('.//wlan:nonBroadcast', ns)
            if hidden_elem is not None:
                profile["hidden"] = hidden_elem.text.lower() == "true"
            
            # Extract key material if present
            key_elem = root.find('.//wlan:keyMaterial', ns)
            if key_elem is not None and key_elem.text:
                profile["password"] = key_elem.text
                profile["protected"] = True
            
            # Shared key
            shared_key = root.find('.//wlan:sharedKey', ns)
            if shared_key is not None:
                protected_elem = shared_key.find('.//wlan:protected', ns)
                if protected_elem is not None:
                    profile["protected"] = protected_elem.text.lower() == "true"
                
                key_elem = shared_key.find('.//wlan:keyMaterial', ns)
                if key_elem is not None and key_elem.text:
                    profile["password"] = key_elem.text
            
            return profile
            
        except ET.ParseError as e:
            self.logger.debug(f"XML parse error in {xml_path}: {e}")
            return None
        except Exception as e:
            self.logger.debug(f"Profile parse error: {e}")
            return None
    
    def extract_from_registry(self, software_hive_path: str) -> List[Dict]:
        """
        Extract WiFi profiles from SOFTWARE registry hive.
        
        Args:
            software_hive_path: Path to SOFTWARE hive
        
        Returns:
            List of WiFi profile info (without passwords)
        """
        profiles = []
        
        if not os.path.exists(software_hive_path):
            self.logger.error(f"SOFTWARE hive not found: {software_hive_path}")
            return profiles
        
        try:
            from Registry import Registry
            reg = Registry.Registry(software_hive_path)
            
            # Navigate to wireless profiles
            try:
                interfaces_key = reg.open(
                    r"Microsoft\WlanSvc\Interfaces"
                )
                
                for interface in interfaces_key.subkeys():
                    try:
                        profiles_key = interface.subkey("Profiles")
                        if profiles_key:
                            for profile in profiles_key.subkeys():
                                profile_info = {
                                    "ssid": profile.name(),
                                    "interface_guid": interface.name(),
                                    "source": "registry"
                                }
                                profiles.append(profile_info)
                    except:
                        pass
            except:
                pass
            
        except ImportError:
            self.logger.warning("python-registry not installed")
        except Exception as e:
            self.logger.error(f"Registry extraction failed: {e}")
        
        return profiles
    
    def search_profiles(self, keyword: str) -> List[Dict]:
        """Search extracted profiles by SSID."""
        keyword_lower = keyword.lower()
        return [
            p for p in self.extracted_profiles
            if keyword_lower in p.get("ssid", "").lower()
        ]
    
    def get_open_networks(self) -> List[Dict]:
        """Get profiles without password protection."""
        return [p for p in self.extracted_profiles if not p.get("protected", False)]
    
    def get_protected_networks(self) -> List[Dict]:
        """Get profiles with password protection."""
        return [p for p in self.extracted_profiles if p.get("protected", False)]
    
    def get_networks_with_passwords(self) -> List[Dict]:
        """Get profiles where password was extracted."""
        return [p for p in self.extracted_profiles if p.get("password")]
    
    def get_statistics(self) -> Dict:
        """Get extraction statistics."""
        total = len(self.extracted_profiles)
        protected = len(self.get_protected_networks())
        open_nets = len(self.get_open_networks())
        with_pass = len(self.get_networks_with_passwords())
        
        auth_types = {}
        enc_types = {}
        
        for p in self.extracted_profiles:
            auth = p.get("authentication", "Unknown")
            enc = p.get("encryption", "Unknown")
            auth_types[auth] = auth_types.get(auth, 0) + 1
            enc_types[enc] = enc_types.get(enc, 0) + 1
        
        return {
            "total_profiles": total,
            "protected": protected,
            "open_networks": open_nets,
            "with_passwords": with_pass,
            "authentication_types": auth_types,
            "encryption_types": enc_types
        }
    
    def display_profiles(self):
        """Display extracted WiFi profiles."""
        if not self.extracted_profiles:
            print("\n[!] No WiFi profiles extracted.\n")
            return
        
        print(f"\n[WiFi Profiles]")
        print(f"{'='*80}")
        print(f"{'SSID':<25} {'Auth':<15} {'Enc':<10} {'Protected':<10} {'Password'}")
        print(f"{'='*80}")
        
        for p in self.extracted_profiles:
            pass_display = "Yes" if p.get("password") else ("Required" if p.get("protected") else "None")
            print(f"{p['ssid'][:24]:<25} "
                  f"{p.get('authentication', '?'):<15} "
                  f"{p.get('encryption', '?'):<10} "
                  f"{str(p.get('protected', False)):<10} "
                  f"{pass_display}")
        
        print(f"{'='*80}")
        print(f"Total: {len(self.extracted_profiles)} profiles\n")
    
    def export_csv(self, output_file: str):
        """Export profiles to CSV."""
        import csv
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["SSID", "Authentication", "Encryption", "Protected", "Password", "Interface GUID", "XML File"])
            
            for p in self.extracted_profiles:
                writer.writerow([
                    p.get("ssid", ""),
                    p.get("authentication", ""),
                    p.get("encryption", ""),
                    p.get("protected", False),
                    p.get("password", ""),
                    p.get("interface_guid", ""),
                    p.get("xml_file", "")
                ])
        
        print(f"[+] Profiles exported to: {output_file}")
