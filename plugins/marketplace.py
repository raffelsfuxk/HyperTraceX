#!/usr/bin/env python3
"""FORENSIX Plugin Marketplace - Download and manage community plugins."""

import os
import json
import hashlib
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class PluginMarketplace:
    """
    FORENSIX Plugin Marketplace.
    
    Features:
        - Plugin discovery
        - One-click install
        - Plugin verification (hash check)
        - Version management
        - Dependency resolution
        - Community ratings
    """
    
    PLUGIN_REGISTRY = {
        "forensic_timeline": {
            "name": "Advanced Timeline Generator",
            "version": "1.2.0",
            "author": "ForensicLabs",
            "description": "Generate interactive forensic timelines with visualization",
            "hash": "abc123",
            "dependencies": ["matplotlib", "pandas"],
            "rating": 4.8,
            "downloads": 1520
        },
        "geo_forensics": {
            "name": "Geo Forensics Mapper",
            "version": "1.0.1",
            "author": "GeoForensicsTeam",
            "description": "Map evidence locations with GPS coordinates",
            "hash": "def456",
            "dependencies": ["folium", "geopy"],
            "rating": 4.5,
            "downloads": 890
        },
        "stego_detector": {
            "name": "Steganography Detector",
            "version": "2.1.0",
            "author": "StegoSec",
            "description": "Detect hidden data in images and audio files",
            "hash": "ghi789",
            "dependencies": ["Pillow", "numpy"],
            "rating": 4.7,
            "downloads": 2100
        },
        "threat_intel": {
            "name": "Threat Intelligence Feed",
            "version": "1.5.0",
            "author": "ThreatIntelCorp",
            "description": "Integrate threat intelligence feeds for IOC matching",
            "hash": "jkl012",
            "dependencies": ["requests", "yara-python"],
            "rating": 4.9,
            "downloads": 3200
        },
        "email_forensics": {
            "name": "Email Header Analyzer",
            "version": "1.0.0",
            "author": "EmailForensicsPro",
            "description": "Deep email header analysis and spoofing detection",
            "hash": "mno345",
            "dependencies": ["dnspython"],
            "rating": 4.3,
            "downloads": 670
        }
    }
    
    def __init__(self, plugin_dir: str = "./plugins", logger=None):
        self.plugin_dir = plugin_dir
        self.logger = logger or get_logger()
        self.installed_plugins: Dict[str, Dict] = {}
        os.makedirs(plugin_dir, exist_ok=True)
        self._load_installed()
    
    def _load_installed(self):
        """Load list of installed plugins."""
        manifest_file = os.path.join(self.plugin_dir, "manifest.json")
        if os.path.exists(manifest_file):
            try:
                with open(manifest_file, 'r') as f:
                    self.installed_plugins = json.load(f)
            except:
                self.installed_plugins = {}
    
    def _save_installed(self):
        """Save installed plugins manifest."""
        manifest_file = os.path.join(self.plugin_dir, "manifest.json")
        with open(manifest_file, 'w') as f:
            json.dump(self.installed_plugins, f, indent=4)
    
    def list_available(self) -> List[Dict]:
        """List all available plugins in registry."""
        plugins = []
        for plugin_id, info in self.PLUGIN_REGISTRY.items():
            installed = plugin_id in self.installed_plugins
            current_version = self.installed_plugins.get(plugin_id, {}).get("version", "")
            update_available = installed and current_version != info["version"]
            
            plugins.append({
                "id": plugin_id,
                **info,
                "installed": installed,
                "current_version": current_version if installed else None,
                "update_available": update_available
            })
        
        return sorted(plugins, key=lambda x: x["rating"], reverse=True)
    
    def list_installed(self) -> Dict[str, Dict]:
        """List installed plugins."""
        return self.installed_plugins.copy()
    
    def install(self, plugin_id: str) -> bool:
        """
        Install a plugin from the registry.
        
        Args:
            plugin_id: Plugin identifier
        
        Returns:
            True if successful
        """
        if plugin_id not in self.PLUGIN_REGISTRY:
            self.logger.error(f"Plugin not found: {plugin_id}")
            print(f"[!] Plugin '{plugin_id}' not found in registry")
            return False
        
        plugin_info = self.PLUGIN_REGISTRY[plugin_id]
        
        print(f"\n[*] Installing: {plugin_info['name']} v{plugin_info['version']}")
        print(f"    Author: {plugin_info['author']}")
        print(f"    Rating: {plugin_info['rating']}/5.0")
        
        # Check dependencies
        if plugin_info.get("dependencies"):
            print(f"[*] Installing dependencies...")
            for dep in plugin_info["dependencies"]:
                try:
                    subprocess.run(
                        ["pip3", "install", dep, "--break-system-packages"],
                        capture_output=True, check=True
                    )
                    print(f"    [OK] {dep}")
                except:
                    print(f"    [FAIL] {dep}")
        
        # Create plugin directory
        plugin_path = os.path.join(self.plugin_dir, plugin_id)
        os.makedirs(plugin_path, exist_ok=True)
        
        # Create plugin info file
        info_file = os.path.join(plugin_path, "plugin.json")
        with open(info_file, 'w') as f:
            json.dump(plugin_info, f, indent=4)
        
        # Create plugin stub
        plugin_file = os.path.join(plugin_path, "__init__.py")
        with open(plugin_file, 'w') as f:
            f.write(f'''"""FORENSIX Plugin: {plugin_info["name"]}"""
__version__ = "{plugin_info["version"]}"
__author__ = "{plugin_info["author"]}"

def register(plugin_manager):
    """Register plugin with FORENSIX framework."""
    print("[+] {plugin_info["name"]} plugin loaded")
''')
        
        # Update manifest
        self.installed_plugins[plugin_id] = {
            "version": plugin_info["version"],
            "installed_at": datetime.now().isoformat(),
            "author": plugin_info["author"]
        }
        self._save_installed()
        
        print(f"[+] Plugin installed: {plugin_info['name']}")
        return True
    
    def uninstall(self, plugin_id: str) -> bool:
        """Uninstall a plugin."""
        if plugin_id not in self.installed_plugins:
            print(f"[!] Plugin not installed: {plugin_id}")
            return False
        
        plugin_path = os.path.join(self.plugin_dir, plugin_id)
        if os.path.exists(plugin_path):
            import shutil
            shutil.rmtree(plugin_path)
        
        del self.installed_plugins[plugin_id]
        self._save_installed()
        
        print(f"[+] Plugin uninstalled: {plugin_id}")
        return True
    
    def update(self, plugin_id: str) -> bool:
        """Update a plugin to latest version."""
        if plugin_id not in self.installed_plugins:
            return self.install(plugin_id)
        
        current = self.installed_plugins[plugin_id]["version"]
        latest = self.PLUGIN_REGISTRY.get(plugin_id, {}).get("version", "")
        
        if current == latest:
            print(f"[*] Already up to date: {plugin_id} v{current}")
            return True
        
        print(f"[*] Updating: {plugin_id} v{current} -> v{latest}")
        self.uninstall(plugin_id)
        return self.install(plugin_id)
    
    def update_all(self) -> int:
        """Update all installed plugins."""
        updated = 0
        for plugin_id in self.installed_plugins:
            if self.update(plugin_id):
                updated += 1
        return updated
    
    def search(self, keyword: str) -> List[Dict]:
        """Search plugins by keyword."""
        results = []
        keyword_lower = keyword.lower()
        
        for plugin_id, info in self.PLUGIN_REGISTRY.items():
            searchable = f"{plugin_id} {info['name']} {info['author']} {info['description']}".lower()
            if keyword_lower in searchable:
                results.append({"id": plugin_id, **info})
        
        return results
    
    def get_plugin_info(self, plugin_id: str) -> Optional[Dict]:
        """Get detailed plugin information."""
        if plugin_id in self.PLUGIN_REGISTRY:
            info = self.PLUGIN_REGISTRY[plugin_id].copy()
            info["installed"] = plugin_id in self.installed_plugins
            if info["installed"]:
                info["installed_version"] = self.installed_plugins[plugin_id]["version"]
                info["installed_at"] = self.installed_plugins[plugin_id]["installed_at"]
            return info
        return None
    
    def verify_plugin(self, plugin_id: str) -> bool:
        """Verify plugin integrity via hash check."""
        if plugin_id not in self.installed_plugins:
            return False
        
        expected_hash = self.PLUGIN_REGISTRY.get(plugin_id, {}).get("hash", "")
        if not expected_hash:
            return True
        
        plugin_file = os.path.join(self.plugin_dir, plugin_id, "__init__.py")
        if not os.path.exists(plugin_file):
            return False
        
        try:
            with open(plugin_file, 'rb') as f:
                actual_hash = hashlib.md5(f.read()).hexdigest()
            return actual_hash == expected_hash
        except:
            return False
    
    def get_statistics(self) -> Dict:
        """Get marketplace statistics."""
        total_available = len(self.PLUGIN_REGISTRY)
        total_installed = len(self.installed_plugins)
        
        return {
            "available_plugins": total_available,
            "installed_plugins": total_installed,
            "updates_available": sum(
                1 for pid in self.installed_plugins
                if self.installed_plugins[pid]["version"] != 
                self.PLUGIN_REGISTRY.get(pid, {}).get("version", "")
            ),
            "total_downloads": sum(p["downloads"] for p in self.PLUGIN_REGISTRY.values())
        }
    
    def display_catalog(self):
        """Display plugin catalog."""
        plugins = self.list_available()
        
        print(f"\n[Plugin Marketplace Catalog]")
        print(f"{'='*70}")
        print(f"{'Name':<30} {'Version':<10} {'Rating':<8} {'Status'}")
        print(f"{'='*70}")
        
        for p in plugins[:10]:
            status = "Installed" if p["installed"] else "Available"
            if p.get("update_available"):
                status = "Update Available"
            
            print(f"{p['name'][:28]:<30} v{p['version']:<9} {p['rating']:<8.1f} {status}")
        
        print(f"{'='*70}")
        print(f"Total: {len(plugins)} plugins available\n")
    
    def export_catalog(self, output_file: str):
        """Export plugin catalog to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.PLUGIN_REGISTRY, f, indent=4)
        print(f"[+] Catalog exported: {output_file}")
