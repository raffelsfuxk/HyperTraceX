#!/usr/bin/env python3
"""
HyperTraceX Community Contribution Plugin Template.
Use this template to create your own HyperTraceX plugins.
"""

from datetime import datetime
from typing import Dict, Any


class ContribPlugin:
    """
    Community Plugin Template for HyperTraceX.
    
    To create your plugin:
    1. Copy this file
    2. Rename to your_plugin.py
    3. Modify Plugin class below
    4. Place in plugins/ directory
    
    Required attributes:
        name: Unique plugin name
        version: Plugin version
        author: Your name
        description: What the plugin does
    
    Required methods:
        run(framework, **kwargs): Main plugin method
        get_info(): Return plugin metadata
    """
    
    name = "Community Plugin"
    version = "1.0.0"
    author = "Your Name"
    description = "Community contributed forensic plugin"
    
    def __init__(self):
        self.results = []
        self.running = False
    
    def run(self, framework: Any, **kwargs) -> Dict[str, Any]:
        """
        Main plugin execution method.
        
        Args:
            framework: HyperTraceX ForensixEngine instance
            **kwargs: Additional arguments
        
        Returns:
            Dict with execution results
        """
        self.running = True
        start_time = datetime.now()
        
        print(f"\n[*] Running {self.name} v{self.version}")
        print(f"    Author: {self.author}")
        print(f"    Description: {self.description}")
        
        try:
            self._execute(framework, **kwargs)
            
            return {
                "plugin": self.name,
                "version": self.version,
                "status": "completed",
                "results": self.results,
                "execution_time": str(datetime.now() - start_time)
            }
        except Exception as e:
            return {
                "plugin": self.name,
                "version": self.version,
                "status": "failed",
                "error": str(e),
                "execution_time": str(datetime.now() - start_time)
            }
        finally:
            self.running = False
    
    def _execute(self, framework: Any, **kwargs):
        """
        Your custom logic here.
        
        Access framework features:
            - framework.scan_drives()
            - framework.acquire_file()
            - framework.calculate_hash()
            - framework.db (DatabaseManager)
            - framework.logger
        """
        # Example: Quick drive scan
        if hasattr(framework, 'scan_drives'):
            drives = framework.scan_drives()
            
            for drive in drives:
                self.results.append({
                    "device": drive.get("device", ""),
                    "size": drive.get("size", ""),
                    "filesystem": drive.get("filesystem", ""),
                    "analyzed_at": datetime.now().isoformat()
                })
                
                if framework.logger:
                    framework.logger.info(f"Plugin analyzed: {drive.get('device')}")
        
        print(f"    Processed {len(self.results)} items")
    
    def get_info(self) -> Dict[str, str]:
        """Return plugin metadata."""
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description
        }
    
    def stop(self):
        """Stop plugin execution."""
        self.running = False
    
    def is_running(self) -> bool:
        """Check if plugin is running."""
        return self.running


def register(plugin_manager):
    """
    Register this plugin with HyperTraceX framework.
    
    This function is called automatically when HyperTraceX loads plugins.
    """
    plugin_manager.register(ContribPlugin())
