#!/usr/bin/env python3
"""Configuration Manager for FORENSIX Framework."""

import json
import os
from typing import Dict, Any, Optional

DEFAULT_CONFIG = {
    "version": "1.0.0",
    "case": {
        "case_id": "",
        "investigator": "",
        "organization": "",
        "description": ""
    },
    "storage": {
        "output_dir": "./output",
        "temp_dir": "/tmp/forensix",
        "evidence_drive": "auto",
        "min_free_space_gb": 10
    },
    "acquisition": {
        "mode": "logical",
        "hash_algorithms": ["sha256", "sha1", "md5"],
        "verify_after_copy": True,
        "preserve_timestamps": True,
        "max_file_size_gb": 4,
        "skip_system_files": True
    },
    "logging": {
        "level": "INFO",
        "file": "forensix.log",
        "max_size_mb": 100,
        "backup_count": 5
    },
    "chain_of_custody": {
        "enabled": True,
        "sign_reports": True
    },
    "dashboard": {
        "enabled": False,
        "host": "127.0.0.1",
        "port": 8888
    }
}

class ConfigManager:
    """Handle framework configuration."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = DEFAULT_CONFIG.copy()
        self.config_path = config_path or "config.json"
        
    def load_from_file(self, filepath: Optional[str] = None) -> Dict[str, Any]:
        path = filepath or self.config_path
        if os.path.isfile(path):
            try:
                with open(path, 'r') as f:
                    file_config = json.load(f)
                    self.config.update(file_config)
            except (json.JSONDecodeError, IOError) as e:
                print(f"[!] Error loading config: {e}")
        return self.config
    
    def load_default(self) -> Dict[str, Any]:
        self.load_from_file()
        return self.config
    
    def save_to_file(self, filepath: Optional[str] = None):
        path = filepath or self.config_path
        with open(path, 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        self.config[key] = value
    
    def __getitem__(self, key: str) -> Any:
        return self.config[key]
    
    def __setitem__(self, key: str, value: Any):
        self.config[key] = value
    
    def __contains__(self, key: str) -> bool:
        return key in self.config
