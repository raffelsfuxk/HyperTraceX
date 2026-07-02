# FORENSIX Wiki - Complete Documentation

## Overview
FORENSIX is an enterprise-grade digital forensics platform for forensic investigators, incident responders, and security professionals. Features include multi-platform acquisition, AI-powered analysis, enterprise multi-user support, chain of custody, REST API, plugin marketplace, and web dashboard.

## System Requirements
- Kali Linux / Parrot OS / Debian-based Linux
- Python 3.9+, 4GB RAM minimum (8GB recommended), 10GB free disk space

## Quick Install
git clone https://github.com/raffelsfuxk/FORENSIX.git && cd FORENSIX && sudo bash install.sh && sudo forensix

## Architecture
FORENSIX follows a modular architecture: core engine, acquisition modules, artifact extraction, analysis tools, AI/ML, enterprise features, reporting, dashboard, GUI, CLI, native C++ modules, plugins, and comprehensive tests.

## Module Reference

### Core: engine.py, database.py, config.py, logger.py, error_handler.py
### Acquisition: disk_imager.py, partition_scanner.py, memory_dumper.py
### Artifacts: registry_parser.py, browser_forensics.py, email_extractor.py, wifi_extractor.py
### Analysis: file_carver.py, mft_parser.py, hash_manager.py, timeline_generator.py, signature_analyzer.py
### AI: image_classifier.py, document_analyzer.py, anomaly_detector.py
### Enterprise: chain_of_custody.py, multi_user.py, audit_logging.py, api_server.py
### Advanced: android_parser.py, ios_parser.py, chat_extractor.py, cloud_scanner.py, network_forensics.py, malware_analyzer.py, memory_forensics.py, database_forensics.py, social_forensics.py, blockchain_forensics.py

## Plugin Development Quick Start
Create a class with name, version, author, description, run(), and get_info() methods. Place in plugins/ directory. Use register() function to expose to framework.

## Contributing
Fork repo, create feature branch, commit changes, push, open Pull Request. Follow PEP 8, 120 char limit, docstrings, type hints, and unit tests.

## FAQ
Q: Install? A: git clone && sudo bash install.sh
Q: Permissions? A: Root required for disk/network access
Q: Windows? A: Use WSL2 or VM
Q: Create plugin? A: Copy plugins/contrib_plugin.py
Q: Report bug? A: GitHub Issues
Q: Court-admissible? A: Includes chain of custody, follow local laws
Q: Docker? A: docker build -t forensix . && docker run -it --privileged forensix
Q: Update? A: git pull && sudo bash install.sh

## Support
GitHub Issues: https://github.com/raffelsfuxk/FORENSIX/issues
Author: raffelsfuxk
License: MIT
Version: 1.0.0
