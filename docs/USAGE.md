# HyperTraceX Usage Guide

## Table of Contents
1. Quick Start
2. Case Management
3. Evidence Acquisition
4. Artifact Extraction
5. Analysis Tools
6. Reporting
7. Enterprise Features
8. Plugin Development
9. Troubleshooting

---

## Quick Start

### Installation
git clone https://github.com/raffelsfuxk/HyperTraceX.git && cd HyperTraceX && sudo bash install.sh

### First Run
sudo tracex

### Command Help
sudo tracex --help
sudo tracex [command] --help

---

## Case Management

### Create New Case
sudo tracex case-create --id CASE001 --investigator "John Doe" --org "Security Corp" --desc "Investigation"

### View All Cases
Interactive menu > View Case Status

### Close Case
Interactive menu > Close Case

---

## Evidence Acquisition

### Scan Drives
sudo tracex scan-drives

### Acquire Files
sudo tracex acquire --source /mnt/windows --dest ./evidence
sudo tracex acquire --source /mnt/windows --dest ./evidence --ext pdf,docx,xlsx,jpg

### Create Forensic Image
sudo tracex image --device /dev/sda1 --output ./case001.img

### Memory Dump
sudo tracex memory --output ./memdump.raw --method lime
sudo tracex memory --output ./memdump.raw --method proc
sudo tracex memory --output ./memdump.raw --method devmem

---

## Artifact Extraction

### Windows Registry
sudo tracex registry --hive SAM --type sam
sudo tracex registry --hive SYSTEM --type system
sudo tracex registry --hive SOFTWARE --type all

### Browser Forensics
sudo tracex browser --profile /mnt/Windows/Users
sudo tracex browser --profile /mnt/Windows/Users --browsers chrome,firefox,edge

### Email Extraction
sudo tracex email --source mailbox.pst --type pst
sudo tracex email --source inbox.mbox --type mbox

### WiFi Passwords
sudo tracex wifi --mount /mnt/windows

---

## Analysis Tools

### File Carving
sudo tracex carve --source disk.img --output ./carved
sudo tracex carve --source disk.img --output ./carved --types jpg,png,pdf,docx

### Hash Verification
sudo tracex verify --file evidence.txt --hash abc123def456 --algo sha256
sudo tracex verify --file evidence.txt --hash abc123 --algo md5
sudo tracex verify --file evidence.txt --hash abc123 --algo sha1

### Hash Lookup
sudo tracex hash-lookup --hash abc123def456

### Signature Analysis
Python API:
from modules.analysis.signature_analyzer import SignatureAnalyzer
analyzer = SignatureAnalyzer()
result = analyzer.identify_file("suspicious.exe")

### Timeline Generation
Python API:
from modules.analysis.timeline_generator import TimelineGenerator
tl = TimelineGenerator()
tl.scan_filesystem("/mnt/windows")
tl.sort_timeline()
tl.display_timeline()

---

## Reporting

### HTML Report
sudo tracex report --format html --output investigation_report.html

### JSON Report
sudo tracex report --format json --output investigation_report.json

### PDF Report
Python API:
from reporting.pdf_reporter import PDFReporter
reporter = PDFReporter()
reporter.set_case_info("CASE001", "John Doe", "Security Corp")
reporter.add_evidence(evidence_list)
reporter.generate("report.pdf")

---

## Enterprise Features

### Multi-User Management
from enterprise.multi_user import MultiUserManager
users = MultiUserManager()
users.create_user("investigator1", "password123", "investigator", "Jane Smith")
session = users.authenticate("investigator1", "password123")

### Chain of Custody
from enterprise.chain_of_custody import ChainOfCustody
coc = ChainOfCustody("CASE001")
coc.register_evidence("EVID001", "Laptop HDD", "/evidence/disk.img", "John Doe", "Server Room")
coc.log_transfer("EVID001", "TRANSFERRED", "Jane Smith", "Lab Room 2")
coc.verify_integrity("EVID001")
coc.generate_report("custody_report.txt")

### Audit Logging
from enterprise.audit_logging import AuditLogger
audit = AuditLogger()
audit.log_event("admin", "CASE_CREATED", "Investigation started", case_id="CASE001")
audit.log_user_login("admin", True, "192.168.1.100")
audit.display_summary()

### REST API
from enterprise.api_server import APIServer
api = APIServer(engine, host="0.0.0.0", port=5000)
api.start()

### Web Dashboard
sudo tracex dashboard
Open: http://127.0.0.1:8888

---

## Plugin Development

### Template
from plugins.contrib_plugin import ContribPlugin

class MyPlugin(ContribPlugin):
    name = "My Custom Plugin"
    version = "1.0.0"
    author = "Your Name"
    description = "Custom forensic analysis plugin"
    
    def _execute(self, framework, **kwargs):
        drives = framework.scan_drives()
        for drive in drives:
            self.results.append(drive)
        return {"drives": len(drives)}

def register(plugin_manager):
    plugin_manager.register(MyPlugin())

### Load Plugin
Interactive menu > Load Plugins > Enter plugin directory

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied | sudo tracex |
| Missing dependencies | sudo bash install.sh |
| Database locked | pkill -f tracex && rm -f tracex.db-journal |
| Native module error | cd native && make clean && make all && make install |
| Flask not found | pip3 install flask flask-socketio --break-system-packages |
| fpdf not found | pip3 install fpdf --break-system-packages |
| Mount failed | Check filesystem: lsblk -f |
| Hash mismatch | Evidence may be compromised! |
| API port in use | Change port: api = APIServer(engine, port=9999) |

---

## Support

GitHub: https://github.com/raffelsfuxk/HyperTraceX
GitHub Issues: https://github.com/raffelsfuxk/HyperTraceX/issues
Author: raffelsfuxk
License: MIT
Copyright (c) 2024 raffelsfuxk - Ethical Hacker Lab
