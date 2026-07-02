# HyperTraceX - Enterprise Digital Forensics Platform

**Version:** 1.0.0  
**Author:** raffelsfuxk  
**License:** MIT

---

## Description

HyperTraceX is a professional digital forensics acquisition and analysis platform designed for Kali Linux and Parrot OS. It provides comprehensive forensic tools for evidence collection, analysis, and reporting.

---

## Features

### Acquisition
- Raw disk imaging with hash verification
- Memory dump (LiME, /proc/kcore, /dev/mem)
- File-level evidence collection
- Partition detection and analysis

### Artifact Extraction
- Windows Registry (SAM, SYSTEM, SOFTWARE)
- Browser forensics (Chrome, Firefox, Edge, Brave, Opera)
- Email extraction (PST, MBOX, EML)
- WiFi credential recovery
- USB device history
- Installed software enumeration

### Analysis
- File carving (header/footer based)
- Hash calculation and verification
- Known hash database lookup
- Timeline generation

### Enterprise
- Case management system
- Chain of custody tracking
- SQLite database for evidence
- Audit logging

### Reporting
- JSON reports
- HTML reports
- CSV export
- Statistics summaries

---

## Quick Install

```bash
git clone https://github.com/raffelsfuxk/HyperTraceX.git && cd HyperTraceX && sudo bash install.sh

Then run:
sudo tracex

Usage:
# Interactive mode
sudo tracex

# Command mode
sudo tracex case-create --id CASE001 --investigator "Name"
sudo tracex scan-drives
sudo tracex acquire --source /mnt/windows --dest ./output
sudo tracex wifi --mount /mnt/windows
sudo tracex browser --profile /mnt/windows/Users
sudo tracex email --source mailbox.pst
sudo tracex registry --hive SAM --type sam
sudo tracex carve --source disk.img --output ./carved
sudo tracex verify --file evidence.img --hash abc123
sudo tracex report --format html --output report.html

Disclamer:
FOR EDUCATIONAL AND AUTHORIZED USE ONLY!

This tool is designed for:

Digital forensics investigations

Incident response

Security research

Authorized penetration testing

Never use this tool on systems without proper authorization.

License:
MIT License - See LICENSE file for details

Copyright (c) 2024 raffelsfuxk 
