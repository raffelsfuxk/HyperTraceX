# FORENSIX Frequently Asked Questions

## General

**Q: What is FORENSIX?**
A: FORENSIX is an enterprise-grade digital forensics platform for forensic acquisition, analysis, and reporting. It supports Windows, Linux, Mac, mobile, cloud, IoT, drone, vehicle, and SCADA forensics.

**Q: Who created FORENSIX?**
A: raffelsfuxk - Ethical Hacker Lab

**Q: Is FORENSIX free?**
A: Yes! FORENSIX is open-source under MIT License.

## Installation

**Q: How to install?**
A: git clone https://github.com/raffelsfuxk/FORENSIX.git && cd FORENSIX && sudo bash install.sh

**Q: Requirements?**
A: Kali/Parrot/Debian Linux, Python 3.9+, 4GB RAM, 10GB disk

**Q: Docker support?**
A: Yes! docker build -t forensix . && docker run -it --privileged forensix

## Usage

**Q: How to start?**
A: sudo forensix or sudo python3 forensix.py

**Q: How to scan drives?**
A: sudo forensix scan-drives

**Q: How to extract browser data?**
A: sudo forensix browser --profile /mnt/Windows/Users

**Q: How to crack WiFi passwords?**
A: sudo forensix wifi --mount /mnt/windows

**Q: How to generate report?**
A: sudo forensix report --format html --output report.html

## Features

**Q: What file systems are supported?**
A: NTFS, FAT32, exFAT, ext2/3/4, HFS+, APFS (read-only)

**Q: Does it support cloud forensics?**
A: Yes! OneDrive, Google Drive, Dropbox, iCloud, Box

**Q: Does it support mobile forensics?**
A: Yes! Android (ADB backups, SQLite) and iOS (iTunes backups)

**Q: Does it have AI features?**
A: Yes! Image classification, document analysis, anomaly detection

**Q: Can I create plugins?**
A: Yes! See plugins/contrib_plugin.py for template

## Troubleshooting

**Q: Permission denied?**
A: Run with sudo. FORENSIX requires root for disk access.

**Q: Module not found?**
A: Run sudo bash install.sh to install all dependencies.

**Q: Database locked?**
A: pkill -f forensix && rm -f forensix.db-journal

**Q: Flask not found?**
A: pip3 install flask flask-socketio --break-system-packages

**Q: Native module error?**
A: cd native && make clean && make all && make install

## Legal

**Q: Is FORENSIX court-admissible?**
A: FORENSIX includes chain of custody and integrity verification. Follow local legal procedures.

**Q: Can I use this for unauthorized access?**
A: NO! FORENSIX is for authorized forensic investigations only. Unauthorized use is illegal.

## Support

GitHub: https://github.com/raffelsfuxk/FORENSIX
Issues: https://github.com/raffelsfuxk/FORENSIX/issues
Author: raffelsfuxk
