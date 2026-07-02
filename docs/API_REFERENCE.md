# HyperTraceX API Reference

## Core Engine API

### ForensixEngine

```python
from core.engine import ForensixEngine

engine = ForensixEngine()
engine.check_root()
engine.check_dependencies()

# Case Management
case_id = engine.create_case("CASE001", "Investigator", "Org", "Description")
engine.close_case("CASE001")

# Drive Operations
drives = engine.scan_drives()
windows = engine.find_windows_partitions()

# Evidence Acquisition
result = engine.acquire_file("/source/file.txt", "/dest/file.txt")
results = engine.acquire_directory("/source/", "/dest/", extensions=["pdf", "docx"])

# Hash Operations
hash_value = engine.calculate_hash("/path/to/file", "sha256")
is_valid = engine.verify_file_integrity("/path/to/file", "expected_hash", "sha256")

# Reporting
report = engine.generate_case_report("CASE001")
engine.export_report_json("/path/to/report.json", "CASE001")
Database Manager API
python
from core.database import DatabaseManager

db = DatabaseManager("tracex.db")

# Cases
case_pk = db.create_case("CASE001", "Investigator", "Org", "Description")
case = db.get_case("CASE001")
all_cases = db.get_all_cases()
db.close_case("CASE001")

# Evidence
ev_id = db.add_evidence(case_pk, "/path/to/file", "/original/path", 1024, "md5", "sha1", "sha256")
evidence = db.get_case_evidence(case_pk)
results = db.search_evidence(case_pk, "keyword")

# Chain of Custody
custody_id = db.add_custody_entry(ev_id, "COLLECTED", "Officer", "Location", "Notes")
chain = db.get_custody_chain(ev_id)

# Audit
db.log_audit(case_pk, "ACTION", "User", "Details")
audit_log = db.get_audit_log(case_pk)

# Statistics
stats = db.get_case_stats(case_pk)
db.close()
Acquisition Modules
DiskImager
python
from modules.acquisition.disk_imager import DiskImager

imager = DiskImager()

# Create raw image
hash_value = imager.create_raw_image("/dev/sda1", "/output/image.img")
hash_value = imager.create_raw_image("/dev/sda1", "/output/image.img", hash_algorithm="sha256", block_size="1M")

# Create split image
imager.create_split_image("/dev/sda1", "/output/image", split_size="2G")

# Verify image
is_valid = imager.verify_image("/output/image.img", "/output/image.img.sha256")

# Progress
progress = imager.get_progress()
imager.stop()
PartitionScanner
python
from modules.acquisition.partition_scanner import PartitionScanner

scanner = PartitionScanner()

# Scan
partitions = scanner.scan_all()

# Filter
windows = scanner.get_windows_partitions()
linux = scanner.get_linux_partitions()
unmounted = scanner.get_unmounted()
largest = scanner.get_largest_partitions(5)

# Mount
scanner.mount_readonly("/dev/sda1", "/mnt/evidence")
scanner.unmount("/mnt/evidence")

# Display
scanner.display_partitions()
summary = scanner.get_summary()
MemoryDumper
python
from modules.acquisition.memory_dumper import MemoryDumper

dumper = MemoryDumper()

# LiME dump
dumper.dump_with_lime("/output/memory.raw")

# /proc/kcore dump
dumper.dump_proc_kcore("/output/kcore.raw")

# /dev/mem dump
dumper.dump_dev_mem("/output/mem.raw", max_size_gb=4)

# Process memory
dumper.capture_process_memory(1234, "/output/process/")

# Swap
dumper.capture_swap("/output/swap.raw")

# Info
info = dumper.get_memory_info()
dumper.display_memory_info()
Artifact Modules
RegistryParser
python
from modules.artifacts.registry_parser import RegistryParser

reg = RegistryParser()

# Parse hives
users = reg.parse_sam_hive("/path/to/SAM")
system = reg.parse_system_hive("/path/to/SYSTEM")
software = reg.parse_software_hive("/path/to/SOFTWARE")
usb = reg.parse_usb_history("/path/to/SYSTEM")

# Display
reg.display_users()
reg.display_usb_history()

# Export
data = reg.get_all_data()
BrowserForensics
python
from modules.artifacts.browser_forensics import BrowserForensics

bf = BrowserForensics()

# Extract all
results = bf.extract_all("/mnt/Windows/Users")

# Extract specific
results = bf.extract_all("/mnt/Windows/Users", browsers=["chrome", "firefox"])

# With copy
results = bf.extract_all("/mnt/Windows/Users", copy_first=True, output_dir="/tmp/browser_data")

# Display
bf.display_summary()
EmailExtractor
python
from modules.artifacts.email_extractor import EmailExtractor

extractor = EmailExtractor()

# PST
emails = extractor.extract_pst("/path/to/mailbox.pst")
emails = extractor.extract_pst("/path/to/mailbox.pst", output_dir="/tmp/attachments")

# MBOX
emails = extractor.extract_mbox("/path/to/inbox.mbox")

# EML
email = extractor.extract_eml("/path/to/message.eml")

# Search
results = extractor.search_emails("password", field="body")

# Stats
stats = extractor.get_statistics()
extractor.display_summary()
WiFiExtractor
python
from modules.artifacts.wifi_extractor import WiFiExtractor

wifi = WiFiExtractor()

# Extract
profiles = wifi.extract_from_mount("/mnt/windows")

# Filter
open_nets = wifi.get_open_networks()
protected = wifi.get_protected_networks()
with_pass = wifi.get_networks_with_passwords()

# Search
results = wifi.search_profiles("HomeWiFi")

# Export
wifi.export_csv("wifi_profiles.csv")
wifi.display_profiles()
Analysis Modules
FileCarver
python
from modules.analysis.file_carver import FileCarver

carver = FileCarver()

# Carve files
carved = carver.carve_from_file("/path/to/disk.img", "/output/carved")
carved = carver.carve_from_file("/path/to/disk.img", "/output/carved", file_types=["jpg", "pdf"])

# Custom signature
carver.add_signature("custom", [b"MAGIC"], [b"END"], "Custom file")

# List signatures
sigs = carver.list_signatures()
carver.display_signatures()

# Stats
stats = carver.get_statistics()
HashManager
python
from modules.analysis.hash_manager import HashManager

hm = HashManager("hashes.db")

# Calculate
hashes = hm.calculate_hash("/path/to/file", ["md5", "sha256"])
batch = hm.calculate_hash_batch(["/file1", "/file2"])

# Verify
is_valid = hm.verify_file("/path/to/file", "expected_hash", "sha256")
same = hm.compare_files("/file1", "/file2")

# Known hashes
hm.add_known_hash("abc123", "sha256", "malware.exe", 1024, "malware")
results = hm.lookup_hash("abc123")
is_known, matches = hm.is_known_file("/path/to/file")

# Filter
known, unknown = hm.filter_known_files(["/file1", "/file2"])

# NSRL import
hm.import_nsrl("/path/to/NSRLFile.txt")

# Stats
stats = hm.get_statistics()
hm.display_statistics()
Enterprise API
ChainOfCustody
python
from enterprise.chain_of_custody import ChainOfCustody

coc = ChainOfCustody("CASE001")

# Register
coc.register_evidence("EVID001", "Description", "/path/to/evidence", "Collector", "Location")

# Transfer
coc.log_transfer("EVID001", "TRANSFERRED", "Handler", "Lab", "Notes")

# Verify
result = coc.verify_integrity("EVID001")
all_results = coc.verify_all()

# Reports
coc.generate_report("custody_report.txt")
coc.export_json("custody_data.json")
coc.display_report()
MultiUserManager
python
from enterprise.multi_user import MultiUserManager

users = MultiUserManager()

# Users
users.create_user("username", "password", "investigator", "Full Name", "email@example.com")
session = users.authenticate("username", "password")
users.logout(session["session_id"])

# Permissions
has_perm = users.check_permission(session["session_id"], "create_case")

# Management
users.list_users()
users.change_password("username", "old_pass", "new_pass")
users.delete_user("username")
users.set_user_role("username", "admin")
AuditLogger
python
from enterprise.audit_logging import AuditLogger

audit = AuditLogger("./audit_logs")

# Log events
audit.log_event("user", "ACTION", "Details", case_id="CASE001", severity="INFO")
audit.log_user_login("user", True, "192.168.1.1")
audit.log_evidence_action("user", "ACQUIRED", "EVID001", "CASE001")

# Reports
audit.display_summary()
audit.export_json("audit_report.json", days=30)
audit.generate_compliance_report("ISO27001")

# Maintenance
audit.cleanup_old_logs(retention_days=90)
AI Modules
ImageClassifier
python
from ai.image_classifier import ImageClassifier

classifier = ImageClassifier()

# Classify
result = classifier.classify_image("/path/to/image.jpg")
results = classifier.classify_directory("/path/to/images/")

# Filter
photos = classifier.find_by_category("photo")
with_gps = classifier.find_with_gps()
manipulated = classifier.find_manipulated()

# Stats
stats = classifier.get_statistics()
classifier.display_summary()
DocumentAnalyzer
python
from ai.document_analyzer import DocumentAnalyzer

analyzer = DocumentAnalyzer()

# Analyze
result = analyzer.analyze_file("/path/to/document.txt")
results = analyzer.analyze_directory("/path/to/docs/")

# Filter
sensitive = analyzer.get_sensitive_documents(min_score=50)
with_pii = analyzer.get_documents_with_pii()

# Stats
stats = analyzer.get_statistics()
analyzer.display_report()
AnomalyDetector
python
from ai.anomaly_detector import AnomalyDetector

detector = AnomalyDetector()

# Detect
anomalies = detector.analyze_filesystem("/path/to/scan")

# Filter
high = detector.filter_by_threat_level("HIGH")
severe = detector.filter_by_severity(7)

# Report
detector.display_report()
detector.export_report("anomaly_report.json")
Support
GitHub: https://github.com/raffelsfuxk/HyperTraceX

Author: raffelsfuxk

License: MIT
