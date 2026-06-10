#!/usr/bin/env python3
"""
FORENSIX - Enterprise Digital Forensics Platform
Main Entry Point
Usage: sudo python3 forensix.py
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import ForensixEngine
from core.config import ConfigManager

__version__ = "1.0.0"

BANNER = """
    ╔══════════════════════════════════════════════════════════╗
    ║     FORENSIX - Enterprise Digital Forensics Platform     ║
    ║     Version """ + __version__ + """  |  Ethical Use Only                    ║
    ╚══════════════════════════════════════════════════════════╝
"""

def create_parser():
    parser = argparse.ArgumentParser(
        description="FORENSIX - Digital Forensics Acquisition & Analysis Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  sudo python3 forensix.py                                    # Interactive mode
  sudo python3 forensix.py case-create --id CASE001 --investigator "Name"
  sudo python3 forensix.py scan-drives                        # List all drives
  sudo python3 forensix.py acquire --source /mnt/windows --dest ./output
  sudo python3 forensix.py verify --file evidence.img --hash abc123
  sudo python3 forensix.py carve --source disk.img --output ./carved
  sudo python3 forensix.py report --format html --output report.html
  sudo python3 forensix.py wifi --mount /mnt/windows          # WiFi passwords
  sudo python3 forensix.py browser --profile /mnt/windows/Users
"""
    )
    
    parser.add_argument("-v", "--version", action="version", version=f"FORENSIX v{__version__}")
    
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # case-create
    case_parser = subparsers.add_parser("case-create", help="Create new case")
    case_parser.add_argument("--id", required=True, help="Case ID")
    case_parser.add_argument("--investigator", required=True, help="Investigator name")
    case_parser.add_argument("--org", default="", help="Organization")
    case_parser.add_argument("--desc", default="", help="Description")
    
    # scan-drives
    subparsers.add_parser("scan-drives", help="Scan connected drives")
    
    # acquire
    acquire_parser = subparsers.add_parser("acquire", help="Acquire evidence")
    acquire_parser.add_argument("--source", required=True, help="Source directory")
    acquire_parser.add_argument("--dest", required=True, help="Destination directory")
    acquire_parser.add_argument("--ext", default="", help="File extensions (comma separated)")
    
    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify file integrity")
    verify_parser.add_argument("--file", required=True, help="File to verify")
    verify_parser.add_argument("--hash", required=True, help="Expected hash")
    verify_parser.add_argument("--algo", default="sha256", help="Hash algorithm")
    
    # carve
    carve_parser = subparsers.add_parser("carve", help="Carve files from image")
    carve_parser.add_argument("--source", required=True, help="Source image file")
    carve_parser.add_argument("--output", required=True, help="Output directory")
    carve_parser.add_argument("--types", default="", help="File types (jpg,png,pdf,docx)")
    
    # image
    image_parser = subparsers.add_parser("image", help="Create forensic image")
    image_parser.add_argument("--device", required=True, help="Source device")
    image_parser.add_argument("--output", required=True, help="Output image file")
    
    # memory
    mem_parser = subparsers.add_parser("memory", help="Capture memory dump")
    mem_parser.add_argument("--output", default="./memory_dump.raw", help="Output file")
    mem_parser.add_argument("--method", default="lime", choices=["lime", "proc", "devmem"], help="Capture method")
    
    # wifi
    wifi_parser = subparsers.add_parser("wifi", help="Extract WiFi passwords")
    wifi_parser.add_argument("--mount", required=True, help="Windows mount point")
    
    # browser
    browser_parser = subparsers.add_parser("browser", help="Extract browser artifacts")
    browser_parser.add_argument("--profile", required=True, help="Users profile path")
    browser_parser.add_argument("--browsers", default="chrome,firefox,edge", help="Browsers to extract")
    
    # email
    email_parser = subparsers.add_parser("email", help="Extract emails")
    email_parser.add_argument("--source", required=True, help="PST/MBOX file")
    email_parser.add_argument("--type", default="auto", choices=["pst", "mbox", "auto"], help="File type")
    
    # registry
    reg_parser = subparsers.add_parser("registry", help="Parse registry hive")
    reg_parser.add_argument("--hive", required=True, help="Registry hive path")
    reg_parser.add_argument("--type", default="sam", choices=["sam", "system", "software", "all"], help="Hive type")
    
    # hash-lookup
    hash_parser = subparsers.add_parser("hash-lookup", help="Lookup hash in database")
    hash_parser.add_argument("--hash", required=True, help="Hash value")
    
    # report
    report_parser = subparsers.add_parser("report", help="Generate report")
    report_parser.add_argument("--format", default="html", choices=["json", "html"], help="Report format")
    report_parser.add_argument("--output", required=True, help="Output file")

    # status
    subparsers.add_parser("status", help="Show framework status")

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        print(BANNER)
        engine = ForensixEngine()
        engine.check_root()
        engine.check_dependencies()
        
        try:
            while engine.interactive_menu():
                pass
        except KeyboardInterrupt:
            engine.shutdown()
        return
    
    engine = ForensixEngine()
    engine.check_root()
    engine.check_dependencies()
    
    try:
        if args.command == "case-create":
            engine.create_case(args.id, args.investigator, args.org, args.desc)
            
        elif args.command == "scan-drives":
            drives = engine.scan_drives()
            print(f"\n[Connected Drives]")
            for d in drives:
                print(f"  {d['device']:<12} {d['size']:<8} {d.get('filesystem', 'N/A'):<10}")
            
        elif args.command == "acquire":
            exts = [e.strip() for e in args.ext.split(',')] if args.ext else None
            results = engine.acquire_directory(args.source, args.dest, exts)
            print(f"\n[+] Acquired {len(results)} files")
            
        elif args.command == "verify":
            valid = engine.verify_file_integrity(args.file, args.hash, args.algo)
            print(f"\n[+] Integrity: {'PASSED' if valid else 'FAILED'}")
            
        elif args.command == "carve":
            from modules.analysis.file_carver import FileCarver
            carver = FileCarver()
            types = [t.strip() for t in args.types.split(',')] if args.types else None
            carver.carve_from_file(args.source, args.output, types)
            
        elif args.command == "image":
            from modules.acquisition.disk_imager import DiskImager
            imager = DiskImager()
            imager.create_raw_image(args.device, args.output)
            
        elif args.command == "memory":
            from modules.acquisition.memory_dumper import MemoryDumper
            dumper = MemoryDumper()
            if args.method == "lime":
                dumper.dump_with_lime(args.output)
            elif args.method == "proc":
                dumper.dump_proc_kcore(args.output)
            elif args.method == "devmem":
                dumper.dump_dev_mem(args.output)
                
        elif args.command == "wifi":
            from modules.artifacts.wifi_extractor import WiFiExtractor
            extractor = WiFiExtractor()
            extractor.extract_from_mount(args.mount)
            extractor.display_profiles()
            
        elif args.command == "browser":
            from modules.artifacts.browser_forensics import BrowserForensics
            browsers = [b.strip() for b in args.browsers.split(',')]
            browser_forensics = BrowserForensics()
            browser_forensics.extract_all(args.profile, browsers)
            browser_forensics.display_summary()
            
        elif args.command == "email":
            from modules.artifacts.email_extractor import EmailExtractor
            extractor = EmailExtractor()
            if args.type == "pst" or (args.type == "auto" and args.source.endswith('.pst')):
                extractor.extract_pst(args.source)
            elif args.type == "mbox" or (args.type == "auto" and args.source.endswith('.mbox')):
                extractor.extract_mbox(args.source)
            extractor.display_summary()
            
        elif args.command == "registry":
            from modules.artifacts.registry_parser import RegistryParser
            reg = RegistryParser()
            if args.type in ["sam", "all"]:
                reg.parse_sam_hive(args.hive)
            if args.type in ["system", "all"]:
                reg.parse_system_hive(args.hive)
            reg.display_users()
            
        elif args.command == "hash-lookup":
            from modules.analysis.hash_manager import HashManager
            hm = HashManager()
            results = hm.lookup_hash(args.hash)
            if results:
                for r in results:
                    print(f"  [{r.get('category', '?')}] {r.get('file_name', '?')}")
            else:
                print("[!] Hash not found in database")

                 elif args.command == "status":
            engine.display_status()
            
        elif args.command == "report":
            output = args.output
            if not output.endswith(f".{args.format}"):
                output = f"{output}.{args.format}"
            engine.export_report_json(output)

    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    finally:
        engine.shutdown()


if __name__ == "__main__":
    main()
