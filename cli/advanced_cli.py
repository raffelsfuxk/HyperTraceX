#!/usr/bin/env python3
"""HyperTraceX Advanced CLI - Interactive command-line interface with auto-complete."""

import os
import sys
import cmd
import json
import glob
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.engine import ForensixEngine
except ImportError:
    pass


class AdvancedCLI(cmd.Cmd):
    """
    HyperTraceX Advanced Command-Line Interface.
    
    Features:
        - Tab auto-complete
        - Command history
        - Colored output
        - Interactive help
        - Shell integration
        - Batch processing
    """
    
    intro = """
    ╔══════════════════════════════════════════════════════════╗
    ║     HyperTraceX Interactive Console v1.0.0                  ║
    ║     Type 'help' for available commands                   ║
    ║     Type 'exit' to quit                                 ║
    ╚══════════════════════════════════════════════════════════╝
    """
    prompt = "HyperTraceX> "
    
    def __init__(self, engine=None):
        super().__init__()
        self.engine = engine
        self.current_case = None
        self.history_file = os.path.expanduser("~/.tracex_history")
        self._load_history()
    
    def _load_history(self):
        """Load command history."""
        try:
            import readline
            if os.path.exists(self.history_file):
                readline.read_history_file(self.history_file)
        except ImportError:
            pass
    
    def _save_history(self):
        """Save command history."""
        try:
            import readline
            readline.write_history_file(self.history_file)
        except ImportError:
            pass
    
    # ==================== Case Commands ====================
    
    def do_case_create(self, arg):
        """Create a new forensic case: case create <id> <investigator> [org] [description]"""
        args = arg.split()
        if len(args) < 2:
            print("[!] Usage: case create <id> <investigator> [org] [description]")
            return
        
        case_id = args[0]
        investigator = args[1]
        org = args[2] if len(args) > 2 else ""
        desc = " ".join(args[3:]) if len(args) > 3 else ""
        
        if self.engine:
            self.engine.create_case(case_id, investigator, org, desc)
            self.current_case = case_id
            print(f"[+] Active case: {case_id}")
    
    def do_case_list(self, arg):
        """List all cases"""
        if self.engine and self.engine.db:
            cases = self.engine.db.get_all_cases()
            if not cases:
                print("[*] No cases found")
                return
            
            print(f"\n{'ID':<5} {'Case ID':<20} {'Investigator':<20} {'Status':<12} {'Created'}")
            print("=" * 80)
            for case in cases:
                print(f"{case['id']:<5} {case['case_id']:<20} {case['investigator']:<20} "
                      f"{case['status']:<12} {case['created_at'][:19]}")
            print(f"\nTotal: {len(cases)} cases")
    
    def do_case_info(self, arg):
        """Show current case information"""
        if not self.current_case:
            print("[!] No active case. Use 'case create' first")
            return
        
        if self.engine and self.engine.db:
            case = self.engine.db.get_case(self.current_case)
            if case:
                print(f"\n[Case Information]")
                print(f"  Case ID:      {case['case_id']}")
                print(f"  Investigator: {case['investigator']}")
                print(f"  Organization: {case.get('organization', 'N/A')}")
                print(f"  Status:       {case['status']}")
                print(f"  Created:      {case['created_at'][:19]}")
    
    # ==================== Evidence Commands ====================
    
    def do_evidence_list(self, arg):
        """List evidence for current case"""
        if not self.current_case:
            print("[!] No active case")
            return
        
        if self.engine and self.engine.db:
            case = self.engine.db.get_case(self.current_case)
            if case:
                evidence = self.engine.db.get_case_evidence(case["id"])
                if not evidence:
                    print("[*] No evidence items")
                    return
                
                print(f"\n{'ID':<5} {'File':<40} {'Size':<10} {'Hash'}")
                print("=" * 80)
                for ev in evidence[:20]:
                    print(f"{ev['id']:<5} {ev['file_path'][:38]:<40} "
                          f"{ev['file_size']:<10} {ev.get('sha256_hash', 'N/A')[:16]}")
                print(f"\nTotal: {len(evidence)} items")
    
    def do_evidence_add(self, arg):
        """Add evidence: evidence add <file_path>"""
        if not arg:
            print("[!] Usage: evidence add <file_path>")
            return
        
        filepath = arg.strip()
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return
        
        if self.engine and self.current_case:
            result = self.engine.acquire_file(filepath, filepath)
            if result:
                print(f"[+] Evidence acquired: {os.path.basename(filepath)}")
                print(f"    Size: {result['size']} bytes")
                print(f"    SHA256: {result['sha256'][:32]}...")
    
    def do_evidence_search(self, arg):
        """Search evidence: evidence search <keyword>"""
        if not arg:
            print("[!] Usage: evidence search <keyword>")
            return
        
        if self.engine and self.engine.db and self.current_case:
            case = self.engine.db.get_case(self.current_case)
            if case:
                results = self.engine.db.search_evidence(case["id"], arg.strip())
                print(f"\n[Search Results for '{arg}']")
                for r in results:
                    print(f"  {r['file_path']}")
                print(f"\nFound: {len(results)} matches")
    
    # ==================== Analysis Commands ====================
    
    def do_scan_drives(self, arg):
        """Scan connected drives"""
        if self.engine:
            drives = self.engine.scan_drives()
            print(f"\n[Connected Drives]")
            for d in drives:
                print(f"  {d['device']:<12} {d['size']:<8} {d.get('filesystem', 'N/A')}")
    
    def do_analyze_file(self, arg):
        """Analyze a file: analyze file <filepath>"""
        if not arg:
            print("[!] Usage: analyze file <filepath>")
            return
        
        filepath = arg.strip()
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return
        
        print(f"[*] Analyzing: {filepath}")
        
        md5 = self.engine.calculate_hash(filepath, "md5") if self.engine else "N/A"
        sha256 = self.engine.calculate_hash(filepath, "sha256") if self.engine else "N/A"
        
        print(f"    Size:   {os.path.getsize(filepath)} bytes")
        print(f"    MD5:    {md5}")
        print(f"    SHA256: {sha256}")
    
    def do_hash_verify(self, arg):
        """Verify file hash: hash verify <file> <expected_hash> [algorithm]"""
        args = arg.split()
        if len(args) < 2:
            print("[!] Usage: hash verify <file> <expected_hash> [algorithm]")
            return
        
        filepath = args[0]
        expected = args[1]
        algo = args[2] if len(args) > 2 else "sha256"
        
        if self.engine:
            valid = self.engine.verify_file_integrity(filepath, expected, algo)
            print(f"[+] Verification: {'PASSED' if valid else 'FAILED'}")
    
    # ==================== Report Commands ====================
    
    def do_report_generate(self, arg):
        """Generate report: report generate <format> <output>"""
        args = arg.split()
        if len(args) < 2:
            print("[!] Usage: report generate <format> <output>")
            print("    Formats: json, html")
            return
        
        fmt = args[0]
        output = args[1]
        
        if self.engine:
            self.engine.export_report_json(output)
            print(f"[+] Report generated: {output}")
    
    # ==================== System Commands ====================
    
    def do_status(self, arg):
        """Show system status"""
        if self.engine:
            self.engine.display_status()
        else:
            print(f"[*] HyperTraceX v1.0.0")
            print(f"    Active Case: {self.current_case or 'None'}")
    
    def do_clear(self, arg):
        """Clear the screen"""
        os.system('clear' if os.name != 'nt' else 'cls')
    
    def do_shell(self, arg):
        """Execute shell command: shell <command>"""
        if arg:
            os.system(arg)
    
    def do_history(self, arg):
        """Show command history"""
        try:
            import readline
            for i in range(readline.get_current_history_length()):
                print(f"  {i+1}: {readline.get_history_item(i+1)}")
        except ImportError:
            print("[!] readline not available")
    
    def do_exit(self, arg):
        """Exit HyperTraceX console"""
        self._save_history()
        print("[*] Goodbye!")
        return True
    
    def do_quit(self, arg):
        """Exit HyperTraceX console"""
        return self.do_exit(arg)
    
    # Shortcuts
    def do_c(self, arg):
        """Shortcut for case"""
        self.do_case_create(arg)
    
    def do_ls(self, arg):
        """List files in directory"""
        path = arg or "."
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            if os.path.isdir(full_path):
                print(f"  [DIR]  {item}")
            else:
                size = os.path.getsize(full_path)
                print(f"  [FILE] {item} ({size} bytes)")
    
    def do_pwd(self, arg):
        """Print working directory"""
        print(os.getcwd())
    
    def do_cd(self, arg):
        """Change directory"""
        if arg:
            try:
                os.chdir(arg)
                print(os.getcwd())
            except Exception as e:
                print(f"[!] {e}")
    
    # Auto-complete
    def complete_case_create(self, text, line, begidx, endidx):
        return []
    
    def complete_evidence_add(self, text, line, begidx, endidx):
        """Auto-complete file paths."""
        before = line[:begidx]
        path = text or "."
        
        try:
            if os.path.isdir(path):
                items = [os.path.join(path, f) for f in os.listdir(path)]
            else:
                items = glob.glob(path + "*")
            
            return [item for item in items if item.startswith(path)]
        except:
            return []
    
    def default(self, line):
        """Handle unknown commands."""
        print(f"[!] Unknown command: {line}")
        print("    Type 'help' for available commands")
    
    def emptyline(self):
        """Do nothing on empty line."""
        pass


if __name__ == "__main__":
    cli = AdvancedCLI()
    try:
        cli.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Interrupted")
        cli._save_history()
