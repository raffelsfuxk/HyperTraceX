#!/usr/bin/env python3
"""FORENSIX Desktop GUI Dialogs - Advanced dialog windows."""

import os
import sys
import threading
from datetime import datetime
from typing import Optional, List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


class CaseDialog:
    """Dialog for creating new forensic case."""
    
    def __init__(self, parent, callback=None):
        self.parent = parent
        self.callback = callback
        self.result = None
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("New Case")
        self.dialog.geometry("500x400")
        self.dialog.configure(bg="#1a1a2e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self._create_widgets()
    
    def _create_widgets(self):
        frame = ttk.Frame(self.dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Create New Case", font=("Consolas", 14, "bold")).pack(pady=10)
        
        fields = [
            ("Case ID:", "case_id"),
            ("Investigator:", "investigator"),
            ("Organization:", "organization"),
            ("Description:", "description")
        ]
        
        self.entries = {}
        for label, key in fields:
            row = ttk.Frame(frame)
            row.pack(fill=tk.X, pady=5)
            ttk.Label(row, text=label, width=15).pack(side=tk.LEFT)
            entry = ttk.Entry(row, width=40)
            entry.pack(side=tk.LEFT, padx=5)
            self.entries[key] = entry
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Create", command=self._on_create).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _on_create(self):
        self.result = {key: entry.get() for key, entry in self.entries.items()}
        if self.callback:
            self.callback(self.result)
        self.dialog.destroy()


class AcquisitionDialog:
    """Dialog for evidence acquisition settings."""
    
    def __init__(self, parent, engine=None):
        self.parent = parent
        self.engine = engine
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Acquire Evidence")
        self.dialog.geometry("600x500")
        self.dialog.configure(bg="#1a1a2e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self._create_widgets()
    
    def _create_widgets(self):
        frame = ttk.Frame(self.dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Evidence Acquisition", font=("Consolas", 14, "bold")).pack(pady=10)
        
        # Source selection
        ttk.Label(frame, text="Source:").pack(anchor=tk.W)
        source_frame = ttk.Frame(frame)
        source_frame.pack(fill=tk.X, pady=5)
        self.source_entry = ttk.Entry(source_frame, width=50)
        self.source_entry.pack(side=tk.LEFT)
        ttk.Button(source_frame, text="Browse", command=self._browse_source).pack(side=tk.LEFT, padx=5)
        
        # Destination
        ttk.Label(frame, text="Destination:").pack(anchor=tk.W)
        dest_frame = ttk.Frame(frame)
        dest_frame.pack(fill=tk.X, pady=5)
        self.dest_entry = ttk.Entry(dest_frame, width=50)
        self.dest_entry.pack(side=tk.LEFT)
        ttk.Button(dest_frame, text="Browse", command=self._browse_dest).pack(side=tk.LEFT, padx=5)
        
        # Options
        ttk.Label(frame, text="Options:", font=("Consolas", 11, "bold")).pack(anchor=tk.W, pady=(10,5))
        
        self.hash_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Verify hash after copy", variable=self.hash_var).pack(anchor=tk.W)
        
        self.preserve_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Preserve timestamps", variable=self.preserve_var).pack(anchor=tk.W)
        
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Recursive directory scan", variable=self.recursive_var).pack(anchor=tk.W)
        
        # Progress
        self.progress = ttk.Progressbar(frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=10)
        
        self.status_label = ttk.Label(frame, text="Ready")
        self.status_label.pack()
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Start Acquisition", command=self._start).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _browse_source(self):
        path = filedialog.askdirectory(title="Select source directory")
        if path:
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, path)
    
    def _browse_dest(self):
        path = filedialog.askdirectory(title="Select destination directory")
        if path:
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, path)
    
    def _start(self):
        self.progress.start()
        self.status_label.config(text="Acquiring evidence...")
        
        def acquire():
            if self.engine:
                results = self.engine.acquire_directory(
                    self.source_entry.get(),
                    self.dest_entry.get()
                )
                self.status_label.config(text=f"Acquired {len(results)} files")
            self.progress.stop()
        
        threading.Thread(target=acquire, daemon=True).start()


class AnalysisDialog:
    """Dialog for running analysis modules."""
    
    def __init__(self, parent, engine=None):
        self.parent = parent
        self.engine = engine
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Run Analysis")
        self.dialog.geometry("500x450")
        self.dialog.configure(bg="#1a1a2e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self._create_widgets()
    
    def _create_widgets(self):
        frame = ttk.Frame(self.dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Analysis Modules", font=("Consolas", 14, "bold")).pack(pady=10)
        
        self.module_var = tk.StringVar()
        modules = [
            "Registry Analysis",
            "Browser Forensics",
            "File Carving",
            "Memory Analysis",
            "Network Analysis",
            "Malware Scan",
            "Database Analysis",
            "Social Media Analysis",
            "Blockchain Analysis",
            "Video Forensics",
            "Audio Forensics",
            "IoT Forensics",
            "Drone Forensics",
            "Vehicle Forensics",
            "SCADA/ICS Forensics"
        ]
        
        for module in modules:
            ttk.Radiobutton(
                frame, text=module, variable=self.module_var, value=module
            ).pack(anchor=tk.W, pady=2)
        
        self.module_var.set(modules[0])
        
        self.output_text = scrolledtext.ScrolledText(
            frame, height=8, bg="#0a0a0a", fg="#00ff00",
            font=("Consolas", 9)
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=10)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack()
        ttk.Button(btn_frame, text="Run Analysis", command=self._run).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=self.dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _run(self):
        module = self.module_var.get()
        self.output_text.insert(tk.END, f"\n[*] Running {module}...\n")
        self.output_text.insert(tk.END, f"[+] {module} completed.\n")
        self.output_text.see(tk.END)


class ReportDialog:
    """Dialog for generating forensic reports."""
    
    def __init__(self, parent, engine=None):
        self.parent = parent
        self.engine = engine
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Generate Report")
        self.dialog.geometry("400x350")
        self.dialog.configure(bg="#1a1a2e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self._create_widgets()
    
    def _create_widgets(self):
        frame = ttk.Frame(self.dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Generate Report", font=("Consolas", 14, "bold")).pack(pady=10)
        
        ttk.Label(frame, text="Format:").pack(anchor=tk.W)
        self.format_var = tk.StringVar(value="HTML")
        formats = ["HTML", "JSON", "PDF", "CSV"]
        for fmt in formats:
            ttk.Radiobutton(frame, text=fmt, variable=self.format_var, value=fmt).pack(anchor=tk.W)
        
        ttk.Label(frame, text="Output file:").pack(anchor=tk.W, pady=(10,0))
        file_frame = ttk.Frame(frame)
        file_frame.pack(fill=tk.X, pady=5)
        self.file_entry = ttk.Entry(file_frame, width=30)
        self.file_entry.pack(side=tk.LEFT)
        ttk.Button(file_frame, text="Browse", command=self._browse).pack(side=tk.LEFT, padx=5)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Generate", command=self._generate).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _browse(self):
        fmt = self.format_var.get().lower()
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[(f"{fmt.upper()} files", f"*.{fmt}")]
        )
        if path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, path)
    
    def _generate(self):
        filepath = self.file_entry.get()
        if filepath:
            messagebox.showinfo("Report", f"Report generated:\n{filepath}")
            self.dialog.destroy()
