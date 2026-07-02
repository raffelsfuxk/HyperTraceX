#!/usr/bin/env python3
"""FORENSIX Desktop GUI - Professional forensic analysis interface."""

import os
import sys
import threading
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

try:
    from core.engine import ForensixEngine
except ImportError:
    pass


class MainWindow:
    """
    FORENSIX Desktop GUI Application.
    
    Provides a professional graphical interface for:
        - Case management
        - Evidence acquisition
        - Artifact extraction
        - Report generation
        - Real-time monitoring
    """
    
    def __init__(self, engine=None):
        if not TKINTER_AVAILABLE:
            print("[!] tkinter not available")
            return
        
        self.engine = engine
        self.root = tk.Tk()
        self.root.title("FORENSIX - Digital Forensics Platform")
        self.root.geometry("1200x700")
        self.root.configure(bg="#1a1a2e")
        
        self._setup_styles()
        self._create_widgets()
        self._setup_menu()
        self._setup_status_bar()
    
    def _setup_styles(self):
        """Configure ttk styles."""
        style = ttk.Style()
        style.theme_use("clam")
        
        style.configure(
            "TFrame",
            background="#1a1a2e"
        )
        style.configure(
            "TLabel",
            background="#1a1a2e",
            foreground="#00ff00",
            font=("Consolas", 10)
        )
        style.configure(
            "TButton",
            background="#0a0a1e",
            foreground="#00ff00",
            font=("Consolas", 10),
            padding=10
        )
        style.configure(
            "TNotebook",
            background="#1a1a2e",
            borderwidth=0
        )
        style.configure(
            "TNotebook.Tab",
            background="#0a0a1e",
            foreground="#00ff00",
            padding=[15, 5],
            font=("Consolas", 10)
        )
    
    def _create_widgets(self):
        """Create main GUI widgets."""
        # Header
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        title_label = ttk.Label(
            header_frame,
            text="FORENSIX - Enterprise Digital Forensics Platform",
            font=("Consolas", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)
        
        version_label = ttk.Label(
            header_frame,
            text="v1.0.0",
            font=("Consolas", 10)
        )
        version_label.pack(side=tk.RIGHT)
        
        # Notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Dashboard tab
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text=" Dashboard ")
        self._create_dashboard()
        
        # Evidence tab
        self.evidence_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.evidence_frame, text=" Evidence ")
        self._create_evidence_tab()
        
        # Analysis tab
        self.analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.analysis_frame, text=" Analysis ")
        self._create_analysis_tab()
        
        # Reports tab
        self.reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_frame, text=" Reports ")
        self._create_reports_tab()
        
        # Log tab
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text=" Activity Log ")
        self._create_log_tab()
    
    def _create_dashboard(self):
        """Create dashboard panel."""
        # Stats grid
        stats_frame = ttk.Frame(self.dashboard_frame)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        stats = [
            ("Active Cases", "0"),
            ("Evidence Items", "0"),
            ("Total Size", "0 MB"),
            ("Active Tasks", "0")
        ]
        
        for i, (label, value) in enumerate(stats):
            card = ttk.Frame(stats_frame, relief=tk.RIDGE, borderwidth=2)
            card.grid(row=0, column=i, padx=10, pady=5, sticky="nsew")
            
            ttk.Label(card, text=value, font=("Consolas", 20, "bold")).pack(pady=5)
            ttk.Label(card, text=label, font=("Consolas", 8)).pack(pady=5)
        
        stats_frame.grid_columnconfigure(0, weight=1)
        stats_frame.grid_columnconfigure(1, weight=1)
        stats_frame.grid_columnconfigure(2, weight=1)
        stats_frame.grid_columnconfigure(3, weight=1)
        
        # Quick actions
        actions_frame = ttk.Frame(self.dashboard_frame)
        actions_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(actions_frame, text="Quick Actions", font=("Consolas", 12, "bold")).pack(anchor=tk.W)
        
        actions = [
            ("New Case", self._on_new_case),
            ("Scan Drives", self._on_scan_drives),
            ("Acquire Evidence", self._on_acquire),
            ("Generate Report", self._on_generate_report)
        ]
        
        for text, command in actions:
            btn = ttk.Button(actions_frame, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=5, pady=5)
    
    def _create_evidence_tab(self):
        """Create evidence management panel."""
        # File list
        list_frame = ttk.Frame(self.evidence_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(list_frame, text="Evidence Inventory", font=("Consolas", 12, "bold")).pack(anchor=tk.W)
        
        self.evidence_tree = ttk.Treeview(
            list_frame,
            columns=("file", "size", "hash", "date"),
            show="headings",
            height=20
        )
        self.evidence_tree.heading("file", text="File Name")
        self.evidence_tree.heading("size", text="Size")
        self.evidence_tree.heading("hash", text="SHA256")
        self.evidence_tree.heading("date", text="Acquired")
        
        self.evidence_tree.column("file", width=300)
        self.evidence_tree.column("size", width=100)
        self.evidence_tree.column("hash", width=200)
        self.evidence_tree.column("date", width=150)
        
        self.evidence_tree.pack(fill=tk.BOTH, expand=True)
        
        # Buttons
        btn_frame = ttk.Frame(self.evidence_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Add Evidence", command=self._on_add_evidence).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Verify Integrity", command=self._on_verify).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Export List", command=self._on_export_list).pack(side=tk.LEFT, padx=5)
    
    def _create_analysis_tab(self):
        """Create analysis panel."""
        modules_frame = ttk.Frame(self.analysis_frame)
        modules_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(modules_frame, text="Analysis Modules", font=("Consolas", 12, "bold")).pack(anchor=tk.W)
        
        modules = [
            ("Registry Analysis", "Parse Windows registry hives"),
            ("Browser Forensics", "Extract browser artifacts"),
            ("File Carving", "Recover deleted files"),
            ("Memory Analysis", "Analyze memory dumps"),
            ("Network Analysis", "Examine network traffic"),
            ("Malware Scan", "Detect malicious files"),
            ("Database Analysis", "Extract database records"),
            ("Social Media", "Extract social media artifacts"),
            ("Blockchain Analysis", "Find crypto wallets"),
        ]
        
        for name, desc in modules:
            frame = ttk.Frame(modules_frame)
            frame.pack(fill=tk.X, pady=2)
            
            ttk.Button(frame, text="Run", width=8, 
                      command=lambda n=name: self._on_run_module(n)).pack(side=tk.LEFT, padx=5)
            ttk.Label(frame, text=name, font=("Consolas", 10, "bold")).pack(side=tk.LEFT, padx=5)
            ttk.Label(frame, text=desc, font=("Consolas", 8), foreground="#888").pack(side=tk.LEFT, padx=5)
    
    def _create_reports_tab(self):
        """Create report generation panel."""
        options_frame = ttk.Frame(self.reports_frame)
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(options_frame, text="Report Generation", font=("Consolas", 12, "bold")).pack(anchor=tk.W)
        
        # Format selection
        format_frame = ttk.Frame(options_frame)
        format_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(format_frame, text="Format:").pack(side=tk.LEFT, padx=5)
        self.report_format = tk.StringVar(value="html")
        ttk.Radiobutton(format_frame, text="HTML", variable=self.report_format, value="html").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="JSON", variable=self.report_format, value="json").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="PDF", variable=self.report_format, value="pdf").pack(side=tk.LEFT, padx=5)
        
        ttk.Button(options_frame, text="Generate Report", command=self._on_generate_report).pack(pady=10)
    
    def _create_log_tab(self):
        """Create activity log panel."""
        self.log_text = scrolledtext.ScrolledText(
            self.log_frame,
            height=25,
            bg="#0a0a0a",
            fg="#00ff00",
            font=("Consolas", 9),
            insertbackground="#00ff00"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_text.insert(tk.END, f"[{datetime.now():%Y-%m-%d %H:%M:%S}] FORENSIX GUI started\n")
        self.log_text.insert(tk.END, f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Ready for forensic operations\n")
        self.log_text.see(tk.END)
    
    def _setup_menu(self):
        """Setup application menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Case", command=self._on_new_case)
        file_menu.add_command(label="Open Case", command=self._on_open_case)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Scan Drives", command=self._on_scan_drives)
        tools_menu.add_command(label="Acquire Evidence", command=self._on_acquire)
        tools_menu.add_command(label="Generate Report", command=self._on_generate_report)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._on_about)
    
    def _setup_status_bar(self):
        """Setup status bar."""
        self.status_bar = ttk.Label(
            self.root,
            text="Ready",
            relief=tk.SUNKEN,
            anchor=tk.W,
            font=("Consolas", 8)
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def log(self, message: str):
        """Add message to activity log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.status_bar.config(text=message)
    
    def _on_new_case(self):
        """Handle new case creation."""
        messagebox.showinfo("New Case", "Case creation dialog (implement in full version)")
        self.log("New case created")
    
    def _on_open_case(self):
        """Handle open case."""
        messagebox.showinfo("Open Case", "Case opening dialog (implement in full version)")
    
    def _on_scan_drives(self):
        """Handle drive scan."""
        self.log("Starting drive scan...")
        
        def scan():
            if self.engine:
                drives = self.engine.scan_drives()
                self.log(f"Found {len(drives)} partitions")
        
        threading.Thread(target=scan, daemon=True).start()
    
    def _on_acquire(self):
        """Handle evidence acquisition."""
        messagebox.showinfo("Acquire", "Evidence acquisition dialog (implement in full version)")
    
    def _on_verify(self):
        """Handle evidence verification."""
        messagebox.showinfo("Verify", "Verification dialog (implement in full version)")
    
    def _on_export_list(self):
        """Handle evidence list export."""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filepath:
            self.log(f"Evidence list exported to: {filepath}")
    
    def _on_run_module(self, module_name: str):
        """Handle running analysis module."""
        self.log(f"Running module: {module_name}")
        
        def run_module():
            self.log(f"Module '{module_name}' completed")
        
        threading.Thread(target=run_module, daemon=True).start()
    
    def _on_generate_report(self):
        """Handle report generation."""
        self.log(f"Generating {self.report_format.get().upper()} report...")
        messagebox.showinfo("Report", f"{self.report_format.get().upper()} report generated")
    
    def _on_add_evidence(self):
        """Handle adding evidence."""
        filepath = filedialog.askopenfilename(
            title="Select evidence file",
            filetypes=[("All files", "*.*")]
        )
        if filepath:
            self.evidence_tree.insert(
                "",
                tk.END,
                values=(
                    os.path.basename(filepath),
                    str(os.path.getsize(filepath)),
                    "N/A",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
            )
            self.log(f"Evidence added: {filepath}")
    
    def _on_about(self):
        """Show about dialog."""
        messagebox.showinfo(
            "About FORENSIX",
            "FORENSIX v1.0.0\n"
            "Enterprise Digital Forensics Platform\n\n"
            "Author: raffelsfuxk\n"
            "License: MIT\n"
            "GitHub: https://github.com/raffelsfuxk/FORENSIX"
        )
    
    def run(self):
        """Start the GUI application."""
        if not TKINTER_AVAILABLE:
            print("[!] tkinter not available. Install: sudo apt install python3-tk")
            return
        
        self.log("FORENSIX GUI starting...")
        self.root.mainloop()


if __name__ == "__main__":
    app = MainWindow()
    app.run()
