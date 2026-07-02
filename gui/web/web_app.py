#!/usr/bin/env python3
"""FORENSIX Web GUI - Advanced web-based forensic management interface."""

import os
import sys
import json
import threading
import time
from datetime import datetime
from typing import Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    from flask import Flask, render_template_string, jsonify, request, send_file
    from flask_socketio import SocketIO, emit
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from core.engine import ForensixEngine
except ImportError:
    pass


class WebApp:
    """
    FORENSIX Advanced Web Interface.
    
    Features:
        - Real-time case dashboard
        - Evidence management
        - Analysis progress tracking
        - Report generation
        - Multi-user support
        - WebSocket live updates
    """
    
    INDEX_HTML = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FORENSIX Web Console</title>
        <style>
            :root {
                --bg: #0a0a0a;
                --panel: #1a1a2e;
                --border: #16213e;
                --accent: #0f3460;
                --green: #00ff00;
                --yellow: #ffaa00;
                --red: #ff4444;
                --text: #e0e0e0;
                --muted: #888;
            }
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Courier New', monospace;
                background: var(--bg);
                color: var(--text);
                min-height: 100vh;
            }
            .app-container {
                display: flex;
                min-height: 100vh;
            }
            .sidebar {
                width: 250px;
                background: var(--panel);
                border-right: 2px solid var(--accent);
                padding: 20px 0;
                display: flex;
                flex-direction: column;
            }
            .sidebar-header {
                padding: 0 20px 20px;
                border-bottom: 1px solid var(--border);
                text-align: center;
            }
            .sidebar-header h2 {
                color: var(--green);
                font-size: 1.3em;
                text-shadow: 0 0 10px rgba(0,255,0,0.3);
            }
            .sidebar-nav {
                flex: 1;
                padding: 20px 0;
            }
            .nav-item {
                display: block;
                padding: 12px 20px;
                color: var(--muted);
                text-decoration: none;
                transition: all 0.3s;
                border-left: 3px solid transparent;
                cursor: pointer;
            }
            .nav-item:hover, .nav-item.active {
                color: var(--green);
                background: rgba(0,255,0,0.05);
                border-left-color: var(--green);
            }
            .main-content {
                flex: 1;
                padding: 30px;
                overflow-y: auto;
            }
            .header {
                margin-bottom: 30px;
            }
            .header h1 {
                color: var(--green);
                font-size: 2em;
                text-shadow: 0 0 15px rgba(0,255,0,0.3);
            }
            .header p {
                color: var(--muted);
                margin-top: 5px;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-bottom: 30px;
            }
            .stat-card {
                background: var(--panel);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 20px;
                text-align: center;
            }
            .stat-card .number {
                font-size: 2.5em;
                font-weight: bold;
                color: var(--green);
            }
            .stat-card .label {
                color: var(--muted);
                font-size: 0.9em;
                margin-top: 5px;
            }
            .panel {
                background: var(--panel);
                border: 1px solid var(--border);
                border-radius: 8px;
                margin-bottom: 20px;
                overflow: hidden;
            }
            .panel-header {
                background: rgba(0,255,0,0.05);
                padding: 15px 20px;
                border-bottom: 1px solid var(--border);
                font-weight: bold;
                color: var(--green);
            }
            .panel-body {
                padding: 20px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th {
                background: rgba(0,255,0,0.05);
                color: var(--green);
                padding: 12px;
                text-align: left;
                border-bottom: 2px solid var(--border);
                font-size: 0.9em;
            }
            td {
                padding: 10px 12px;
                border-bottom: 1px solid var(--border);
                font-size: 0.85em;
            }
            tr:hover {
                background: rgba(0,255,0,0.02);
            }
            .badge {
                display: inline-block;
                padding: 3px 10px;
                border-radius: 12px;
                font-size: 0.8em;
                font-weight: bold;
            }
            .badge-success { background: rgba(0,255,0,0.2); color: var(--green); }
            .badge-warning { background: rgba(255,170,0,0.2); color: var(--yellow); }
            .badge-danger { background: rgba(255,68,68,0.2); color: var(--red); }
            .badge-info { background: rgba(0,170,255,0.2); color: #00aaff; }
            .progress-bar {
                height: 8px;
                background: var(--border);
                border-radius: 4px;
                overflow: hidden;
            }
            .progress-fill {
                height: 100%;
                background: var(--green);
                transition: width 0.5s;
            }
            .btn {
                padding: 10px 20px;
                border: 1px solid var(--green);
                background: transparent;
                color: var(--green);
                border-radius: 5px;
                cursor: pointer;
                font-family: 'Courier New', monospace;
                transition: all 0.3s;
            }
            .btn:hover {
                background: rgba(0,255,0,0.1);
                box-shadow: 0 0 10px rgba(0,255,0,0.3);
            }
            .btn-danger {
                border-color: var(--red);
                color: var(--red);
            }
            .btn-danger:hover {
                background: rgba(255,68,68,0.1);
                box-shadow: 0 0 10px rgba(255,68,68,0.3);
            }
            .log-container {
                max-height: 300px;
                overflow-y: auto;
                font-size: 0.85em;
            }
            .log-entry {
                padding: 4px 0;
                border-bottom: 1px solid rgba(255,255,255,0.03);
            }
            .log-time { color: var(--muted); }
            .footer {
                text-align: center;
                padding: 20px;
                color: var(--muted);
                font-size: 0.85em;
                border-top: 1px solid var(--border);
                margin-top: 30px;
            }
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            .live-indicator {
                display: inline-block;
                width: 10px;
                height: 10px;
                background: var(--green);
                border-radius: 50%;
                animation: pulse 1s infinite;
                margin-right: 5px;
            }
        </style>
    </head>
    <body>
        <div class="app-container">
            <div class="sidebar">
                <div class="sidebar-header">
                    <h2>FORENSIX</h2>
                    <p style="color:var(--muted);font-size:0.8em;">Web Console v1.0</p>
                </div>
                <div class="sidebar-nav">
                    <div class="nav-item active" data-page="dashboard">
                        📊 Dashboard
                    </div>
                    <div class="nav-item" data-page="evidence">
                        📁 Evidence
                    </div>
                    <div class="nav-item" data-page="analysis">
                        🔬 Analysis
                    </div>
                    <div class="nav-item" data-page="reports">
                        📄 Reports
                    </div>
                    <div class="nav-item" data-page="settings">
                        ⚙️ Settings
                    </div>
                </div>
            </div>
            <div class="main-content">
                <div class="header">
                    <h1>Digital Forensics Dashboard</h1>
                    <p><span class="live-indicator"></span> System Active</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="number" id="stat-cases">0</div>
                        <div class="label">Active Cases</div>
                    </div>
                    <div class="stat-card">
                        <div class="number" id="stat-evidence">0</div>
                        <div class="label">Evidence Items</div>
                    </div>
                    <div class="stat-card">
                        <div class="number" id="stat-size">0 GB</div>
                        <div class="label">Total Size</div>
                    </div>
                    <div class="stat-card">
                        <div class="number" id="stat-tasks">0</div>
                        <div class="label">Active Tasks</div>
                    </div>
                </div>
                
                <div class="panel">
                    <div class="panel-header">Recent Activity</div>
                    <div class="panel-body">
                        <div class="log-container" id="activity-log">
                            <div class="log-entry"><span class="log-time">--:--:--</span> Waiting for activity...</div>
                        </div>
                    </div>
                </div>
                
                <div class="footer">
                    FORENSIX v1.0.0 | raffelsfuxk | MIT License
                </div>
            </div>
        </div>
        
        <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
        <script>
            const socket = io();
            
            socket.on('connect', () => {
                console.log('Connected to FORENSIX Web Console');
            });
            
            socket.on('update', (data) => {
                document.getElementById('stat-cases').textContent = data.cases || 0;
                document.getElementById('stat-evidence').textContent = data.evidence_count || 0;
                document.getElementById('stat-size').textContent = (data.total_size_gb || 0).toFixed(1) + ' GB';
                document.getElementById('stat-tasks').textContent = data.active_tasks || 0;
                
                if (data.logs && data.logs.length > 0) {
                    let logHtml = '';
                    data.logs.forEach(log => {
                        logHtml += `<div class="log-entry"><span class="log-time">${log.time}</span> ${log.message}</div>`;
                    });
                    document.getElementById('activity-log').innerHTML = logHtml;
                }
            });
            
            document.querySelectorAll('.nav-item').forEach(item => {
                item.addEventListener('click', () => {
                    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
                    item.classList.add('active');
                });
            });
        </script>
    </body>
    </html>
    """
    
    def __init__(self, engine=None, host: str = "127.0.0.1", port: int = 8888):
        self.engine = engine
        self.host = host
        self.port = port
        self.app = None
        self.socketio = None
        self.running = False
    
    def start(self):
        """Start web application."""
        if not FLASK_AVAILABLE:
            print("[!] Flask not installed")
            return
        
        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        @self.app.route('/')
        def index():
            return render_template_string(self.INDEX_HTML)
        
        @self.app.route('/api/status')
        def api_status():
            return jsonify({
                "status": "running",
                "version": "1.0.0",
                "timestamp": datetime.now().isoformat()
            })
        
        @self.app.route('/api/cases')
        def api_cases():
            cases = []
            if self.engine and self.engine.db:
                try:
                    cases = self.engine.db.get_all_cases()
                except:
                    pass
            return jsonify(cases)
        
        self.running = True
        
        def emit_loop():
            while self.running:
                data = {
                    "cases": 0,
                    "evidence_count": 0,
                    "total_size_gb": 0,
                    "active_tasks": 0,
                    "logs": [
                        {"time": datetime.now().strftime("%H:%M:%S"), 
                         "message": "System running"}
                    ]
                }
                self.socketio.emit('update', data)
                time.sleep(5)
        
        thread = threading.Thread(target=emit_loop, daemon=True)
        thread.start()
        
        print(f"\n[*] FORENSIX Web Console started")
        print(f"    URL: http://{self.host}:{self.port}")
        
        self.socketio.run(self.app, host=self.host, port=self.port, 
                         allow_unsafe_werkzeug=True, use_reloader=False)
    
    def stop(self):
        self.running = False
