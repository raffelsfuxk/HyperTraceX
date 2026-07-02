#!/usr/bin/env python3
"""HyperTraceX Web Dashboard - Real-time monitoring interface."""

import os
import time
import json
import threading
from datetime import datetime
from typing import Dict, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)

try:
    from flask import Flask, render_template_string, jsonify, request
    from flask_socketio import SocketIO, emit
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


class WebDashboard:
    """
    Real-time Web Dashboard for HyperTraceX.
    
    Features:
        - Live case monitoring
        - Evidence statistics
        - Progress tracking
        - Activity log streaming
        - Responsive design
    """
    
    DASHBOARD_HTML = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>HyperTraceX Dashboard</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                background: #0a0a0a;
                color: #00ff00;
                padding: 20px;
            }
            .header {
                text-align: center;
                padding: 20px;
                border-bottom: 2px solid #00ff00;
                margin-bottom: 20px;
            }
            .header h1 { font-size: 2em; text-shadow: 0 0 10px #00ff00; }
            .header .subtitle { color: #008800; margin-top: 5px; }
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-bottom: 20px;
            }
            .stat-card {
                background: #1a1a1a;
                border: 1px solid #00ff00;
                border-radius: 8px;
                padding: 20px;
                text-align: center;
            }
            .stat-card .number {
                font-size: 2.5em;
                font-weight: bold;
                color: #00ff00;
            }
            .stat-card .label {
                color: #008800;
                font-size: 0.9em;
                margin-top: 5px;
            }
            .panel {
                background: #1a1a1a;
                border: 1px solid #333;
                border-radius: 8px;
                margin-bottom: 20px;
                overflow: hidden;
            }
            .panel-header {
                background: #111;
                padding: 15px;
                border-bottom: 1px solid #333;
                font-size: 1.2em;
                font-weight: bold;
            }
            .panel-body {
                padding: 15px;
                max-height: 400px;
                overflow-y: auto;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th {
                background: #222;
                color: #00ff00;
                padding: 10px;
                text-align: left;
                border-bottom: 1px solid #333;
            }
            td {
                padding: 8px 10px;
                border-bottom: 1px solid #1a1a1a;
                font-size: 0.9em;
            }
            tr:hover { background: #222; }
            .badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 10px;
                font-size: 0.8em;
            }
            .badge-success { background: #1a3a1a; color: #00ff00; }
            .badge-warning { background: #3a3a1a; color: #ffaa00; }
            .badge-danger { background: #3a1a1a; color: #ff4444; }
            .badge-info { background: #1a1a3a; color: #00aaff; }
            .log-entry {
                padding: 5px 0;
                border-bottom: 1px solid #222;
                font-size: 0.85em;
            }
            .log-time { color: #888; }
            .footer {
                text-align: center;
                padding: 20px;
                color: #555;
                border-top: 1px solid #333;
                margin-top: 20px;
            }
            .blink { animation: blink 1s infinite; }
            @keyframes blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>HyperTraceX Dashboard</h1>
            <p class="subtitle">Real-Time Digital Forensics Monitor</p>
            <p class="subtitle blink">● LIVE</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="number" id="total-cases">0</div>
                <div class="label">Active Cases</div>
            </div>
            <div class="stat-card">
                <div class="number" id="total-evidence">0</div>
                <div class="label">Evidence Items</div>
            </div>
            <div class="stat-card">
                <div class="number" id="total-size">0 MB</div>
                <div class="label">Total Size</div>
            </div>
            <div class="stat-card">
                <div class="number" id="active-tasks">0</div>
                <div class="label">Active Tasks</div>
            </div>
        </div>

        <div class="panel">
            <div class="panel-header">Recent Evidence</div>
            <div class="panel-body">
                <table>
                    <thead>
                        <tr><th>File</th><th>Size</th><th>Hash</th><th>Status</th></tr>
                    </thead>
                    <tbody id="evidence-table">
                        <tr><td colspan="4" style="text-align:center;color:#555;">Waiting for data...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="panel">
            <div class="panel-header">Activity Log</div>
            <div class="panel-body" id="activity-log">
                <div class="log-entry"><span class="log-time">--:--:--</span> Waiting for activity...</div>
            </div>
        </div>

        <div class="footer">
            HyperTraceX v1.0.0 | raffelsfuxk
        </div>

        <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
        <script>
            const socket = io();
            
            socket.on('connect', function() {
                console.log('Connected to HyperTraceX Dashboard');
            });

            socket.on('update', function(data) {
                document.getElementById('total-cases').textContent = data.cases || 0;
                document.getElementById('total-evidence').textContent = data.evidence_count || 0;
                document.getElementById('total-size').textContent = (data.total_size_mb || 0) + ' MB';
                document.getElementById('active-tasks').textContent = data.active_tasks || 0;

                if (data.recent_evidence && data.recent_evidence.length > 0) {
                    var tableHtml = '';
                    data.recent_evidence.forEach(function(ev) {
                        tableHtml += '<tr>';
                        tableHtml += '<td>' + (ev.file_path || ev.file || '?').substring(0, 40) + '</td>';
                        tableHtml += '<td>' + (ev.size || ev.file_size || 0) + '</td>';
                        tableHtml += '<td><code>' + (ev.sha256 || ev.sha256_hash || '?').substring(0, 16) + '...</code></td>';
                        tableHtml += '<td><span class="badge badge-success">Acquired</span></td>';
                        tableHtml += '</tr>';
                    });
                    document.getElementById('evidence-table').innerHTML = tableHtml;
                }

                if (data.logs && data.logs.length > 0) {
                    var logHtml = '';
                    data.logs.forEach(function(log) {
                        var logClass = 'badge-info';
                        if (log.type === 'error') logClass = 'badge-danger';
                        else if (log.type === 'warning') logClass = 'badge-warning';
                        else if (log.type === 'success') logClass = 'badge-success';
                        
                        logHtml += '<div class="log-entry">';
                        logHtml += '<span class="log-time">' + (log.time || '--:--:--') + '</span> ';
                        logHtml += '<span class="badge ' + logClass + '">' + (log.type || 'INFO') + '</span> ';
                        logHtml += (log.message || '');
                        logHtml += '</div>';
                    });
                    document.getElementById('activity-log').innerHTML = logHtml;
                }
            });
        </script>
    </body>
    </html>
    """
    
    def __init__(self, engine=None, host: str = "127.0.0.1", 
                 port: int = 8888, logger=None):
        self.engine = engine
        self.host = host
        self.port = port
        self.logger = logger or get_logger()
        self.app = None
        self.socketio = None
        self.running = False
    
    def set_engine(self, engine):
        self.engine = engine
    
    def start(self):
        if not FLASK_AVAILABLE:
            print("[!] Flask not installed. Install: pip install flask flask-socketio")
            return
        
        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        @self.app.route('/')
        def index():
            return render_template_string(self.DASHBOARD_HTML)
        
        @self.app.route('/api/stats')
        def api_stats():
            data = self._get_dashboard_data()
            return jsonify(data)
        
        self.running = True
        
        def emit_data():
            while self.running:
                data = self._get_dashboard_data()
                self.socketio.emit('update', data)
                time.sleep(3)
        
        thread = threading.Thread(target=emit_data, daemon=True)
        thread.start()
        
        print(f"\n[*] HyperTraceX Dashboard started")
        print(f"    URL: http://{self.host}:{self.port}")
        
        try:
            self.socketio.run(self.app, host=self.host, port=self.port, 
                            allow_unsafe_werkzeug=True, use_reloader=False)
        except Exception as e:
            self.logger.error(f"Dashboard error: {e}")
        finally:
            self.running = False
    
    def _get_dashboard_data(self) -> Dict:
        data = {
            "cases": 0,
            "evidence_count": 0,
            "total_size_mb": 0,
            "active_tasks": 0,
            "recent_evidence": [],
            "logs": []
        }
        
        if self.engine and self.engine.db:
            try:
                cases = self.engine.db.get_all_cases()
                data["cases"] = len(cases)
                
                if self.engine.current_case_id:
                    evidence = self.engine.db.get_case_evidence(self.engine.current_case_id)
                    data["evidence_count"] = len(evidence)
                    data["recent_evidence"] = evidence[-5:]
                    
                    stats = self.engine.db.get_case_stats(self.engine.current_case_id)
                    data["total_size_mb"] = round(stats.get("total_size_bytes", 0) / (1024*1024), 2)
            except:
                pass
        
        return data
    
    def stop(self):
        self.running = False
        self.logger.info("Dashboard stopped")
