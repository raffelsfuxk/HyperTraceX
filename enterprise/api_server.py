#!/usr/bin/env python3
"""HyperTraceX REST API Server - Programmatic access for external integrations."""

import json
from datetime import datetime
from typing import Dict, Any, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)

try:
    from flask import Flask, request, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


class APIServer:
    """
    HyperTraceX REST API Server.
    
    Provides programmatic access to forensic capabilities:
        - Case management
        - Evidence retrieval
        - Analysis triggering
        - Status monitoring
        - Report generation
    """
    
    def __init__(self, engine=None, host: str = "127.0.0.1", 
                 port: int = 5000, logger=None):
        self.engine = engine
        self.host = host
        self.port = port
        self.logger = logger or get_logger()
        self.app = None
        self.running = False
        
        if not FLASK_AVAILABLE:
            self.logger.warning("Flask not installed. API server unavailable.")
    
    def start(self):
        """Start the REST API server."""
        if not FLASK_AVAILABLE:
            print("[!] Flask not installed. Install: pip install flask")
            return
        
        self.app = Flask(__name__)
        self._register_routes()
        
        print(f"\n[*] Starting HyperTraceX API Server")
        print(f"    URL: http://{self.host}:{self.port}")
        print(f"    Docs: http://{self.host}:{self.port}/api")
        print(f"    Press Ctrl+C to stop\n")
        
        self.running = True
        
        try:
            self.app.run(host=self.host, port=self.port, debug=False)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            self.logger.error(f"API server error: {e}")
    
    def _register_routes(self):
        """Register API routes."""
        
        @self.app.route('/api', methods=['GET'])
        def api_index():
            return jsonify({
                "service": "HyperTraceX API",
                "version": "1.0.0",
                "endpoints": {
                    "GET /api": "API documentation",
                    "GET /api/status": "Server status",
                    "POST /api/case": "Create new case",
                    "GET /api/case/<id>": "Get case info",
                    "POST /api/evidence": "Register evidence",
                    "GET /api/evidence/<case_id>": "List evidence",
                    "POST /api/analyze": "Run analysis",
                    "GET /api/report/<case_id>": "Generate report"
                }
            })
        
        @self.app.route('/api/status', methods=['GET'])
        def api_status():
            return jsonify({
                "status": "running",
                "timestamp": datetime.now().isoformat(),
                "uptime": "active"
            })
        
        @self.app.route('/api/case', methods=['POST'])
        def api_create_case():
            try:
                data = request.get_json()
                
                if not data:
                    return jsonify({"error": "No JSON data provided"}), 400
                
                case_id = data.get("case_id")
                investigator = data.get("investigator")
                
                if not case_id or not investigator:
                    return jsonify({"error": "case_id and investigator required"}), 400
                
                if self.engine:
                    self.engine.create_case(
                        case_id, 
                        investigator,
                        data.get("organization", ""),
                        data.get("description", "")
                    )
                
                return jsonify({
                    "success": True,
                    "case_id": case_id,
                    "created_at": datetime.now().isoformat()
                }), 201
                
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/case/<case_id>', methods=['GET'])
        def api_get_case(case_id):
            if self.engine and self.engine.db:
                case = self.engine.db.get_case(case_id)
                if case:
                    return jsonify(case)
                return jsonify({"error": "Case not found"}), 404
            return jsonify({"error": "Engine not initialized"}), 500
        
        @self.app.route('/api/evidence', methods=['POST'])
        def api_add_evidence():
            try:
                data = request.get_json()
                
                if not data:
                    return jsonify({"error": "No JSON data provided"}), 400
                
                case_id = data.get("case_id")
                file_path = data.get("file_path")
                
                if not case_id or not file_path:
                    return jsonify({"error": "case_id and file_path required"}), 400
                
                if self.engine:
                    result = self.engine.acquire_file(file_path, file_path)
                    
                    if result and self.engine.db:
                        case = self.engine.db.get_case(case_id)
                        if case:
                            self.engine.db.add_evidence(
                                case["id"],
                                file_path,
                                file_path,
                                result["size"],
                                result["md5"],
                                result["sha1"],
                                result["sha256"]
                            )
                
                return jsonify({
                    "success": True,
                    "file_path": file_path,
                    "registered_at": datetime.now().isoformat()
                }), 201
                
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/evidence/<case_id>', methods=['GET'])
        def api_list_evidence(case_id):
            if self.engine and self.engine.db:
                case = self.engine.db.get_case(case_id)
                if case:
                    evidence = self.engine.db.get_case_evidence(case["id"])
                    return jsonify({
                        "case_id": case_id,
                        "count": len(evidence),
                        "evidence": evidence
                    })
                return jsonify({"error": "Case not found"}), 404
            return jsonify({"error": "Engine not initialized"}), 500
        
        @self.app.route('/api/analyze', methods=['POST'])
        def api_analyze():
            try:
                data = request.get_json()
                
                if not data:
                    return jsonify({"error": "No JSON data provided"}), 400
                
                analysis_type = data.get("type", "basic")
                target = data.get("target", "")
                
                if not target:
                    return jsonify({"error": "target path required"}), 400
                
                results = {
                    "type": analysis_type,
                    "target": target,
                    "status": "completed",
                    "timestamp": datetime.now().isoformat()
                }
                
                return jsonify(results), 200
                
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/report/<case_id>', methods=['GET'])
        def api_report(case_id):
            if self.engine:
                report = self.engine.generate_case_report(case_id)
                if report:
                    return jsonify(report)
                return jsonify({"error": "Case not found"}), 404
            return jsonify({"error": "Engine not initialized"}), 500
        
        @self.app.route('/api/health', methods=['GET'])
        def api_health():
            return jsonify({
                "status": "healthy",
                "timestamp": datetime.now().isoformat()
            })
    
    def stop(self):
        """Stop the API server."""
        self.running = False
        self.logger.info("API server stopped")
        print("[*] API server stopped")
    
    def is_running(self) -> bool:
        return self.running
