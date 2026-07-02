# FORENSIX Complete API Reference

## Base URL: http://localhost:5000/api

## Authentication
All API requests require authentication via JWT token.
Header: Authorization: Bearer <token>

## Endpoints

### GET /api
Returns API documentation and available endpoints.

### GET /api/status
Returns server status.
Response: {"status": "running", "version": "1.0.0", "timestamp": "..."}

### GET /api/health
Health check endpoint.
Response: {"status": "healthy", "timestamp": "..."}

### POST /api/case
Create new case.
Body: {"case_id": "CASE001", "investigator": "Name", "organization": "Org", "description": "Desc"}
Response: {"success": true, "case_id": "CASE001", "created_at": "..."}

### GET /api/case/<case_id>
Get case details.
Response: {"id": 1, "case_id": "CASE001", "investigator": "Name", "status": "open"}

### GET /api/cases
List all cases.
Response: [{"id": 1, "case_id": "CASE001", ...}, ...]

### POST /api/evidence
Add evidence to case.
Body: {"case_id": "CASE001", "file_path": "/path/to/evidence", "file_size": 1024}
Response: {"success": true, "file_path": "..."}

### GET /api/evidence/<case_id>
List evidence for case.
Response: {"case_id": "CASE001", "count": 5, "evidence": [...]}

### DELETE /api/evidence/<evidence_id>
Delete evidence item.
Response: {"success": true}

### POST /api/analyze
Run analysis on target.
Body: {"type": "basic|full|custom", "target": "/path/to/target", "modules": ["browser", "registry"]}
Response: {"status": "completed", "results": {...}}

### GET /api/analyze/status/<task_id>
Check analysis task status.
Response: {"task_id": "...", "status": "running|completed|failed", "progress": 75}

### POST /api/report
Generate report.
Body: {"case_id": "CASE001", "format": "html|json|pdf|csv", "type": "full|summary|evidence"}
Response: {"report_url": "/reports/report_CASE001.html"}

### GET /api/report/<case_id>
Download generated report.
Response: Binary file download

### POST /api/custody
Log chain of custody entry.
Body: {"evidence_id": 1, "action": "TRANSFERRED", "handler": "Name", "location": "Lab"}
Response: {"success": true, "custody_id": 1}

### GET /api/custody/<evidence_id>
Get chain of custody for evidence.
Response: [{"action": "COLLECTED", "handler": "Name", "timestamp": "..."}, ...]

### POST /api/search
Search across all evidence.
Body: {"query": "password", "case_id": "CASE001"}
Response: {"results": [...], "total": 5}

### GET /api/stats/<case_id>
Get case statistics.
Response: {"evidence_count": 100, "total_size_gb": 2.5, "custody_entries": 15}

### GET /api/plugins
List installed plugins.
Response: [{"name": "Example", "version": "1.0", "status": "active"}, ...]

### POST /api/plugins/install
Install plugin from marketplace.
Body: {"plugin_id": "forensic_timeline"}
Response: {"success": true, "plugin": "forensic_timeline"}

### GET /api/dashboard
Get dashboard data.
Response: {"cases": 5, "evidence_count": 200, "active_tasks": 2, "recent": [...]}

## Error Codes
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 500: Internal Server Error

## Rate Limiting
- 100 requests per minute per IP
- Header: X-RateLimit-Remaining

## Support
GitHub: https://github.com/raffelsfuxk/FORENSIX
Author: raffelsfuxk
