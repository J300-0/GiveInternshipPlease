# FastAPI Security Monitoring - Alert & Playbook Output Layer

**Purpose**: Offline security monitoring system that ingests logs, detects anomalies using statistical ML (PyOD), and outputs structured alerts for AI/MCP consumption.

## What This System Does

1. **Ingests logs** from ELK-monitored application traffic
2. **Validates** using OCSF-compliant Pydantic schemas
3. **Detects anomalies** using PyOD (ECOD, Isolation Forest)
4. **Generates alerts** with full context for investigation
5. **Outputs structured data** via REST API for AI/MCP systems

**See [COMPLETE_DATA_FLOW.md](COMPLETE_DATA_FLOW.md) for detailed stage-by-stage flow.**
**See [SYSTEM_EXPLANATION.md](SYSTEM_EXPLANATION.md) for a thorough guide on Architecture & AI Integration.**

---

## Architecture Overview

```
ELK Stack (Monitors Traffic) 
    → FastAPI Ingestion (Validates & Stores)
    → PyOD Detection (Analyzes & Alerts)
    → REST API Output (AI/MCP Consumption)
```

### Core Components

1. **Log Ingestion** (`POST /api/v1/logs/ingest`)
   - OCSF schema validation
   - Metadata enrichment
   - Elasticsearch storage

2. **Anomaly Detection** (`POST /api/v1/alerts/detection/run`)
   - PyOD statistical models (ECOD, Isolation Forest)
   - Feature extraction from logs
   - Alert generation (score > threshold)

3. **Alert API** (For AI/MCP)
   - `GET /api/v1/alerts` - List alerts
   - `GET /api/v1/alerts/{id}` - Get alert details
   - `GET /api/v1/alerts/{id}/context` - Investigation context

4. **Playbook API** (For Future AI)
   - `GET /api/v1/playbooks` - List playbooks
   - `POST /api/v1/playbooks` - Submit AI-generated playbooks

---

## Prerequisites

- Docker and Docker Compose
- ELK Stack running (monitors your application traffic)
- Python 3.11+ (for local development)

---

## Quick Start

### 1. Start Full Application Stack

Since the entire application is dockerized, you can start everything with a single command:

```bash
cd C:\Users\LENOVO\Desktop\Barclays\Barclays-project
docker-compose up -d --build
```
This starts:
1.  **FastAPI Service** (Port 8000)
2.  **Sample App** (Generates traffic automatically on start)
3.  **ELK Stack** (Port 9200/5601)

### 2. Verify Service

```bash
# Check health
curl http://localhost:8000/api/v1/logs/health

# View API docs
# Open http://localhost:8000/docs
```

---

## API Endpoints

### Log Ingestion

**POST /api/v1/logs/ingest**
```bash
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [{
      "time": "2026-02-15T12:00:00Z",
      "severity_id": 3,
      "category_uid": 4,
      "class_uid": 4001,
      "activity_id": 1,
      "type_uid": 400101,
      "message": "Network connection",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.50"
    }]
  }'
```

### Anomaly Detection

**POST /api/v1/alerts/detection/run**
```bash
# Run detection on last 5 minutes of logs
curl -X POST "http://localhost:8000/api/v1/alerts/detection/run?window_minutes=5&threshold=0.85&algorithm=ecod"
```

**Response:**
```json
{
  "status": "completed",
  "logs_analyzed": 150,
  "anomalies_detected": 3,
  "alerts_generated": 3,
  "alert_ids": ["alert-550e8400-...", "alert-660f9511-...", "alert-770fa622-..."],
  "algorithm": "ECOD",
  "threshold": 0.85
}
```

### Query Alerts (AI/MCP Interface)

**GET /api/v1/alerts**
```bash
# List all alerts
curl "http://localhost:8000/api/v1/alerts?page=1&page_size=10"

# Filter by severity
curl "http://localhost:8000/api/v1/alerts?severity=4&status=new"
```

**GET /api/v1/alerts/{alert_id}**
```bash
# Get specific alert with full context
curl "http://localhost:8000/api/v1/alerts/alert-550e8400-e29b-41d4-a716-446655440000"
```

**GET /api/v1/alerts/{alert_id}/context**
```bash
# Get investigation context
curl "http://localhost:8000/api/v1/alerts/alert-550e8400/context"
```

---

## Project Structure

```
Barclays-project/
├── app/
│   ├── api/v1/
│   │   ├── logs.py              # Log ingestion endpoints
│   │   ├── alerts.py            # Alert & detection endpoints
│   │   └── playbooks.py         # Playbook endpoints (future AI)
│   ├── core/
│   │   └── config.py            # Configuration
│   ├── models/
│   │   ├── log.py               # OCSF log schemas
│   │   ├── alert.py             # Alert schemas (AI-ready)
│   │   └── playbook.py          # Playbook schemas (AI-ready)
│   ├── services/
│   │   ├── elasticsearch_service.py  # ES async client
│   │   ├── ingestion_service.py      # Log processing
│   │   └── detection_service.py      # PyOD anomaly detection
│   └── main.py                  # FastAPI application
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## Configuration

Edit `.env`:

```env
# Elasticsearch
ELASTICSEARCH_HOST=elasticsearch
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=changeme
ELASTICSEARCH_INDEX=security-logs

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=True
```

---

## Alert Schema (For AI/MCP)

Alerts are stored in Elasticsearch with this structure:

```json
{
  "alert_id": "alert-550e8400-...",
  "anomaly_score": 0.92,
  "detection_algorithm": "ECOD",
  "severity": 4,
  "status": "new",
  "category": "auth_anomaly",
  "affected_entities": {
    "users": ["admin"],
    "ips": ["203.0.113.45"]
  },
  "context_logs": [
    {
      "log_id": "log-123",
      "timestamp": "2026-02-15T12:00:00Z",
      "message": "Failed login attempt",
      "user": "admin",
      "src_ip": "203.0.113.45"
    }
  ],
  "features": {
    "failed_login_count": 15.0,
    "unique_source_ips": 1.0
  },
  "summary": "Unusual authentication activity detected"
}
```

---

## How AI/MCP Integrates

### 1. Query Alerts
```python
import requests

# Get new high-severity alerts
response = requests.get(
    "http://fastapi-app:8000/api/v1/alerts",
    params={"severity": 4, "status": "new"}
)
alerts = response.json()["alerts"]
```

### 2. Investigate
```python
# Get full context for investigation
alert_id = alerts[0]["alert_id"]
context = requests.get(
    f"http://fastapi-app:8000/api/v1/alerts/{alert_id}/context"
).json()

# AI analyzes:
# - affected_entities
# - features (statistical data)
# - context_logs
```

### 3. Generate Playbook (Future)
```python
# AI generates response actions
playbook = {
    "name": "Mitigate Brute Force",
    "alert_id": alert_id,
    "actions": [
        {"action_type": "block_ip", "parameters": {"ip": "203.0.113.45"}}
    ]
}

# Submit for human approval
requests.post("http://fastapi-app:8000/api/v1/playbooks", json=playbook)
```

---

## Testing

### 1. Ingest Sample Logs
```bash
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [{
      "time": "2026-02-15T12:00:00Z",
      "severity_id": 4,
      "category_uid": 3,
      "class_uid": 3002,
      "activity_id": 2,
      "type_uid": 300202,
      "message": "Failed login",
      "user": "admin",
      "src_ip": "203.0.113.45"
    }]
  }'
```

### 2. Run Detection
```bash
curl -X POST "http://localhost:8000/api/v1/alerts/detection/run?window_minutes=5"
```

### 3. View Alerts
```bash
curl "http://localhost:8000/api/v1/alerts"
```

### 4. Check Elasticsearch
```bash
# View alerts index
curl -u elastic:changeme "http://localhost:9200/security-alerts/_search?pretty"
```

---

## Docker Commands

```bash
# View logs
docker-compose logs -f fastapi-app

# Restart
docker-compose restart fastapi-app

# Rebuild after code changes
docker-compose up --build -d

# Stop
docker-compose down
```

---

## Troubleshooting

### Service won't start
- Check ELK stack: `docker ps`
- Verify network: `docker network ls | grep elk`
- Check logs: `docker-compose logs fastapi-app`

### No anomalies detected
- Ensure sufficient logs (minimum 10 logs)
- Lower threshold: `?threshold=0.7`
- Check log variety (anomalies need normal baseline)

### Alerts not appearing
- Check Elasticsearch: `curl http://localhost:9200/security-alerts/_search`
- Verify detection ran: Check API response
- Review service logs for errors

---

## Development

### Local Development
```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run service
python -m app.main
```

### Adding New Detection Algorithms
Edit `app/services/detection_service.py`:
```python
from pyod.models.knn import KNN

# Add to _run_pyod_model method
elif algorithm == "knn":
    model = KNN(contamination=0.1)
```

---

## What's NOT Implemented

This implementation provides the **data output layer** for AI/MCP consumption. The following are **NOT included**:

- AI Agent (LangGraph, Ollama, LLM integration)
- Playbook execution engine
- WebSocket real-time alerts
- Scheduled detection (cron jobs)

These can be built by external systems that consume the structured alert data via the REST API.

---

## License

This project is part of an offline cybersecurity threat detection system.