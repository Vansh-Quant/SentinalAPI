# SentinelAPI — Zero-Trust API Vulnerability Scanner

SentinelAPI is a Zero-Trust API Vulnerability Scanner designed to analyze OpenAPI specifications, discover API endpoints, enforce strict sandbox target isolation, run security vulnerability scans (BOLA, BOPLA, Auth Bypass, Headers), and manage persistent scan records, dashboard metrics, attack surface graphs, scan timelines, executive reports, and real-time WebSocket feeds.

---

## 🏛️ Architecture Overview

```
Frontend (Dashboard & Reports)
   │
   ├── WebSocket (/ws/scans/{scan_id}) ──► Real-Time Progress & Findings Stream
   │
   ▼
Backend API (FastAPI)
   │
   ├── Auth & Projects Management
   ├── OpenAPI Spec Parser & Storage
   ├── Results Persistence & Sanitizer (Redacts secrets)
   ├── Dashboard, Attack Surface, Timeline & Report Engine
   ├── Database Persistence (PostgreSQL / SQLite)
   │
   ▼
Scan Manager (Async Task Engine)
   │
   ├── Zero-Trust Sandbox Isolation Policy
   │
   ▼
Scanner Engine (BOLA / BOPLA Scanner & Sandbox API Adapter)
   │
   ▼
Target Sandbox API (`sandbox/`)
```

---

## 🛠️ Project Components & Stack

- **Backend**: FastAPI, SQLAlchemy 2.0, Pydantic v2, JWT Auth (`backend/`)
- **Scanner Engine**: OpenAPI Normalizer, BOLA/BOPLA Analyzer, HTTP Executor (`scanner/`)
- **Sandbox API**: Intentionally Vulnerable Mock Target API (`sandbox/`)
- **Database**: PostgreSQL (Production) / SQLite (Local & Testing)
- **Real-Time Feed**: WebSockets (`/ws/scans/{scan_id}`)
- **Testing**: `pytest` unit and integration test suite (`tests/` & `backend/tests/`)

---

## ⚙️ Environment Variables Configuration

Create a `.env` file in the root or `backend/` directory based on `.env.example`:

```env
# Security (Set a long random key in production)
SECRET_KEY=dev-only-secret-do-not-use-in-production-0123456789abcdef
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Database Connection URL
DATABASE_URL=sqlite:///./sentinel.db

# Upload limits
UPLOAD_DIR=uploads
MAX_UPLOAD_SIZE=10485760 # 10 MiB

# Scanner Sandbox Settings (Zero-Trust)
SANDBOX_BASE_URL=http://localhost:9000

# Application Environment
ENVIRONMENT=development
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
LOG_LEVEL=INFO
```

---

## 🚀 Getting Started

### 1. Install Dependencies

Create and activate a virtual environment, then install dependencies:

```bash
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

---

### 2. Run Automated Tests

Run the full 53+ test suite across scanner engine and backend:

```bash
pytest
```

---

### 3. Run Backend Server

Start the FastAPI server:

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Interactive API documentation will be available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## 📡 API Endpoints

### 🔐 Authentication
- `POST /api/auth/register` — Register new user
- `POST /api/auth/login` — Authenticate and receive JWT access token
- `GET /api/auth/me` — Get current user details

### 📁 Projects
- `POST /api/projects` — Create a new project
- `GET /api/projects` — List user's projects
- `GET /api/projects/{project_id}` — Get project details

### 🔍 Scans & Job Management
- `POST /api/scans` — Upload OpenAPI spec and create queued scan
- `GET /api/scans` — List user's scans
- `GET /api/scans/{scan_id}` — Get scan details and spec summary
- `GET /api/scans/{scan_id}/status` — Polling status (progress, endpoints, tests, findings)
- `POST /api/scans/{scan_id}/start` — Initiate background scan execution
- `POST /api/scans/{scan_id}/cancel` — Safely cancel a queued or running scan

### 🐛 Findings & Evidence (Phase 3)
- `GET /api/scans/{scan_id}/findings` — Filterable findings list (by `severity`, `type`, `status`) with pagination (`?page=1&limit=20`)
- `GET /api/findings/{finding_id}` — Get detailed finding object with sanitized evidence & cURL PoC
- `PATCH /api/findings/{finding_id}` — Update finding status (`open`, `resolved`, `false_positive`, `in_review`)

### 📊 Dashboard & Attack Surface (Phase 3)
- `GET /api/scans/{scan_id}/dashboard` — Security score, severity breakdown (`critical`, `high`, `medium`, `low`), scan duration
- `GET /api/scans/{scan_id}/endpoints` — Discovered endpoints or Attack Surface graph (`?page=1&limit=20`) with risk levels & related findings

### ⏱️ Timeline & Reports (Phase 3)
- `GET /api/scans/{scan_id}/events` — Chronological timeline of scan execution events
- `GET /api/scans/{scan_id}/report` — Comprehensive executive vulnerability report

### ⚡ Live WebSockets
- `WS /ws/scans/{scan_id}` (or `WS /api/scans/{scan_id}/ws`) — Real-time progress & findings feed

---

## 🧮 Deterministic Security Score Calculation

The security score is calculated deterministically on a 0 to 100 scale:

$$\text{Security Score} = \max(0, \min(100, 100 - (25 \cdot N_{\text{Critical}} + 15 \cdot N_{\text{High}} + 5 \cdot N_{\text{Medium}} + 2 \cdot N_{\text{Low}})))$$

- **Critical**: -25 points
- **High**: -15 points
- **Medium**: -5 points
- **Low**: -2 points

---

## 🧪 Testing with `curl`

### 1. Register & Login
```bash
# Register user
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "engineer@sentinel.dev", "password": "SecurePassword123!"}'

# Login to get JWT token
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "engineer@sentinel.dev", "password": "SecurePassword123!"}'
```

### 2. Upload Spec & Start Scan
```bash
# Create Scan
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer <TOKEN>" \
  -F "project_id=<PROJECT_ID>" \
  -F "file=@spec.json;type=application/json"

# Start Scan Execution
curl -X POST http://localhost:8000/api/scans/<SCAN_ID>/start \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://localhost:9000"}'
```

### 3. Fetch Dashboard & Findings
```bash
# Dashboard metrics
curl -X GET http://localhost:8000/api/scans/<SCAN_ID>/dashboard \
  -H "Authorization: Bearer <TOKEN>"

# Findings list (filtered & paginated)
curl -X GET "http://localhost:8000/api/scans/<SCAN_ID>/findings?severity=CRITICAL&page=1&limit=10" \
  -H "Authorization: Bearer <TOKEN>"

# Finding details with evidence
curl -X GET http://localhost:8000/api/findings/<FINDING_ID> \
  -H "Authorization: Bearer <TOKEN>"

# Executive Report
curl -X GET http://localhost:8000/api/scans/<SCAN_ID>/report \
  -H "Authorization: Bearer <TOKEN>"
```

---

## 📡 Frontend WebSocket Integration Guide

```javascript
const scanId = "8d33aee9-7502-4947-8ca0-655fd09c9d15";
const ws = new WebSocket(`ws://localhost:8000/ws/scans/${scanId}`);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log("Scan Event:", data);

  switch (data.type) {
    case "status":
      console.log(`Scan state changed: ${data.status}`);
      break;
    case "progress":
      console.log(`Progress: ${data.progress}% - ${data.message}`);
      break;
    case "finding":
      console.warn("New Vulnerability Finding:", data.finding);
      break;
    case "completed":
      console.log("Scan completed with findings:", data.findings_count);
      break;
    case "error":
      console.error("Scan Error:", data.message);
      break;
  }
};
```

---

> **Zero-Trust Security Disclaimer**: Only scan API targets and systems that you are explicitly authorized to test.
