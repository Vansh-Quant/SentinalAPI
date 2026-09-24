# SentinelAPI — Zero-Trust API Vulnerability Scanner

SentinelAPI is a Zero-Trust API Vulnerability Scanner designed to analyze OpenAPI specifications, discover API endpoints, enforce strict sandbox target isolation, and orchestrate security vulnerability scans against target environments.

---

## 🏛️ Architecture Overview

```
Frontend (Dashboard)
   │
   ├── WebSocket (/ws/scans/{scan_id}) ──► Real-Time Progress & Findings Stream
   │
   ▼
Backend API (FastAPI)
   │
   ├── Auth & Projects Management
   ├── OpenAPI Spec Parser & Storage
   ├── Database Persistence (PostgreSQL / SQLite)
   │
   ▼
Scan Manager (Async Task Engine)
   │
   ├── Zero-Trust Sandbox Isolation Policy
   │
   ▼
Scanner Engine (HTTP API Client / Mock Scanner Adapter)
   │
   ▼
Target Sandbox API
```

---

## 🛠️ Technology Stack

- **Framework**: FastAPI (Python 3.11+)
- **Database**: PostgreSQL (Production) / SQLite (Development & Testing)
- **ORM & Validation**: SQLAlchemy 2.0 (Async-compatible), Pydantic v2
- **Authentication**: JWT (JSON Web Tokens) with Passlib & Bcrypt password hashing
- **Networking**: `httpx` for HTTP communication, WebSockets for live status updates
- **Testing**: `pytest` test suite

---

## ⚙️ Environment Variables Configuration

Create a `.env` file in the `backend/` directory or root directory based on `.env.example`:

```env
# Security (Set a long random key in production)
SECRET_KEY=dev-only-secret-do-not-use-in-production-0123456789abcdef
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Database Connection URL
# PostgreSQL Example: postgresql+psycopg2://sentinel:sentinelpass@localhost:5432/sentinel_db
# SQLite Fallback:
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
cd backend
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Database Setup

#### Option A: PostgreSQL (Recommended for Production)

Start PostgreSQL using Docker:

```bash
docker-compose up -d postgres
```

Or run PostgreSQL locally and create the database:

```sql
CREATE DATABASE sentinel_db;
CREATE USER sentinel WITH PASSWORD 'sentinelpass';
GRANT ALL PRIVILEGES ON DATABASE sentinel_db TO sentinel;
```

#### Option B: SQLite (Quick Local Development)

No setup needed! SQLite will automatically create `sentinel.db` on launch.

---

### 3. Run Backend Server

Start the FastAPI server using `uvicorn`:

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API docs will be available at:
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

### 🔍 Scans
- `POST /api/scans` — Upload OpenAPI JSON/YAML spec and create queued scan
- `GET /api/scans` — List user's scans
- `GET /api/scans/{scan_id}` — Get scan details and spec summary
- `GET /api/scans/{scan_id}/status` — Polling status (progress, endpoints, tests, findings)
- `GET /api/scans/{scan_id}/endpoints` — List discovered spec endpoints
- `POST /api/scans/{scan_id}/start` — Initiate background scan execution
- `POST /api/scans/{scan_id}/cancel` — Safely cancel a queued or running scan

### ⚡ Live WebSockets
- `WS /ws/scans/{scan_id}` (or `WS /api/scans/{scan_id}/ws`) — Real-time progress & findings feed

---

## 🧪 Testing with `curl`

### 1. Register & Login
```bash
# Register user
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "engineer@sentinel.dev", "password": "SecurePassword123!"}'

# Login to get JWT
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "engineer@sentinel.dev", "password": "SecurePassword123!"}'
```

Save the `access_token` from the response for subsequent requests.

### 2. Create Project
```bash
curl -X POST http://localhost:8000/api/projects \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name": "E-Commerce API Test", "base_url": "http://localhost:9000"}'
```

### 3. Upload OpenAPI Spec & Create Scan
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer <TOKEN>" \
  -F "project_id=<PROJECT_ID>" \
  -F "file=@petstore.json;type=application/json"
```

### 4. Start Scan Execution
```bash
curl -X POST http://localhost:8000/api/scans/<SCAN_ID>/start \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://localhost:9000", "identities": {"user_a": "token_user_a", "user_b": "token_user_b"}}'
```

### 5. Check Scan Status
```bash
curl -X GET http://localhost:8000/api/scans/<SCAN_ID>/status \
  -H "Authorization: Bearer <TOKEN>"
```

### 6. Cancel Scan
```bash
curl -X POST http://localhost:8000/api/scans/<SCAN_ID>/cancel \
  -H "Authorization: Bearer <TOKEN>"
```

---

## 🤝 Internal Scanner Contract

Backend sends execution payload to Scanner Engine:

```json
{
  "scan_id": "8d33aee9-7502-4947-8ca0-655fd09c9d15",
  "target_url": "http://localhost:9000",
  "openapi_spec": {
    "openapi": "3.0.3",
    "info": { "title": "Mini Petstore", "version": "1.0.0" },
    "paths": { ... }
  },
  "identities": {
    "user_a": "Bearer eyJhbGciOi...",
    "user_b": "Bearer eyJhbGciOi..."
  }
}
```

The Scanner Engine processes tests and streams back updates. The Backend maintains full ownership of database persistence.

---

## 📡 Frontend WebSocket Integration Guide

Frontend clients can connect to `/ws/scans/{scan_id}` to receive real-time updates.

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

## 🧪 Running Automated Tests

Run the complete test suite:

```bash
cd backend
.venv\Scripts\pytest.exe tests
```

---
