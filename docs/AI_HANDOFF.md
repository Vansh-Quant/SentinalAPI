# SentinelAPI AI Handoff

## Purpose

SentinelAPI is a local-first, zero-trust API vulnerability scanning demo. A user authenticates, creates an API project, uploads an OpenAPI 3.x document, starts a scan against an explicitly allowed sandbox target, receives progress updates, and reviews persisted findings, evidence, PoC requests, dashboards, and reports.

This document is an implementation handoff for another AI model. Treat the current source code as authoritative when this document and older documentation differ.

## Repository Layout

- `backend/app/main.py`: FastAPI application entrypoint, startup database initialization, CORS, health route, WebSocket route, helper scanner routes, and static frontend mount.
- `backend/app/api/`: REST and WebSocket route modules.
- `backend/app/core/`: settings, SQLAlchemy engine/session, password/JWT security.
- `backend/app/models/`: SQLAlchemy tables for users, projects, scans, endpoints, findings, evidence, and scan events.
- `backend/app/schemas/`: Pydantic request/response contracts.
- `backend/app/services/`: upload parsing/storage, scan orchestration, scanner HTTP client, sanitization, dashboard/report generation, WebSocket manager.
- `backend/tests/`: backend authentication, project, scan, WebSocket, persistence, report, and security tests.
- `scanner/`: lower-level parser, models, HTTP executor, BOLA/BOPLA components, and orchestrator.
- `sandbox/`: intentionally vulnerable FastAPI target used only as the authorized demo API.
- `frontend/index.html`: single-file frontend copied from the supplied UI and connected to the backend without changing its visual theme.
- `docs/`: human and AI documentation.
- `Dockerfile`: backend image.
- `Dockerfile.sandbox`: sandbox image.
- `docker-compose.yml`: PostgreSQL, backend, sandbox, and optional scanner placeholder services.

## Runtime Architecture

```text
Browser
  |
  | HTTP REST and WebSocket
  v
FastAPI backend
  |-- JWT authentication and ownership checks
  |-- Project and OpenAPI upload APIs
  |-- Scan manager and persistence
  |-- Dashboard, findings, evidence, report APIs
  |-- serves frontend/index.html at /
  |
  | POST SCANNER_BASE_URL/scan/start (optional)
  | fallback if scanner unavailable
  v
Deterministic local scanner
  |
  v
Explicitly allowlisted sandbox target at SANDBOX_BASE_URL
```

The backend and frontend can run from one process. When `main.py` is started from `backend/`, it mounts the repository `frontend/` directory at `/`. The browser should therefore use the backend URL, for example `http://127.0.0.1:8001/` or `http://127.0.0.1:8002/`.

## Important Port Rule

Port `8000` may be occupied by another local application. Use an available port, normally `8001` or `8002`.

The frontend does not permanently assume port 8001 anymore. Its API adapter uses `window.location.origin` by default. This means:

- open frontend at `http://127.0.0.1:8001/` -> API calls use port 8001
- open frontend at `http://127.0.0.1:8002/` -> API calls use port 8002
- optional override: set `window.SENTINEL_API_BASE` before the adapter loads

Do not start a second Uvicorn process on a port already in use. `WinError 10048` means the bind failed; the later `Application shutdown complete` line is a consequence, not the root cause.

## Start Locally on Windows

Terminal 1, sandbox:

```powershell
cd C:\Users\hp\Downloads\sentinelAPI
.\backend\.venv\Scripts\python.exe -m uvicorn sandbox.http_app:app --host 127.0.0.1 --port 9000
```

Terminal 2, backend plus frontend:

```powershell
cd C:\Users\hp\Downloads\sentinelAPI\backend
$env:DATABASE_URL="sqlite:///./sentinel-demo.db"
$env:SECRET_KEY="local-demo-secret-key-at-least-32-characters"
$env:SANDBOX_BASE_URL="http://127.0.0.1:9000"
$env:SCANNER_BASE_URL="http://127.0.0.1:9100"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Open:

```text
http://127.0.0.1:8001/
http://127.0.0.1:8001/docs
http://127.0.0.1:8001/health
http://127.0.0.1:9000/health
```

If 8001 is occupied, either stop the old process after confirming it is SentinelAPI or use 8002 and open the frontend on 8002. Do not kill an unrelated process without checking its command line.

## Authentication Contract

Public routes:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /health`
- `GET /api/health`

Register/login body:

```json
{
  "email": "demo@example.com",
  "password": "SecurePassword123!"
}
```

Response:

```json
{
  "access_token": "JWT_VALUE",
  "token_type": "bearer"
}
```

Protected requests require:

```text
Authorization: Bearer JWT_VALUE
```

The frontend stores the token in `localStorage` under `sentinel_token`, then calls `GET /api/auth/me` to synchronize the visible profile identity. It must not display the old hardcoded demo identity as the authenticated user.

Passwords are bcrypt-hashed. JWTs are signed HS256 tokens and contain an access-token type claim. Ownership is enforced by resolving the project owner through the authenticated user.

## Project and Scan Flow

1. Register or login.
2. Create a project with `POST /api/projects`.
3. Use the returned top-level `id` as `project_id`. Do not use `owner_id`.
4. Upload an OpenAPI 3.x JSON/YAML file with `POST /api/scans` multipart fields:
   - `project_id`
   - `file`
5. The backend parses and validates the document and persists one Endpoint row per operation.
6. Start the scan with `POST /api/scans/{scan_id}/start`:

```json
{
  "target_url": "http://127.0.0.1:9000",
  "identities": {}
}
```

7. Poll `GET /api/scans/{scan_id}/status` or connect to the WebSocket.
8. Read findings, evidence, dashboard, events, and report.

The supplied deterministic fixture is:

```text
backend/tests/fixtures/petstore_minimal.json
```

## Scan Lifecycle

```text
queued -> running -> completed
                   -> failed
                   -> cancelled
```

The scan manager persists state and results incrementally. Existing findings should remain persisted if a later operation fails. Duplicate starts are rejected. Cancellation marks the scan cancelled and cancels the process-local task when present.

## Scanner Contract

The optional external scanner is configured by `SCANNER_BASE_URL` and receives:

```text
POST {SCANNER_BASE_URL}/scan/start
```

Payload:

```json
{
  "scan_id": "UUID",
  "target_url": "http://127.0.0.1:9000",
  "openapi_spec": {},
  "identities": {}
}
```

It must return a JSON object containing scanner results. The current backend persists external findings through `_persist_scanner_result`.

Cancellation request:

```text
POST {SCANNER_BASE_URL}/scan/{scan_id}/cancel
```

Behavior when the external scanner is unavailable:

- connection error, timeout, or scanner communication error -> deterministic local fallback
- malformed JSON/object response -> hard scanner failure
- external scanner result available -> persist external result; do not synthesize fallback findings

The local fallback performs deterministic checks for BOLA-like paths, excessive data exposure on unauthenticated endpoints, and rate-limiting test representation. It generates findings/evidence for the sandbox demo and broadcasts progress.

## Target Security Policy

`is_sandboxed_url()` rejects arbitrary public internet hosts. Exact configured/default sandbox hosts include local/container names such as:

- `localhost`
- `127.0.0.1`
- `::1`
- `sandbox`
- configured `SANDBOX_BASE_URL` hostname

Only explicitly authorized sandbox targets should be used. Do not broaden this allowlist merely to make a public target work.

## REST Endpoint Inventory

Authentication:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`

Projects:

- `POST /api/projects`
- `GET /api/projects`
- `GET /api/projects/{project_id}`

Scans:

- `POST /api/scans` - multipart OpenAPI upload
- `GET /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/status`
- `POST /api/scans/{scan_id}/start`
- `POST /api/scans/{scan_id}/cancel`
- `GET /api/scans/{scan_id}/endpoints`
- `GET /api/scans/{scan_id}/findings`
- `GET /api/scans/{scan_id}/dashboard`
- `GET /api/scans/{scan_id}/events`
- `GET /api/scans/{scan_id}/report`

Findings:

- `GET /api/findings/{finding_id}`
- `PATCH /api/findings/{finding_id}` with status values such as `open`, `resolved`, `false_positive`, `in_review`, `mitigated`

Scanner helper APIs:

- `POST /api/scan/parse`
- `POST /api/scan/analyze-response`

Health/documentation:

- `GET /health`
- `GET /api/health`
- `GET /docs`
- `GET /openapi.json`

## WebSocket Contract

Supported paths:

```text
ws://HOST/ws/scans/{scan_id}
ws://HOST/api/scans/{scan_id}/ws
```

Connections are authenticated. Browsers pass the JWT as the requested
sub-protocol: `new WebSocket(url, ["bearer", token])`. Non-browser clients may
use `?token=<JWT>`. The server closes with 1008 when credentials are
missing/invalid and 4404 when the scan does not exist or is not owned by the
caller. The frontend in `frontend/app.js` implements the sub-protocol form.

Event types:

- `status`: lifecycle state, often includes progress/message
- `progress`: progress percentage, endpoint/test counters, message
- `finding`: newly persisted finding summary (emitted by both the local
  deterministic engine and the external-scanner persistence path)
- `completed`: final counters and 100 percent progress
- `error`: failure state/message

The frontend also polls status every 800 ms. Polling is authoritative after a disconnect. The WebSocket server accepts a text message loop and removes disconnected clients.

## Scan Restart Rule

Terminal states are final: `completed`, `failed`, and `cancelled` scans cannot
be restarted (`POST /api/scans/{id}/start` returns 400). Create a new scan for
a fresh run; this guarantees findings are never duplicated within one scan.

## Target Policy at Execution Time

The Zero-Trust policy is enforced twice per scan: once when the scan is queued
(`is_sandboxed_url`) and again immediately before the scanner executes
(`assert_target_still_sandboxed`). The external scanner request and the
scanner engine's own HTTP executor never follow redirects, and every target
hostname must resolve to a private/loopback/link-local address — textual
bypasses such as `10.0.0.1.evil.com` are rejected after resolution.

## Database Model

Relationships:

```text
User 1 -> many Project
Project 1 -> many Scan
Scan 1 -> many Endpoint
Scan 1 -> many Finding
Finding 1 -> many Evidence
Scan 1 -> many ScanEvent
```

Key behavior:

- UUID primary keys.
- SQLite for local tests/demo; PostgreSQL for Docker.
- Foreign-key cascades remove scan-owned records.
- Endpoint uniqueness is `(scan_id, method, path)`.
- Indexed ownership/status/scan/severity/endpoint/event columns support common queries.
- Startup uses SQLAlchemy metadata creation; Alembic migrations are not currently included.

## Frontend Behavior

`frontend/index.html` is a single-file UI preserving the supplied visual theme. The backend adapter in the final script:

- calls auth register/login
- stores JWT
- calls `/api/auth/me`
- updates header/profile identity
- creates project and uploads selected OpenAPI file
- starts scan
- polls status and connects to WebSocket
- loads findings and finding details/evidence
- loads report data
- uses current browser origin for API/WebSocket URLs

The frontend must be served over HTTP by FastAPI or a static server. Do not double-click the file using `file://` for the integrated demo.

A previous browser freeze was fixed in the observer that adjusts page height. It now observes `childList` only; do not re-add class/style attribute observation because `fill()` changes those classes itself.

## Failure Diagnosis

### `fetch failed` during login

Usually means the frontend URL and backend URL differ. With current code, open the frontend from the backend origin. If the page is on port 8002, the API must be on port 8002 too. Check:

```text
http://HOST:PORT/health
```

### `404 /`

Usually means an old backend process is running or the process was started from code before the static mount change. Restart the process and verify the current `backend/app/main.py` includes the `StaticFiles` mount.

### `WinError 10048`

Port already in use. Find the owner:

```powershell
Get-NetTCPConnection -State Listen -LocalPort 8001
```

### `401 Could not validate credentials`

The JWT is missing, expired, signed with a different `SECRET_KEY`, or was entered as `Bearer Bearer TOKEN` in Swagger. Swagger's authorize field expects the raw token in this project UI.

### `404 Project not found` during upload

Use the project response's top-level `id`, not `owner_id`. Also ensure login, project creation, upload, and current backend all use the same database file and `SECRET_KEY`.

### `Application shutdown complete`

This is a shutdown log, not necessarily the root error. Look earlier for bind errors, import errors, database errors, or Ctrl+C termination.

### Browser becomes unresponsive

Inspect for observer/event feedback loops in `frontend/index.html`. The known class/style MutationObserver loop has already been removed.

## Testing

From repository root:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest -q
```

Current verified result at handoff: 53 passed, with one Starlette/httpx deprecation warning.

Frontend syntax check:

```powershell
$p='C:\Users\hp\Downloads\sentinelAPI\frontend\index.html'
$env:HTML_PATH=$p
@'
const fs = require('fs');
const vm = require('vm');
const html = fs.readFileSync(process.env.HTML_PATH, 'utf8');
const scripts = [...html.matchAll(/<script(?: [^>]*)?>([\\s\\S]*?)<\\/script>/g)];
scripts.forEach((match, index) => new vm.Script(match[1], {filename: `inline-${index + 1}.js`}));
console.log(`frontend scripts parsed: ${scripts.length}`);
'@ | node -
```

## Current Git State at Handoff

The integrated frontend, API-origin fix, auth identity/theme fix, browser-freeze fix, scanner fallback, Docker setup, and documentation have been pushed to `origin/main`.

Recent relevant commits:

- `4bd442d`: use current frontend origin for API requests
- `eb1d2ae`: prevent frontend navigation freeze
- `425fd8f`: sync frontend identity and theme controls
- `17d6606`: serve exact integrated frontend and restore scan fallback

## Honest Limitations

- The local scanner is deterministic demo logic, not a full production active BOLA/BOPLA engine.
- External scanner result schema is assumed and validated only as a JSON object plus expected fields during persistence.
- Scan tasks are process-local and not distributed across multiple workers.
- Startup table creation is not a migration system.
- AI explanation UI is presentation-level; there is no dedicated AI explanation backend endpoint.
- The report is a JSON REST report; the frontend's old download action is not a server-side PDF generator.
- Docker was configured but may not be installed on the developer workstation.
- Only explicitly authorized sandbox targets may be scanned.
