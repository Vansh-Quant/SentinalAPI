"""Backend-pipeline integration test with a LIVE scanner engine and sandbox.

Closes the last untested seam: everything here is real —

    TestClient -> POST /api/scans/{id}/start
        -> scan_manager.start_scan (Zero-Trust gate, queue)
        -> _run_scan_job -> ScannerClient (real HTTP to scanner.service on :8767)
        -> scanner.service.start -> live HTTP to sandbox.http_app on :8766
        -> _persist_scanner_result (Finding/Evidence rows, WS broadcasts)
        -> GET /api/scans/{id}/findings + /dashboard + /events

Only the auth step is mocked (register via the API directly). No scanner or
sandbox behavior is stubbed: BOLA/BOPLA findings flow through the real
persistence layer into the REST API the frontend consumes.
"""

import json
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from sandbox.http_app import app as sandbox_app
from scanner.service import app as scanner_app

SANDBOX_PORT = 8768
SCANNER_PORT = 8769
FIXTURE = Path(__file__).parent / "fixtures" / "sandbox_openapi.json"
IDENTITIES = {"user_a": "alice:password123", "user_b": "bob:password456"}


def _serve(app, port):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/health", timeout=1.0).status_code == 200:
                return server
        except Exception:
            time.sleep(0.05)
    server.should_exit = True
    raise RuntimeError(f"test server on port {port} failed to start")


@pytest.fixture(scope="module")
def stack():
    sandbox = _serve(sandbox_app, SANDBOX_PORT)
    scanner = _serve(scanner_app, SCANNER_PORT)
    try:
        yield {"target": f"http://127.0.0.1:{SANDBOX_PORT}", "scanner": f"http://127.0.0.1:{SCANNER_PORT}"}
    finally:
        sandbox.should_exit = True
        scanner.should_exit = True
        time.sleep(0.2)


@pytest.fixture()
def client(stack):
    """Point the real settings singleton at the live stack; restore afterwards."""
    saved = (settings.scanner_base_url, settings.sandbox_base_url)
    settings.scanner_base_url = stack["scanner"]
    settings.sandbox_base_url = stack["target"]
    try:
        yield TestClient(app)
    finally:
        settings.scanner_base_url, settings.sandbox_base_url = saved


def _register(client: TestClient) -> dict:
    email = f"pipe-{uuid.uuid4().hex[:8]}@test.dev"
    r = client.post("/api/auth/register", json={"email": email, "password": "S3cretpass!x"})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _create_scan(client: TestClient, headers: dict) -> dict:
    r = client.post(
        "/api/projects",
        json={"name": "Pipe", "base_url": "http://127.0.0.1"},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    project = r.json()
    r = client.post(
        "/api/scans",
        data={"project_id": project["id"]},
        files={"file": ("sandbox_openapi.json", FIXTURE.read_bytes(), "application/json")},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()


def _wait_terminal(client: TestClient, headers: dict, scan_id: str, timeout: float = 20.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = client.get(f"/api/scans/{scan_id}/status", headers=headers).json()
        if last["status"] in ("completed", "failed", "cancelled"):
            return last
        time.sleep(0.2)
    return last or {}


def test_pipeline_live_scan_produces_findings_through_full_stack(stack, client):
    headers = _register(client)
    scan = _create_scan(client, headers)

    r = client.post(
        f"/api/scans/{scan['id']}/start",
        json={"target_url": stack["target"], "identities": IDENTITIES},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "queued"

    final = _wait_terminal(client, headers, scan["id"])
    assert final["status"] == "completed", f"scan failed: {final}"
    assert final["endpoints_discovered"] == 6
    assert final["tests_run"] > 0

    # Findings surfaced through the REST API the frontend consumes
    findings = client.get(f"/api/scans/{scan['id']}/findings", headers=headers).json()
    assert findings["total"] >= 3  # 2 BOLA directions + >=1 BOPLA
    types = {item["type"] for item in findings["items"]}
    assert "BOLA" in types
    assert "BOPLA" in types

    # Ground-truth ownership made it through persistence (identities are in the
    # description; titles are the generic finding label)
    bola_desc = " | ".join(i["description"] or "" for i in findings["items"] if i["type"] == "BOLA")
    assert "user_a" in bola_desc and "user_b" in bola_desc

    # Evidence is sanitized and complete
    fid = findings["items"][0]["id"]
    detail = client.get(f"/api/findings/{fid}", headers=headers).json()
    assert detail["evidence"] is not None
    raw = json.dumps(detail)
    assert "password123" not in raw and "password456" not in raw  # secrets never persisted
    assert "[REDACTED]" in raw or "Bearer" in raw

    # Dashboard and events reflect the live run
    dash = client.get(f"/api/scans/{scan['id']}/dashboard", headers=headers).json()
    assert dash["findings"] == findings["total"]
    assert dash["security_score"] == 100 - 15 * sum(1 for i in findings["items"] if i["severity"] == "HIGH")

    events = client.get(f"/api/scans/{scan['id']}/events", headers=headers).json()
    kinds = {e["event_type"] for e in events}
    assert "scan_started" in kinds and "scan_completed" in kinds


def test_pipeline_zero_trust_blocks_public_target(stack, client):
    headers = _register(client)
    scan = _create_scan(client, headers)
    r = client.post(
        f"/api/scans/{scan['id']}/start",
        json={"target_url": "https://arbitrary-public-website.com"},
        headers=headers,
    )
    assert r.status_code == 400
    assert "outside permitted sandbox" in r.json()["detail"]
    # scan marked failed with the reason persisted
    st = client.get(f"/api/scans/{scan['id']}/status", headers=headers).json()
    assert st["status"] == "failed"


def test_pipeline_terminal_scans_cannot_restart(stack, client):
    headers = _register(client)
    scan = _create_scan(client, headers)
    client.post(
        f"/api/scans/{scan['id']}/start",
        json={"target_url": stack["target"], "identities": IDENTITIES},
        headers=headers,
    )
    final = _wait_terminal(client, headers, scan["id"])
    assert final["status"] == "completed"
    r = client.post(f"/api/scans/{scan['id']}/start", headers=headers)
    assert r.status_code == 400
    assert "cannot be restarted" in r.json()["detail"]
