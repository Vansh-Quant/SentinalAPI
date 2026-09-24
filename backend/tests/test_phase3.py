"""Phase 3 Results Persistence, Dashboard, Attack Surface, Timeline, and Report tests."""

import time
import pytest
from unittest.mock import patch

from fastapi.testclient import TestClient
from tests.conftest import auth_headers, make_project, spec_upload_files
from app.services.scanner_client import ScannerConnectionError


def _create_and_run_scan(client: TestClient, headers: dict) -> tuple[dict, dict]:
    """Helper to create project, upload spec, start scan, and wait for completion."""
    project = make_project(client, headers)
    r_scan = client.post(
        "/api/scans",
        data={"project_id": project["id"]},
        files=spec_upload_files(),
        headers=headers,
    )
    assert r_scan.status_code == 201
    scan = r_scan.json()

    with patch("app.services.scan_manager.ScannerClient.start_scan_job", side_effect=ScannerConnectionError("offline")):
        r_start = client.post(f"/api/scans/{scan['id']}/start", headers=headers)
        assert r_start.status_code == 200

    time.sleep(0.5)
    return project, scan


def test_phase3_finding_ingestion_and_retrieval(client: TestClient):
    """Test finding ingestion, list retrieval, and pagination."""
    headers = auth_headers(client)
    _, scan = _create_and_run_scan(client, headers)

    # Get scan findings
    r = client.get(f"/api/scans/{scan['id']}/findings", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "total" in data
    assert "items" in data
    assert data["total"] > 0

    first_finding = data["items"][0]
    for field in ("id", "scan_id", "type", "title", "severity", "confidence", "status", "created_at"):
        assert field in first_finding

    assert first_finding["type"] in ("BOLA", "EXCESSIVE_DATA_EXPOSURE", "RATE_LIMITING")
    assert first_finding["status"] == "open"


def test_phase3_finding_details_and_evidence_redaction(client: TestClient):
    """Test GET /api/findings/{finding_id} and verify secrets redaction in evidence."""
    headers = auth_headers(client)
    _, scan = _create_and_run_scan(client, headers)

    findings = client.get(f"/api/scans/{scan['id']}/findings", headers=headers).json()["items"]
    fid = findings[0]["id"]

    r = client.get(f"/api/findings/{fid}", headers=headers)
    assert r.status_code == 200, r.text
    detail = r.json()
    assert detail["id"] == fid
    assert "evidence" in detail
    assert "poc_request" in detail

    # Check credential redaction in evidence
    if detail["evidence"]:
        ev = detail["evidence"]
        if ev.get("original_request"):
            assert "<user_a_token>" not in ev["original_request"]
            assert "[REDACTED]" in ev["original_request"] or "Bearer [REDACTED]" in ev["original_request"]


def test_phase3_finding_status_update(client: TestClient):
    """Test PATCH /api/findings/{finding_id} status transition."""
    headers = auth_headers(client)
    _, scan = _create_and_run_scan(client, headers)

    findings = client.get(f"/api/scans/{scan['id']}/findings", headers=headers).json()["items"]
    fid = findings[0]["id"]

    r = client.patch(f"/api/findings/{fid}", json={"status": "resolved"}, headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"

    # Invalid status should return 400
    r_bad = client.patch(f"/api/findings/{fid}", json={"status": "invalid_status_type"}, headers=headers)
    assert r_bad.status_code == 400


def test_phase3_dashboard_calculation(client: TestClient):
    """Test GET /api/scans/{scan_id}/dashboard calculation."""
    headers = auth_headers(client)
    _, scan = _create_and_run_scan(client, headers)

    r = client.get(f"/api/scans/{scan['id']}/dashboard", headers=headers)
    assert r.status_code == 200, r.text
    dash = r.json()

    for key in ("security_score", "endpoints", "tests_run", "tests_completed", "findings", "severity", "scan_status"):
        assert key in dash

    assert 0 <= dash["security_score"] <= 100
    assert dash["endpoints"] == 4
    assert dash["severity"]["critical"] >= 0


def test_phase3_findings_filtering_and_pagination(client: TestClient):
    """Test findings severity/type filtering and page/limit pagination."""
    headers = auth_headers(client)
    _, scan = _create_and_run_scan(client, headers)

    # Filter by severity
    r_crit = client.get(f"/api/scans/{scan['id']}/findings?severity=CRITICAL", headers=headers)
    assert r_crit.status_code == 200
    for item in r_crit.json()["items"]:
        assert item["severity"] == "CRITICAL"

    # Pagination
    r_page = client.get(f"/api/scans/{scan['id']}/findings?page=1&limit=1", headers=headers)
    assert r_page.status_code == 200
    pdata = r_page.json()
    assert pdata["page"] == 1
    assert pdata["limit"] == 1
    assert len(pdata["items"]) <= 1


def test_phase3_attack_surface_api(client: TestClient):
    """Test GET /api/scans/{scan_id}/endpoints Attack Surface graph endpoint."""
    headers = auth_headers(client)
    _, scan = _create_and_run_scan(client, headers)

    r = client.get(f"/api/scans/{scan['id']}/endpoints?page=1&limit=10", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "total" in data
    assert "items" in data
    assert len(data["items"]) == 4

    ep = data["items"][0]
    for key in ("id", "method", "path", "authentication_required", "risk_level", "related_findings"):
        assert key in ep


def test_phase3_scan_timeline_events(client: TestClient):
    """Test GET /api/scans/{scan_id}/events timeline."""
    headers = auth_headers(client)
    _, scan = _create_and_run_scan(client, headers)

    r = client.get(f"/api/scans/{scan['id']}/events", headers=headers)
    assert r.status_code == 200, r.text
    events = r.json()
    assert len(events) > 0

    event_types = [ev["event_type"] for ev in events]
    assert "scan_started" in event_types or "scan_running" in event_types
    assert "openapi_parsed" in event_types


def test_phase3_executive_report_api(client: TestClient):
    """Test GET /api/scans/{scan_id}/report endpoint."""
    headers = auth_headers(client)
    _, scan = _create_and_run_scan(client, headers)

    r = client.get(f"/api/scans/{scan['id']}/report", headers=headers)
    assert r.status_code == 200, r.text
    rep = r.json()

    for key in ("scan_id", "executive_summary", "security_score", "vulnerability_summary", "findings", "recommendations", "scan_metadata"):
        assert key in rep

    assert len(rep["recommendations"]) > 0
    assert 0 <= rep["security_score"] <= 100


def test_phase3_cross_user_access_prevention(client: TestClient, other_user_headers: dict):
    """Test that users cannot access another user's findings, dashboard, report, or events."""
    headers = auth_headers(client)
    _, scan = _create_and_run_scan(client, headers)

    findings = client.get(f"/api/scans/{scan['id']}/findings", headers=headers).json()["items"]
    fid = findings[0]["id"]

    # Other user attempts access
    assert client.get(f"/api/scans/{scan['id']}/findings", headers=other_user_headers).status_code == 404
    assert client.get(f"/api/findings/{fid}", headers=other_user_headers).status_code == 404
    assert client.patch(f"/api/findings/{fid}", json={"status": "resolved"}, headers=other_user_headers).status_code == 404
    assert client.get(f"/api/scans/{scan['id']}/dashboard", headers=other_user_headers).status_code == 404
    assert client.get(f"/api/scans/{scan['id']}/events", headers=other_user_headers).status_code == 404
    assert client.get(f"/api/scans/{scan['id']}/report", headers=other_user_headers).status_code == 404
