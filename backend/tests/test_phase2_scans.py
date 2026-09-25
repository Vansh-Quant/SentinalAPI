"""Phase 2 Scan API and Manager tests.

Tests cover:
- Starting scan jobs (POST /api/scans/{scan_id}/start)
- Preventing duplicate scan execution (400 Bad Request)
- Cancelling active scans (POST /api/scans/{scan_id}/cancel)
- Zero-Trust sandbox URL validation
- Scanner Client timeout, error, and malformed response handling
- Live WebSocket updates (/ws/scans/{scan_id})
"""

import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.services.scanner_client import (
    MalformedScannerResponseError,
    ScannerClient,
    ScannerConnectionError,
    ScannerError,
    is_sandboxed_url,
)
from tests.conftest import auth_headers, make_project, spec_upload_files


def _create_scan(client: TestClient, headers: dict, project_id: str) -> dict:
    r = client.post(
        "/api/scans",
        data={"project_id": project_id},
        files=spec_upload_files(),
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()


def test_start_scan_success(client: TestClient):
    """Test starting a scan job and checking status update."""
    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"])

    with patch("app.services.scan_manager.ScannerClient.start_scan_job", side_effect=ScannerConnectionError("offline")):
        r = client.post(
            f"/api/scans/{scan['id']}/start",
            json={"target_url": "http://localhost:9000", "identities": {"user_a": "token_a"}},
            headers=headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["scan_id"] == scan["id"]
        assert body["status"] in ("queued", "running", "completed")

        # Give background execution a moment to complete
        time.sleep(0.5)

        # Check status endpoint
        r_status = client.get(f"/api/scans/{scan['id']}/status", headers=headers)
        assert r_status.status_code == 200
        st = r_status.json()
        assert st["status"] in ("running", "completed")
        assert st["endpoints_discovered"] == 4
        assert st["tests_generated"] > 0


def test_start_scan_duplicate_rejected(client: TestClient):
    """Test that attempting to start an already running scan returns 400 Bad Request."""
    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"])

    with patch("app.services.scan_manager.scan_manager.is_running", return_value=True):
        r2 = client.post(f"/api/scans/{scan['id']}/start", headers=headers)
        assert r2.status_code == 400
        assert "already running" in r2.json()["detail"].lower()


def test_cancel_scan_success(client: TestClient):
    """Test cancelling an active scan job."""
    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"])

    async def slow_mock_scanner(*args, **kwargs):
        await asyncio.sleep(2.0)

    with patch("app.services.scan_manager.ScannerClient.start_scan_job", side_effect=ScannerConnectionError("offline")):
        with patch("app.services.scan_manager.scan_manager._execute_mock_scanner", side_effect=slow_mock_scanner):
            r_start = client.post(f"/api/scans/{scan['id']}/start", headers=headers)
            assert r_start.status_code == 200

            # Cancel scan while running
            r_cancel = client.post(f"/api/scans/{scan['id']}/cancel", headers=headers)
            assert r_cancel.status_code == 200
            assert r_cancel.json()["status"] == "cancelled"

            # Verify status via status endpoint
            st = client.get(f"/api/scans/{scan['id']}/status", headers=headers).json()
            assert st["status"] == "cancelled"


def test_cancel_cancelled_scan_fails(client: TestClient):
    """Test that cancelling an already cancelled scan returns 400."""
    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"])

    async def slow_mock_scanner(*args, **kwargs):
        await asyncio.sleep(2.0)

    with patch("app.services.scan_manager.ScannerClient.start_scan_job", side_effect=ScannerConnectionError("offline")):
        with patch("app.services.scan_manager.scan_manager._execute_mock_scanner", side_effect=slow_mock_scanner):
            client.post(f"/api/scans/{scan['id']}/start", headers=headers)
            client.post(f"/api/scans/{scan['id']}/cancel", headers=headers)

            r2 = client.post(f"/api/scans/{scan['id']}/cancel", headers=headers)
            assert r2.status_code == 400
            assert "cannot cancel scan" in r2.json()["detail"].lower()


def test_zero_trust_sandbox_validation(client: TestClient):
    """Test that non-sandboxed target URLs are rejected under Zero-Trust rules."""
    valid, reason = is_sandboxed_url("http://localhost:8000")
    assert valid is True

    valid, reason = is_sandboxed_url("http://127.0.0.1:9000")
    assert valid is True

    valid, reason = is_sandboxed_url("https://arbitrary-public-website.com")
    assert valid is False
    assert "outside permitted sandbox environment" in reason

    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"])

    # Attempt to start scan against arbitrary internet host
    r = client.post(
        f"/api/scans/{scan['id']}/start",
        json={"target_url": "https://arbitrary-public-website.com"},
        headers=headers,
    )
    assert r.status_code == 400
    assert "outside permitted sandbox environment" in r.json()["detail"]


def test_scanner_client_timeout_handling():
    """Test ScannerClient timeout error handling."""

    async def _test():
        sc = ScannerClient(base_url="http://localhost:9999", timeout_seconds=0.1, max_retries=1)
        with patch("httpx.AsyncClient.post", side_effect=AsyncMock(side_effect=TimeoutError())):
            with pytest.raises(ScannerError):
                await sc.start_scan_job("scan_123", "http://localhost:9000", {})

    asyncio.run(_test())


def test_scanner_client_connection_error():
    """Test ScannerClient connection failure handling."""

    async def _test():
        sc = ScannerClient(base_url="http://127.0.0.1:9999", timeout_seconds=0.5, max_retries=1)
        with pytest.raises((ScannerConnectionError, ScannerError)):
            await sc.start_scan_job("scan_123", "http://127.0.0.1:9000", {})

    asyncio.run(_test())


def test_scanner_client_malformed_response():
    """Test ScannerClient malformed response handling."""

    async def _test():
        sc = ScannerClient(base_url="http://localhost:9000", timeout_seconds=1.0, max_retries=1)
        mock_resp = AsyncMock()
        def raise_json_err():
            raise ValueError("Invalid JSON")

        mock_resp.raise_for_status = lambda: None
        mock_resp.json = raise_json_err

        with patch("httpx.AsyncClient.post", return_value=mock_resp):
            with pytest.raises(MalformedScannerResponseError):
                await sc.start_scan_job("scan_123", "http://localhost:9000", {})

    asyncio.run(_test())


def test_websocket_scan_updates(client: TestClient):
    """Authenticated WebSocket connection at /ws/scans/{scan_id} for an owned scan."""
    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"])
    token = headers["Authorization"].split(" ", 1)[1]

    with client.websocket_connect(
        f"/ws/scans/{scan['id']}", subprotocols=["bearer", token]
    ) as websocket:
        websocket.send_text("ping")


def test_websocket_requires_auth(client: TestClient):
    """Unauthenticated WebSocket subscriptions are rejected before accept."""
    from starlette.websockets import WebSocketDisconnect

    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"])

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/scans/{scan['id']}"):
            pass


def test_websocket_rejects_foreign_scan(client: TestClient, other_user_headers: dict):
    """A user cannot subscribe to another user's scan WebSocket feed."""
    from starlette.websockets import WebSocketDisconnect

    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"])
    other_token = other_user_headers["Authorization"].split(" ", 1)[1]

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            f"/ws/scans/{scan['id']}", subprotocols=["bearer", other_token]
        ):
            pass


def test_ws_finding_event_broadcast(client: TestClient):
    """Persisting a finding broadcasts the documented `finding` WS event."""
    from unittest.mock import AsyncMock

    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"])

    with patch(
        "app.services.scan_manager.ScannerClient.start_scan_job",
        side_effect=ScannerConnectionError("offline"),
    ):
        with patch(
            "app.services.scan_manager.ws_manager.broadcast_to_scan", new_callable=AsyncMock
        ) as mock_broadcast:
            r = client.post(
                f"/api/scans/{scan['id']}/start",
                json={"target_url": "http://localhost:9000"},
                headers=headers,
            )
            assert r.status_code == 200, r.text

    types = {call.args[1].get("type") for call in mock_broadcast.await_args_list}
    assert "finding" in types, f"expected a finding event, got types={types}"
    finding_event = next(
        call.args[1] for call in mock_broadcast.await_args_list if call.args[1].get("type") == "finding"
    )
    assert finding_event["finding"]["type"] in ("BOLA", "EXCESSIVE_DATA_EXPOSURE", "RATE_LIMITING")
    assert finding_event["scan_id"] == scan["id"]


def test_start_completed_scan_rejected(client: TestClient):
    """Terminal scans cannot be restarted (would duplicate findings)."""
    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"])

    with patch(
        "app.services.scan_manager.ScannerClient.start_scan_job",
        side_effect=ScannerConnectionError("offline"),
    ):
        r = client.post(f"/api/scans/{scan['id']}/start", headers=headers)
        assert r.status_code == 200

        # First start completes the scan via the local engine.
        st = client.get(f"/api/scans/{scan['id']}/status", headers=headers).json()
        assert st["status"] in ("running", "completed")

        # A restart attempt on the finished scan must fail.
        r2 = client.post(f"/api/scans/{scan['id']}/start", headers=headers)
        assert r2.status_code == 400
        assert "cannot be restarted" in r2.json()["detail"]


def test_is_sandboxed_url_rejects_hostile_resolutions():
    """Textual private-range lookalikes must not validate once resolved."""
    from app.services.scanner_client import is_sandboxed_url

    # A name that string-matches the 10.x prefix but cannot be a sandbox:
    # either it resolves to a public address or it does not resolve at all.
    valid, _reason = is_sandboxed_url("http://10.0.0.1.nonexistent.invalid")
    assert valid is False

    # Literal private IPs and localhost still validate (offline-safe).
    valid, _ = is_sandboxed_url("http://127.0.0.1:9000")
    assert valid is True
    valid, _ = is_sandboxed_url("http://localhost:9000")
    assert valid is True

    # Userinfo injection is refused.
    valid, reason = is_sandboxed_url("http://user:pass@localhost:9000")
    assert valid is False
    assert "userinfo" in reason
