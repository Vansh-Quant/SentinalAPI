"""True end-to-end scan tests.

These tests boot the REAL vulnerable sandbox (sandbox.http_app) and the REAL
scanner engine (scanner.service) on ephemeral ports, then drive the actual
detection logic end-to-end:

  scanner/service.start()  ->  live HTTP against sandbox.http_app
  sandbox/vulnerable_sandbox_api.VulnerableAPI (alice/bob/admin identities)

No mocks on the detection path. The ground-truth assertions below are derived
from the sandbox source (vulnerable_sandbox_api.py), not from scanner output:
  - alice owns orders 101, 103   (TEST_USERS user_a.owned_resources.order_ids)
  - bob   owns orders 102, 104
  - /orders/{id} and /users/{id} have NO ownership check  -> BOLA observable
  - /orders (list) and /profile are ownership-filtered    -> BOLA silent
  - authenticated /users leaks password_hash/internal_notes (undocumented) -> BOPLA
  - /products leaks nothing and is public                    -> BOPLA silent
"""

import threading
import time
import uuid
from pathlib import Path

import httpx
import pytest
import uvicorn

from scanner.service import Budget, BudgetExceeded, app as scanner_app
from sandbox.http_app import app as sandbox_app

FIXTURE = Path(__file__).parent.parent / "backend" / "tests" / "fixtures" / "sandbox_openapi.json"

SANDBOX_PORT = 8766
SCANNER_PORT = 8767
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
def live_stack():
    sandbox = _serve(sandbox_app, SANDBOX_PORT)
    scanner = _serve(scanner_app, SCANNER_PORT)
    try:
        yield {
            "target": f"http://127.0.0.1:{SANDBOX_PORT}",
            "scanner": f"http://127.0.0.1:{SCANNER_PORT}",
        }
    finally:
        sandbox.should_exit = True
        scanner.should_exit = True
        # give uvicorn a beat to release the ports
        time.sleep(0.2)


def _scan(target: str, spec: dict, identities: dict) -> dict:
    """Drive the real scanner engine exactly as the backend would."""
    resp = httpx.post(
        f"http://127.0.0.1:{SCANNER_PORT}/scan/start",
        json={
            "scan_id": str(uuid.uuid4()),
            "target_url": target,
            "openapi_spec": spec,
            "identities": identities,
        },
        timeout=30.0,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _spec() -> dict:
    import json
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _by_type(result: dict, kind: str) -> list[dict]:
    return [f for f in result["findings"] if f.get("type") == kind]


# ---------------------------------------------------------------------------
# Ground truth from the sandbox source (not from scanner output)
# ---------------------------------------------------------------------------

def test_ground_truth_sandbox_bola_is_real(live_stack):
    """Sanity: without the scanner, prove /orders/{id} leaks bob's order to alice."""
    login = httpx.post(
        f"{live_stack['target']}/auth/login",
        json={"username": "alice", "password": "password123"},
    ).json()
    token = login["token"]
    r = httpx.get(
        f"{live_stack['target']}/orders/102",
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert r.status_code == 200
    assert body["order"]["user_id"] == 2  # bob's order, returned to alice
    # secure control: the list endpoint is ownership-filtered
    r2 = httpx.get(f"{live_stack['target']}/orders", headers={"Authorization": f"Bearer {token}"})
    ids = [o["id"] for o in r2.json()["orders"]]
    assert 102 not in ids and 104 not in ids


def test_ground_truth_sandbox_bopla_is_real(live_stack):
    """Sanity: authenticated /users leaks password_hash (undocumented in the fixture)."""
    token = httpx.post(
        f"{live_stack['target']}/auth/login",
        json={"username": "alice", "password": "password123"},
    ).json()["token"]
    r = httpx.get(f"{live_stack['target']}/users", headers={"Authorization": f"Bearer {token}"})
    user = r.json()["users"][0]
    assert "password_hash" in user           # the leak
    assert "internal_notes" in user
    spec = _spec()
    expected = spec["paths"]["/users"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
    assert "password_hash" not in expected   # ...and it is undocumented


# ---------------------------------------------------------------------------
# The real detection engine, end to end
# ---------------------------------------------------------------------------

def test_e2e_bola_detected_on_vulnerable_order_endpoint(live_stack):
    """Full pipeline: real scanner -> real sandbox -> BOLA findings in BOTH directions."""
    result = _scan(live_stack["target"], _spec(), IDENTITIES)
    bolas = [f for f in _by_type(result, "BOLA") if f["endpoint"] == "/orders/{order_id}"]
    assert bolas, "scanner must detect BOLA on /orders/{order_id}"

    descriptions = " | ".join(f["description"] for f in bolas)
    # ground-truth ownership asserted from the sandbox source (vulnerable_sandbox_api.py):
    # alice (user_a) -> bob's (user_b) order, and bob -> alice's order
    assert "Identity 'user_a'" in descriptions and "owned by 'user_b'" in descriptions
    assert "Identity 'user_b'" in descriptions and "owned by 'user_a'" in descriptions
    assert all(f["severity"] == "HIGH" for f in bolas)
    assert all(f["evidence"]["proof"]["cross_identity_object_id"] in {"101", "102", "103", "104"} for f in bolas)


def test_e2e_secure_endpoints_produce_no_bola(live_stack):
    """False-positive control: ownership-filtered list endpoints must stay silent."""
    result = _scan(live_stack["target"], _spec(), IDENTITIES)
    bolas = _by_type(result, "BOLA")
    assert all("/orders\"" != f["endpoint"] and f["endpoint"] != "/orders" for f in bolas)
    # /profile and /orders are non-parameterized -> structurally untestable by BOLA loop
    assert all("{" in f["endpoint"] for f in bolas), "BOLA only targets parameterized paths"


def test_e2e_bopla_detected_on_leaky_users_endpoint(live_stack):
    """Full pipeline: real scanner -> real sandbox -> BOPLA finding on /users."""
    result = _scan(live_stack["target"], _spec(), IDENTITIES)
    boplas = _by_type(result, "BOPLA")
    assert boplas, "scanner must flag the authenticated /users leak"
    f = boplas[0]
    assert f["endpoint"] == "/users"
    assert "password_hash" in f["description"]
    assert "internal_notes" in f["description"]
    # schema-aware: declared public fields are NOT reported as exposures
    assert "phone" not in f["evidence"]["proof"]["unauthorized_sensitive_properties"]


def test_e2e_secure_endpoints_produce_no_bopla(live_stack):
    """False-positive control: public catalog and profile stay silent."""
    result = _scan(live_stack["target"], _spec(), IDENTITIES)
    boplas = _by_type(result, "BOPLA")
    endpoints = {f["endpoint"] for f in boplas}
    assert "/products" not in endpoints
    assert "/profile" not in endpoints
    # and the sandbox ground truth: products really are clean
    r = httpx.get(f"{live_stack['target']}/products")
    assert "internal_sku" not in r.text and "supplier_cost" not in r.text


def test_e2e_public_endpoint_scanned_without_identity(live_stack):
    """BOPLA loop covers unauthenticated endpoints with the anonymous context."""
    result = _scan(live_stack["target"], _spec(), {})  # no identities at all
    boplas = _by_type(result, "BOPLA")
    # /users without token returns only public fields -> must NOT flag
    assert not any(f["endpoint"] == "/users" for f in boplas)
    # the scan still ran and counted the public endpoint
    assert result["endpoints_discovered"] == 6


def test_e2e_tests_counted_and_capped(live_stack):
    """Counters are real and the request budget caps execution (TC-SAFE-002)."""
    result = _scan(live_stack["target"], _spec(), IDENTITIES)
    assert result["tests_run"] > 0
    assert result["endpoints_discovered"] == 6

    # Budget: charge() raises at the request cap
    tiny = Budget(max_requests=2, max_seconds=60)
    tiny.charge(); tiny.charge()
    with pytest.raises(BudgetExceeded):
        tiny.charge()


def test_e2e_evidence_captures_live_exchange(live_stack):
    """Evidence contains the real HTTP exchange, not simulated strings."""
    result = _scan(live_stack["target"], _spec(), IDENTITIES)
    bola = next(f for f in result["findings"] if f["type"] == "BOLA")
    ev = bola["evidence"]
    assert ev["attack_response"]["status_code"] == 200
    assert live_stack["target"] in ev["attack_response"]["url"]
    assert ev["baseline_request"]["path"] != ev["attack_request"]["path"]
    # PoC references the real target and the attack path
    assert live_stack["target"].rstrip("/") in bola["poc"]
    assert "/orders/1" in bola["poc"] or "/orders/1" in ev["attack_request"]["path"]
