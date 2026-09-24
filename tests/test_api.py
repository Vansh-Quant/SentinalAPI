from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

def test_parse():
    r = client.post("/api/scan/parse", json={"spec":{"openapi":"3.0.0","paths":{"/users":{"get":{"responses":{"200":{"description":"ok"}}}}}}})
    assert r.status_code == 200
    assert r.json()["count"] == 1
