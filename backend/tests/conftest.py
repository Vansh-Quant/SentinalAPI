"""Test fixtures: isolated SQLite DB, test client, auth helpers, sample specs."""

import io
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models.user import User
from app.core.security import hash_password


@pytest.fixture(autouse=True)
def _isolate_db():
    """Fresh schema per test; teardown drops everything."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# --- helpers -----------------------------------------------------------------

def register(client: TestClient, email: str = "user@test.dev", password: str = "S3cretpass!x") -> dict:
    r = client.post("/api/auth/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.text
    return r.json()


def auth_headers(client: TestClient, email: str = "user@test.dev", password: str = "S3cretpass!x") -> dict:
    tok = register(client, email, password)["access_token"]
    return {"Authorization": f"Bearer {tok}"}


def make_project(client: TestClient, headers: dict, name: str = "Demo") -> dict:
    r = client.post(
        "/api/projects",
        json={"name": name, "base_url": "http://localhost:9000"},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()


SPEC_PATH = Path(__file__).parent / "fixtures" / "petstore_minimal.json"


def load_spec_bytes() -> bytes:
    return SPEC_PATH.read_bytes()


def spec_upload_files() -> dict:
    return {"file": ("openapi.json", io.BytesIO(load_spec_bytes()), "application/json")}


@pytest.fixture
def other_user_headers(client) -> dict:
    """A second account for cross-user authorization tests."""
    return auth_headers(client, email="other@test.dev", password="D1fferentpass!")
