"""Auth flow tests: register, login, me, validation, unauthorized access."""


def test_register_returns_token(client):
    r = client.post("/api/auth/register", json={"email": "a@test.dev", "password": "S3cretpass!x"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["token_type"] == "bearer"
    assert len(body["access_token"]) > 20


def test_register_duplicate_email_conflict(client):
    client.post("/api/auth/register", json={"email": "dup@test.dev", "password": "S3cretpass!x"})
    r = client.post("/api/auth/register", json={"email": "dup@test.dev", "password": "S3cretpass!x"})
    assert r.status_code == 409


def test_register_short_password_rejected(client):
    r = client.post("/api/auth/register", json={"email": "short@test.dev", "password": "short"})
    assert r.status_code == 422


def test_register_invalid_email_rejected(client):
    r = client.post("/api/auth/register", json={"email": "not-an-email", "password": "S3cretpass!x"})
    assert r.status_code == 422


def test_login_success_and_me(client):
    client.post("/api/auth/register", json={"email": "b@test.dev", "password": "S3cretpass!x"})
    r = client.post("/api/auth/login", json={"email": "b@test.dev", "password": "S3cretpass!x"})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]

    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["email"] == "b@test.dev"


def test_login_wrong_password(client):
    client.post("/api/auth/register", json={"email": "c@test.dev", "password": "S3cretpass!x"})
    r = client.post("/api/auth/login", json={"email": "c@test.dev", "password": "WrongPass!99"})
    assert r.status_code == 401


def test_login_unknown_email(client):
    r = client.post("/api/auth/login", json={"email": "ghost@test.dev", "password": "Whatever!123"})
    assert r.status_code == 401


def test_me_requires_token(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401  # missing credentials


def test_me_rejects_garbage_token(client):
    r = client.get("/api/auth/me", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401
