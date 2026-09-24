"""Project API tests, including cross-user authorization."""

from tests.conftest import auth_headers, make_project


def test_create_project(client):
    headers = auth_headers(client)
    r = client.post(
        "/api/projects",
        json={"name": "Payments API", "description": "d", "base_url": "http://localhost:9000"},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "Payments API"
    assert body["base_url"] == "http://localhost:9000"
    assert body["owner_id"]


def test_list_projects_only_own(client):
    h1 = auth_headers(client, email="u1@test.dev")
    h2 = auth_headers(client, email="u2@test.dev")
    make_project(client, h1, "U1 Project")
    make_project(client, h2, "U2 Project")

    r = client.get("/api/projects", headers=h1)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["name"] == "U1 Project"


def test_get_own_project(client):
    headers = auth_headers(client)
    p = make_project(client, headers)
    r = client.get(f"/api/projects/{p['id']}", headers=headers)
    assert r.status_code == 200
    assert r.json()["id"] == p["id"]


def test_get_project_missing_404(client):
    headers = auth_headers(client)
    r = client.get("/api/projects/00000000-0000-0000-0000-000000000000", headers=headers)
    assert r.status_code == 404


def test_get_project_bad_uuid_404(client):
    headers = auth_headers(client)
    r = client.get("/api/projects/not-a-uuid", headers=headers)
    assert r.status_code == 404


def test_foreign_project_hidden(client, other_user_headers):
    headers = auth_headers(client)
    p = make_project(client, headers)  # owned by default user
    r = client.get(f"/api/projects/{p['id']}", headers=other_user_headers)
    assert r.status_code == 404  # ownership check hides foreign projects


def test_projects_require_auth(client):
    r = client.get("/api/projects")
    assert r.status_code == 401  # missing credentials
