"""Scan API tests: upload, validation, extraction, status, ownership."""

from tests.conftest import auth_headers, make_project, spec_upload_files


def _create_scan(client, headers, project_id, filename="openapi.json"):
    return client.post(
        "/api/scans",
        data={"project_id": project_id},
        files=spec_upload_files(),
        headers=headers,
    )


def test_scan_creation_stores_endpoints(client):
    headers = auth_headers(client)
    project = make_project(client, headers)
    r = _create_scan(client, headers, project["id"])
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "queued"
    assert body["endpoints_discovered"] == 4  # fixture spec has 4 operations
    assert body["openapi_version"] == "3.0.3"
    assert body["title"] == "Mini Petstore"

    # endpoints are stored and retrievable
    r = client.get(f"/api/scans/{body['id']}/endpoints", headers=headers)
    assert r.status_code == 200
    eps = r.json()
    assert len(eps) == 4
    methods_paths = {(e["method"], e["path"]) for e in eps}
    assert ("GET", "/pets") in methods_paths
    assert ("POST", "/pets") in methods_paths
    assert ("DELETE", "/pets/{petId}") in methods_paths

    post_ep = next(e for e in eps if e["method"] == "POST")
    assert post_ep["operation_id"] == "createPet"
    assert post_ep["request_body"] is not None
    assert post_ep["security"] == [{"bearerAuth": []}]


def test_scan_status_shape(client):
    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"]).json()

    r = client.get(f"/api/scans/{scan['id']}/status", headers=headers)
    assert r.status_code == 200
    body = r.json()
    for key in (
        "scan_id", "status", "progress",
        "endpoints_discovered", "tests_run", "tests_completed", "findings",
    ):
        assert key in body
    assert body["scan_id"] == scan["id"]
    assert body["status"] == "queued"
    assert body["endpoints_discovered"] == 4
    assert body["findings"] == 0


def test_scan_get_by_id(client):
    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"]).json()
    r = client.get(f"/api/scans/{scan['id']}", headers=headers)
    assert r.status_code == 200
    assert r.json()["id"] == scan["id"]


def test_scan_upload_yaml(client):
    headers = auth_headers(client)
    project = make_project(client, headers)
    yaml_spec = b"""
openapi: 3.0.3
info:
  title: YAML Spec
  version: "1.0"
paths:
  /things:
    get:
      operationId: listThings
      responses:
        '200':
          description: ok
"""
    r = client.post(
        "/api/scans",
        data={"project_id": project["id"]},
        files={"file": ("spec.yaml", yaml_spec, "application/yaml")},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    assert r.json()["spec_format"] == "yaml"
    assert r.json()["endpoints_discovered"] == 1


def test_scan_invalid_file_rejected(client):
    headers = auth_headers(client)
    project = make_project(client, headers)
    r = client.post(
        "/api/scans",
        data={"project_id": project["id"]},
        files={"file": ("evil.exe", b"MZ...", "application/octet-stream")},
        headers=headers,
    )
    assert r.status_code == 400  # bad extension


def test_scan_invalid_openapi_rejected(client):
    headers = auth_headers(client)
    project = make_project(client, headers)
    r = client.post(
        "/api/scans",
        data={"project_id": project["id"]},
        files={"file": ("openapi.json", b'{"swagger": "2.0"}', "application/json")},
        headers=headers,
    )
    assert r.status_code == 422
    assert "OpenAPI 3.x" in r.json()["detail"]


def test_scan_not_really_json_rejected(client):
    headers = auth_headers(client)
    project = make_project(client, headers)
    r = client.post(
        "/api/scans",
        data={"project_id": project["id"]},
        files={"file": ("openapi.json", b"this is not json or yaml {{", "application/json")},
        headers=headers,
    )
    assert r.status_code == 422


def test_scan_foreign_project_rejected(client, other_user_headers):
    headers = auth_headers(client)
    project = make_project(client, headers)
    r = client.post(
        "/api/scans",
        data={"project_id": project["id"]},
        files=spec_upload_files(),
        headers=other_user_headers,
    )
    assert r.status_code == 404


def test_scan_status_foreign_hidden(client, other_user_headers):
    headers = auth_headers(client)
    project = make_project(client, headers)
    scan = _create_scan(client, headers, project["id"]).json()
    r = client.get(f"/api/scans/{scan['id']}/status", headers=other_user_headers)
    assert r.status_code == 404


def test_scan_requires_auth(client):
    r = client.post(
        "/api/scans",
        data={"project_id": "00000000-0000-0000-0000-000000000000"},
        files=spec_upload_files(),
    )
    assert r.status_code == 401  # missing credentials
