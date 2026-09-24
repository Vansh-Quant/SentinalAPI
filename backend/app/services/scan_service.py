"""Scan lifecycle service.

Phase 1 scope: create scans from uploaded OpenAPI specs, persist them safely,
extract and store endpoints, and report status. Actual test execution arrives
with the Phase 2 worker (app/workers/).
"""

import logging
import uuid

from fastapi import HTTPException, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.endpoint import Endpoint
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.scan import ScanStatus
from app.services import openapi_parser
from app.services.storage import save_upload

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {".json", ".yaml", ".yml"}
ALLOWED_CONTENT_TYPES = {
    "application/json",
    "application/yaml",
    "application/x-yaml",
    "text/yaml",
    "text/x-yaml",
    "text/plain",  # curl often sends YAML as text/plain
    "application/octet-stream",  # curl -F sends this unless overridden
}


def _validate_upload(filename: str, content_type: str | None, size: int) -> None:
    if size <= 0:
        raise HTTPException(400, "Uploaded file is empty")
    if size > settings.max_upload_size:
        raise HTTPException(
            413,
            f"File too large ({size} bytes); limit is {settings.max_upload_size} bytes",
        )
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"Unsupported file type '{ext or filename}'; use .json, .yaml or .yml")
    if content_type and content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(415, f"Unsupported content type '{content_type}'")


def create_scan_for_project(
    db: Session,
    *,
    user_id,
    project_id: str,
    file: UploadFile,
) -> Scan:
    """Validate upload, parse OpenAPI, persist spec + scan + endpoints."""
    # --- authorization: project must exist and belong to the caller ---------
    try:
        pid = uuid.UUID(str(project_id))
    except ValueError:
        raise HTTPException(404, "Project not found")
    project = db.get(Project, pid)
    if project is None or project.owner_id != user_id:
        raise HTTPException(404, "Project not found")

    # --- read and size-check the upload --------------------------------------
    filename = file.filename or "spec.json"
    content_type = file.content_type
    data = file.file.read()
    _validate_upload(filename, content_type, len(data))

    # --- parse + validate OpenAPI --------------------------------------------
    try:
        doc, fmt = openapi_parser.parse_spec(data)
        version = openapi_parser.validate_openapi(doc)
    except openapi_parser.OpenAPIError as exc:
        raise HTTPException(422, str(exc))
    endpoints = openapi_parser.extract_endpoints(doc)

    # --- persist spec safely --------------------------------------------------
    rel_path, _safe_name = save_upload(data, filename)
    info = doc.get("info") or {}

    scan = Scan(
        project_id=pid,
        status="queued",
        spec=doc,
        spec_path=rel_path,
        spec_format=fmt,
        openapi_version=version,
        title=info.get("title"),
        endpoints_discovered=len(endpoints),
    )
    db.add(scan)
    db.flush()  # assign scan.id before creating endpoints

    for ep in endpoints:
        db.add(
            Endpoint(
                scan_id=scan.id,
                method=ep["method"],
                path=ep["path"],
                operation_id=ep["operation_id"],
                summary=ep["summary"],
                description=ep["description"],
                tags=ep["tags"],
                parameters=ep["parameters"],
                request_body=ep["request_body"],
                security=ep["security"],
            )
        )
    db.commit()
    db.refresh(scan)
    logger.info(
        "scan %s created for project %s: %d endpoints",
        scan.id, pid, len(endpoints),
    )
    return scan


def get_owned_scan(db: Session, *, user_id, scan_id: str) -> Scan:
    """Fetch a scan the caller owns (via its project) or raise 404."""
    try:
        sid = uuid.UUID(str(scan_id))
    except ValueError:
        raise HTTPException(404, "Scan not found")
    scan = db.get(Scan, sid)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    project = db.get(Project, scan.project_id)
    if project is None or project.owner_id != user_id:
        raise HTTPException(404, "Scan not found")
    return scan


def scan_status_payload(db: Session, scan: Scan) -> ScanStatus:
    """Build the compact status payload, including the live findings count."""
    findings_count = db.execute(
        select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)
    ).scalar_one()
    return ScanStatus(
        scan_id=str(scan.id),
        status=scan.status,
        progress=float(scan.progress),
        endpoints_discovered=scan.endpoints_discovered,
        tests_generated=scan.tests_generated,
        tests_run=scan.tests_run,
        tests_completed=scan.tests_completed,
        findings=int(findings_count),
        target_url=scan.target_url,
    )
