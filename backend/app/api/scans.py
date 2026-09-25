"""Scan endpoints — OpenAPI upload, scan execution, status polling, findings, dashboard, events, and reports."""

import logging
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select

from app.api.deps import CurrentUser, DbSession, require_scan_access_ws
from app.models.endpoint import Endpoint
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.scan_event import ScanEvent
from app.schemas.dashboard import (
    DashboardOut,
    EndpointAttackSurfaceList,
    ReportOut,
    ScanEventOut,
)
from app.schemas.finding import FindingList, FindingOut
from app.schemas.scan import (
    EndpointOut,
    ScanList,
    ScanOut,
    ScanStartRequest,
    ScanStartResponse,
    ScanStatus,
)
from app.services.dashboard_service import (
    format_finding_out,
    generate_scan_report,
    get_attack_surface,
    get_dashboard_summary,
)
from app.services.scan_manager import scan_manager
from app.services.scan_service import create_scan_for_project, get_owned_scan, scan_status_payload
from app.services.ws_manager import manager as ws_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(
    user: CurrentUser,
    db: DbSession,
    project_id: str = Form(..., description="Owning project UUID"),
    file: UploadFile = File(..., description="OpenAPI 3.x JSON or YAML specification"),
) -> Scan:
    """Upload an OpenAPI spec and create a queued scan."""
    return create_scan_for_project(db, user_id=user.id, project_id=project_id, file=file)


@router.get("", response_model=ScanList)
def list_scans(
    user: CurrentUser,
    db: DbSession,
    project_id: str | None = None,
) -> ScanList:
    """List the caller's scans, optionally filtered by project."""
    q = select(Scan).join(Scan.project).where(Scan.project.has(owner_id=user.id))  # type: ignore[attr-defined]
    if project_id:
        q = q.where(Scan.project_id == project_id)
    scans = db.execute(q.order_by(Scan.created_at.desc())).scalars().all()
    return ScanList(total=len(scans), items=list(scans))


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, user: CurrentUser, db: DbSession) -> Scan:
    return get_owned_scan(db, user_id=user.id, scan_id=scan_id)


@router.get("/{scan_id}/status", response_model=ScanStatus)
def get_scan_status(scan_id: str, user: CurrentUser, db: DbSession) -> ScanStatus:
    scan = get_owned_scan(db, user_id=user.id, scan_id=scan_id)
    return scan_status_payload(db, scan)


@router.get("/{scan_id}/endpoints")
def list_scan_endpoints(
    scan_id: str,
    user: CurrentUser,
    db: DbSession,
    page: int | None = None,
    limit: int | None = None,

):
    """List discovered spec endpoints or paginated attack surface graph information."""
    scan = get_owned_scan(db, user_id=user.id, scan_id=scan_id)

    if page is not None or limit is not None:
        return get_attack_surface(db, scan, page=page or 1, limit=limit or 20)

    endpoints = list(
        db.execute(
            select(Endpoint)
            .where(Endpoint.scan_id == scan.id)
            .order_by(Endpoint.path, Endpoint.method)
        ).scalars().all()
    )
    return [EndpointOut.model_validate(ep) for ep in endpoints]


@router.post("/{scan_id}/start", response_model=ScanStartResponse)
async def start_scan_endpoint(
    scan_id: str,
    user: CurrentUser,
    db: DbSession,
    background_tasks: BackgroundTasks,
    payload: ScanStartRequest | None = None,
) -> ScanStartResponse:
    """Start scan execution for an owned scan job."""
    scan = get_owned_scan(db, user_id=user.id, scan_id=scan_id)

    if scan.status == "running" or scan_manager.is_running(str(scan.id)):
        raise HTTPException(status_code=400, detail="Scan is already running")

    if not scan.spec:
        raise HTTPException(status_code=400, detail="OpenAPI specification data missing for this scan")

    target_url = payload.target_url if payload else None
    identities = payload.identities if payload else None

    try:
        updated_scan = await scan_manager.start_scan(
            scan_id=scan.id,
            target_url=target_url,
            identities=identities,
            background_tasks=background_tasks,
        )
        return ScanStartResponse(
            scan_id=str(updated_scan.id),
            status=updated_scan.status,
            message="Scan job queued successfully",
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))


@router.post("/{scan_id}/cancel", response_model=ScanStartResponse)
async def cancel_scan_endpoint(
    scan_id: str,
    user: CurrentUser,
    db: DbSession,
) -> ScanStartResponse:
    """Safely cancel a queued or running scan job."""
    scan = get_owned_scan(db, user_id=user.id, scan_id=scan_id)

    if scan.status in ("completed", "failed", "cancelled"):
        raise HTTPException(
            status_code=400, detail=f"Cannot cancel scan in '{scan.status}' state"
        )

    success = await scan_manager.cancel_scan(scan_id=scan.id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to cancel scan job")

    return ScanStartResponse(
        scan_id=str(scan.id),
        status="cancelled",
        message="Scan cancelled successfully",
    )


# --- Phase 3 Endpoints ---

@router.get("/{scan_id}/findings", response_model=FindingList)
def list_scan_findings(
    scan_id: str,
    user: CurrentUser,
    db: DbSession,
    severity: str | None = Query(None, description="Filter by severity e.g. CRITICAL, HIGH, MEDIUM, LOW"),
    type: str | None = Query(None, description="Filter by type e.g. BOLA, EXCESSIVE_DATA_EXPOSURE, RATE_LIMITING"),
    status: str | None = Query(None, description="Filter by status e.g. open, resolved, false_positive"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
) -> FindingList:
    """Fetch findings for a scan with severity/type/status filtering and pagination."""
    scan = get_owned_scan(db, user_id=user.id, scan_id=scan_id)

    q = select(Finding).where(Finding.scan_id == scan.id)
    if severity:
        q = q.where(func.upper(Finding.severity) == severity.upper())
    if type:
        q = q.where(func.upper(Finding.type) == type.upper())
    if status:
        q = q.where(func.lower(Finding.status) == status.lower())

    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()

    offset = (page - 1) * limit
    findings = db.execute(
        q.order_by(Finding.created_at.desc()).offset(offset).limit(limit)
    ).scalars().all()

    items = [format_finding_out(f) for f in findings]
    return FindingList(total=total, page=page, limit=limit, items=items)


@router.get("/{scan_id}/dashboard", response_model=DashboardOut)
def get_scan_dashboard(scan_id: str, user: CurrentUser, db: DbSession) -> DashboardOut:
    """Fetch dashboard metrics, severity breakdown, and deterministic security score."""
    scan = get_owned_scan(db, user_id=user.id, scan_id=scan_id)
    return get_dashboard_summary(db, scan)


@router.get("/{scan_id}/events", response_model=list[ScanEventOut])
def list_scan_events(scan_id: str, user: CurrentUser, db: DbSession) -> list[ScanEvent]:
    """Fetch chronological timeline events for a scan job."""
    scan = get_owned_scan(db, user_id=user.id, scan_id=scan_id)
    return list(
        db.execute(
            select(ScanEvent)
            .where(ScanEvent.scan_id == scan.id)
            .order_by(ScanEvent.created_at.asc())
        ).scalars().all()
    )


@router.get("/{scan_id}/report", response_model=ReportOut)
def get_scan_report(scan_id: str, user: CurrentUser, db: DbSession) -> ReportOut:
    """Generate executive vulnerability report for a scan."""
    scan = get_owned_scan(db, user_id=user.id, scan_id=scan_id)
    return generate_scan_report(db, scan)


@router.websocket("/{scan_id}/ws")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint mounted at /api/scans/{scan_id}/ws for live updates."""
    # Zero-Trust parity with REST: only the scan owner may subscribe.
    require_scan_access_ws(websocket, scan_id)
    await ws_manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)
