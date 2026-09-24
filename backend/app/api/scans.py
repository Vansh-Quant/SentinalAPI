"""Scan endpoints — OpenAPI upload, scan retrieval, status polling, scan execution, and live WebSockets."""

import logging
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession
from app.models.endpoint import Endpoint
from app.models.scan import Scan
from app.schemas.scan import (
    EndpointOut,
    ScanList,
    ScanOut,
    ScanStartRequest,
    ScanStartResponse,
    ScanStatus,
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


@router.get("/{scan_id}/endpoints", response_model=list[EndpointOut])
def list_scan_endpoints(scan_id: str, user: CurrentUser, db: DbSession) -> list[Endpoint]:
    scan = get_owned_scan(db, user_id=user.id, scan_id=scan_id)
    return list(
        db.execute(
            select(Endpoint)
            .where(Endpoint.scan_id == scan.id)
            .order_by(Endpoint.path, Endpoint.method)
        ).scalars().all()
    )


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


@router.websocket("/{scan_id}/ws")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint mounted at /api/scans/{scan_id}/ws for live updates."""
    await ws_manager.connect(scan_id, websocket)
    try:
        while True:
            # Keep connection open and receive optional ping/pong/messages from client
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)
