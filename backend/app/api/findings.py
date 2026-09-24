"""Findings standalone API router — GET /api/findings/{id}, PATCH /api/findings/{id}."""

import logging
import uuid

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.finding import FindingOut, FindingUpdate
from app.services.dashboard_service import format_finding_out

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/findings", tags=["findings"])


def get_owned_finding(db: DbSession, user_id: uuid.UUID, finding_id_str: str) -> Finding:
    """Fetch a finding by ID, ensuring the caller owns the parent project."""
    try:
        fid = uuid.UUID(str(finding_id_str))
    except ValueError:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding = db.get(Finding, fid)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    scan = db.get(Scan, finding.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Finding not found")

    project = db.get(Project, scan.project_id)
    if not project or project.owner_id != user_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    return finding


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, user: CurrentUser, db: DbSession) -> FindingOut:
    """Fetch detailed information, evidence, and PoC request for a specific finding."""
    finding = get_owned_finding(db, user_id=user.id, finding_id_str=finding_id)
    return format_finding_out(finding)


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding_status(
    finding_id: str,
    payload: FindingUpdate,
    user: CurrentUser,
    db: DbSession,
) -> FindingOut:
    """Update finding status (e.g., open, resolved, false_positive, in_review)."""
    finding = get_owned_finding(db, user_id=user.id, finding_id_str=finding_id)

    valid_statuses = {"open", "resolved", "false_positive", "in_review", "mitigated"}
    new_status = payload.status.lower()
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{payload.status}'. Must be one of: {', '.join(sorted(valid_statuses))}",
        )

    finding.status = new_status
    db.commit()
    db.refresh(finding)
    logger.info("finding %s status updated to '%s' by user %s", finding.id, new_status, user.id)

    return format_finding_out(finding)
