"""Dashboard, Attack Surface, Event Timeline, and Report schemas."""

import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.finding import FindingOut


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DashboardOut(BaseModel):
    scan_id: uuid.UUID
    security_score: int
    endpoints: int
    tests_run: int
    tests_completed: int
    findings: int
    severity: SeverityBreakdown
    scan_status: str
    scan_duration: float | None = None


class EndpointAttackSurfaceOut(BaseModel):
    id: uuid.UUID
    method: str
    path: str
    operation_id: str | None = None
    summary: str | None = None
    authentication_required: bool = False
    risk_level: str = "SAFE"
    related_findings: int = 0
    tests_performed: int = 0


class EndpointAttackSurfaceList(BaseModel):
    total: int
    page: int
    limit: int
    items: list[EndpointAttackSurfaceOut]


class ScanEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    event_type: str
    message: str
    details: dict | None = None
    created_at: datetime


class ReportOut(BaseModel):
    scan_id: uuid.UUID
    title: str | None = None
    openapi_version: str | None = None
    scan_status: str
    created_at: datetime
    scan_duration: float | None = None
    executive_summary: str
    security_score: int
    vulnerability_summary: SeverityBreakdown
    findings: list[FindingOut]
    severity_counts: dict[str, int]
    recommendations: list[str]
    scan_metadata: dict
