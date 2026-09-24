"""Scan/endpoint request-response schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    """Body fields accepted alongside the multipart file upload."""

    project_id: str = Field(..., description="Owning project UUID")


class ScanStartRequest(BaseModel):
    """Payload to trigger execution of a scan."""

    target_url: str | None = Field(
        None,
        description="Target sandbox base URL. If omitted, uses spec servers or SANDBOX_BASE_URL.",
    )
    identities: dict[str, str] | None = Field(
        None,
        description="Optional dictionary of authentication tokens/headers per role for BOLA testing",
    )


class ScanStartResponse(BaseModel):
    scan_id: str
    status: str
    message: str = "Scan initiated"


class EndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    method: str
    path: str
    operation_id: str | None
    summary: str | None
    description: str | None
    tags: list | None
    parameters: list | None
    request_body: dict | None
    security: list | None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    status: str
    progress: float
    error: str | None
    spec_format: str
    openapi_version: str | None
    title: str | None
    target_url: str | None = None
    endpoints_discovered: int
    tests_generated: int = 0
    tests_run: int
    tests_completed: int
    created_at: datetime
    updated_at: datetime


class ScanStatus(BaseModel):
    """Compact status payload for polling by the dashboard."""

    scan_id: uuid.UUID
    status: str
    progress: float
    endpoints_discovered: int
    tests_generated: int = 0
    tests_run: int
    tests_completed: int
    findings: int
    target_url: str | None = None


class ScanList(BaseModel):
    total: int
    items: list[ScanOut]

