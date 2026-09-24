"""Finding and evidence response/request schemas."""

import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class EndpointBrief(BaseModel):
    method: str
    path: str


class EvidenceOut(BaseModel):
    original_request: str | None = None
    modified_request: str | None = None
    original_response: str | None = None
    modified_response: str | None = None
    poc_request: str | None = None
    relevant_headers: dict | None = None
    relevant_response_fields: dict | None = None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    endpoint_id: uuid.UUID | None = None
    type: str
    title: str
    severity: str
    confidence: float
    endpoint: EndpointBrief | None = None
    description: str | None = None
    impact: str | None = None
    remediation: str | None = None
    evidence: EvidenceOut | None = None
    poc_request: str | None = None
    status: str
    created_at: datetime


class FindingUpdate(BaseModel):
    status: str = Field(..., description="Updated finding status e.g. open, resolved, false_positive, in_review")


class FindingList(BaseModel):
    total: int
    page: int
    limit: int
    items: list[FindingOut]
