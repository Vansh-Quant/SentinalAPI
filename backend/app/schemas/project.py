"""Project request/response schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: str | None = Field(None, max_length=2000)
    # Target base URL of the API under test. Only sandboxed/allowlisted targets
    # are ever scanned (Phase 2 enforces this); this field records the intent.
    base_url: str = Field(
        default="",
        max_length=500,
        description="Base URL of the (sandboxed) API under test, e.g. http://localhost:9000",
    )


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    base_url: str
    owner_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class ProjectList(BaseModel):
    total: int
    items: list[ProjectOut]
