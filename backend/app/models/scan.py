"""Scan model — one analysis run of an uploaded OpenAPI spec against a project."""

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, GUID
from app.models.user import uuid_pk


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # queued -> running -> completed | failed
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False, index=True)
    progress: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # JSONB on PostgreSQL, portable JSON elsewhere (SQLite)
    spec: Mapped[dict] = mapped_column(JSONB().with_variant(JSON(), "sqlite"), nullable=False)
    spec_path: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    spec_format: Mapped[str] = mapped_column(String(10), default="json", nullable=False)
    openapi_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Counters for the status endpoint
    endpoints_discovered: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tests_generated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tests_run: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tests_completed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    target_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    project: Mapped["Project"] = relationship(back_populates="scans")
    endpoints: Mapped[list["Endpoint"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Scan {self.id} status={self.status}>"
