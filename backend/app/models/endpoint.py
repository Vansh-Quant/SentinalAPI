"""Endpoint model — a single operation extracted from an OpenAPI spec."""

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, GUID
from app.models.user import uuid_pk


def _json_variant():
    return JSONB().with_variant(JSON(), "sqlite")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    method: Mapped[str] = mapped_column(String(10), nullable=False)  # GET/POST/...
    path: Mapped[str] = mapped_column(String(500), nullable=False)   # /users/{id}
    operation_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list | None] = mapped_column(_json_variant(), nullable=True)
    parameters: Mapped[list | None] = mapped_column(_json_variant(), nullable=True)
    request_body: Mapped[dict | None] = mapped_column(_json_variant(), nullable=True)
    # effective security requirement (operation-level overrides spec-level)
    security: Mapped[list | None] = mapped_column(_json_variant(), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("scan_id", "method", "path", name="uq_endpoint_scan_method_path"),
        Index("ix_endpoints_scan_path", "scan_id", "path"),
    )

    scan: Mapped["Scan"] = relationship(back_populates="endpoints")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Endpoint {self.method} {self.path}>"
