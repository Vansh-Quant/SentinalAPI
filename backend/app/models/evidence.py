"""Evidence model — raw proof (HTTP exchange, payload, log) backing a finding."""

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, GUID
from app.models.user import uuid_pk


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    kind: Mapped[str] = mapped_column(String(50), nullable=False, default="http_exchange")
    request: Mapped[str | None] = mapped_column(Text, nullable=True)
    response: Mapped[str | None] = mapped_column(Text, nullable=True)
    original_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    modified_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    original_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    modified_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    poc_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    relevant_headers: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    relevant_response_fields: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    finding: Mapped["Finding"] = relationship(back_populates="evidence")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Evidence {self.kind} for {self.finding_id}>"
