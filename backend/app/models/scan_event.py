"""ScanEvent model — chronological audit log of events during scan execution."""

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, GUID
from app.models.user import uuid_pk


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    scan: Mapped["Scan"] = relationship(back_populates="events")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ScanEvent {self.event_type} - {self.message}>"
