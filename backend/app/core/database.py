"""Database engine, session management and declarative base.

- PostgreSQL in development/production (docker-compose.yml provides one).
- SQLite fallback for unit tests / quick local runs.

FastAPI dependencies use `get_db`, which always yields a session and closes it.
"""

import logging
import uuid
from collections.abc import Generator

from sqlalchemy import CHAR, String, create_engine, event
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator

from app.core.config import settings

logger = logging.getLogger(__name__)


class GUID(TypeDecorator):
    """Portable UUID type: native UUID on PostgreSQL, CHAR(36) elsewhere."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PGUUID(as_uuid=True))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            return value
        return str(value)  # SQLite/other: bind as string

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


class Base(DeclarativeBase):
    pass


def _make_engine_kwargs() -> dict:
    if settings.is_sqlite:
        return {"connect_args": {"check_same_thread": False}}
    return {"pool_pre_ping": True, "pool_size": 5, "max_overflow": 10}


engine = create_engine(settings.database_url, echo=False, **_make_engine_kwargs())

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

if settings.is_sqlite:
    # Enable foreign key enforcement (off by default in SQLite).
    @event.listens_for(engine, "connect")
    def _fk_pragma(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: one session per request, always closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables from ORM metadata.

    Phase 1 uses metadata creation for a simple, reproducible setup; the team can
    move to Alembic migrations once the schema stabilizes.
    """
    import app.models  # noqa: F401  (register all models on Base.metadata)

    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized at %s", settings.database_url)
