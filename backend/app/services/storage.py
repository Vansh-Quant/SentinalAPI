"""Upload storage with safe filenames and path-traversal protection.

Files are stored under settings.upload_path with random UUID names (no user
input ever touches the filesystem path). Only ASCII, alphanumerics, dots and
dashes survive in the stored name; everything else is stripped. All paths are
validated to remain inside the upload root.
"""

import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException

from app.core.config import settings

logger = logging.getLogger(__name__)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_NAME_LEN = 80


def sanitize_filename(name: str) -> str:
    """Reduce a client-supplied filename to a safe stem (no traversal, no tricks)."""
    base = Path(name or "").name  # drop any directory components
    base = _SAFE_NAME.sub("_", base).strip("._") or "spec"
    return base[:_MAX_NAME_LEN]


def _resolve_inside_root(root: Path, relative: str) -> Path:
    """Join and verify the result stays within root (defense in depth)."""
    candidate = (root / relative).resolve()
    root_resolved = root.resolve()
    if not candidate.is_relative_to(root_resolved):
        raise HTTPException(status_code=500, detail="Refusing to write outside upload root")
    return candidate


def save_upload(content: bytes, original_filename: str) -> tuple[str, str]:
    """Persist upload bytes; returns (relative_path, sanitized_name).

    Layout: uploads/<yyyy>/<mm>/<uuid>_<sanitized-name>
    """
    root = settings.upload_path
    root.mkdir(parents=True, exist_ok=True)

    safe_name = sanitize_filename(original_filename)
    now = datetime.now(timezone.utc)
    rel = f"{now.year}/{now.month:02d}/{uuid.uuid4().hex[:12]}_{safe_name}"
    dest = _resolve_inside_root(root, rel)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    logger.info("stored upload %s (%d bytes)", rel, len(content))
    return rel, safe_name


def read_upload(relative_path: str) -> bytes:
    root = settings.upload_path
    p = _resolve_inside_root(root, relative_path)
    return p.read_bytes()


def delete_upload(relative_path: str) -> None:
    try:
        p = _resolve_inside_root(settings.upload_path, relative_path)
        p.unlink(missing_ok=True)
    except OSError as exc:  # pragma: no cover
        logger.warning("could not delete upload %s: %s", relative_path, exc)
