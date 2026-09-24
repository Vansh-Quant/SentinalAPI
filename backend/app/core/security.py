"""Security primitives: password hashing, JWT creation/verification, token auth.

- Passwords are hashed with bcrypt; plaintext is never stored or logged.
- Sessions are stateless JWT bearer tokens (HS256, signed with SECRET_KEY).
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from app.core.config import settings

logger = logging.getLogger(__name__)

_BCRYPT_ROUNDS = 12


# --- Passwords -------------------------------------------------------------

def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt (salt embedded in the hash)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time verification of a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


# --- JWT sessions ----------------------------------------------------------

_ALGORITHM = "HS256"


def create_access_token(subject: str, extra_claims: dict[str, Any] | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.secret_key, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a token; raises jwt.PyJWTError on any problem."""
    return jwt.decode(token, settings.secret_key, algorithms=[_ALGORITHM])
