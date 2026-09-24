"""Shared FastAPI dependencies: DB session and authenticated user."""

import uuid
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_access_token
from app.models.user import User

# Do not let FastAPI's HTTPBearer convert missing credentials into a 403.
# API authentication failures should consistently use HTTP 401.
bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Resolve the User from a Bearer JWT; 401 on missing/invalid/unknown user."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    sub = payload.get("sub")
    try:
        user_id = uuid.UUID(str(sub))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token subject")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
DbSession = Annotated[Session, Depends(get_db)]
