"""Shared FastAPI dependencies: DB session and authenticated user."""

import uuid
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, WebSocket, WebSocketException, status
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


def get_current_user_ws(websocket: WebSocket, db: Session) -> User:
    """Resolve the User for a WebSocket connection.

    Browsers cannot set an Authorization header on new WebSocket(...), so the
    token arrives as the requested sub-protocol (sec-websocket-protocol):
        new WebSocket(url, ["bearer", token])
    A query parameter (?token=...) is accepted for non-browser clients.
    Rejects with 1008 (policy violation) before the socket is accepted when
    authentication fails.
    """
    token: str | None = None
    protocols = websocket.headers.get("sec-websocket-protocol", "")
    parts = [p.strip() for p in protocols.split(",") if p.strip()]
    if len(parts) >= 2 and parts[0].lower() == "bearer":
        token = parts[1]
    if not token:
        token = websocket.query_params.get("token")
    if not token:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)

    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)

    if payload.get("type") != "access":
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)

    try:
        user_id = uuid.UUID(str(payload.get("sub")))
    except (TypeError, ValueError):
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    return user


def require_scan_access_ws(websocket: WebSocket, scan_id: str) -> None:
    """Authenticate a scan WebSocket and enforce scan ownership.

    Must be called BEFORE ws_manager.connect()/accept. Closes with 1008 on
    missing/invalid credentials and 4404 when the scan does not exist or is
    not owned by the caller (no existence leak).
    """
    from app.core.database import SessionLocal
    from app.models.project import Project
    from app.models.scan import Scan

    db = SessionLocal()
    try:
        user = get_current_user_ws(websocket, db)
        try:
            sid = uuid.UUID(str(scan_id))
        except ValueError:
            raise WebSocketException(code=4404)
        scan = db.get(Scan, sid)
        project = db.get(Project, scan.project_id) if scan else None
        if project is None or project.owner_id != user.id:
            raise WebSocketException(code=4404)
    finally:
        db.close()
