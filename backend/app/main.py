"""SentinelAPI backend — FastAPI application entrypoint."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.api import api_router
from app.core.config import settings
from app.core.database import init_db

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    logger.info("SentinelAPI backend started (env=%s)", settings.environment)
    yield
    logger.info("SentinelAPI backend shutting down")


app = FastAPI(
    title="SentinelAPI",
    description=(
        "Zero-Trust API Vulnerability Scanner — backend. "
        "Scans run only against explicitly provided, sandboxed APIs."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Log full details server-side; return a generic 500 to the client."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(api_router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinalapi"}


@app.websocket("/ws/scans/{scan_id}")
async def root_websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """Direct WebSocket endpoint at /ws/scans/{scan_id} for live scan updates."""
    from app.services.ws_manager import manager as ws_manager

    await ws_manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)


# --- Helper endpoints for scanner parsing / analysis ---

class SpecRequest(BaseModel):
    spec: dict


class ResponseAnalysis(BaseModel):
    endpoint: str
    response: dict
    expected_fields: list[str] = []


@app.post("/api/scan/parse")
def parse(req: SpecRequest):
    try:
        from scanner.parser import normalize
        endpoints = normalize(req.spec)
        return {"count": len(endpoints), "endpoints": [e.__dict__ for e in endpoints]}
    except (ImportError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/scan/analyze-response")
def analyze(req: ResponseAnalysis):
    try:
        from scanner.bopla import analyze_response
        finding = analyze_response(req.endpoint, req.response, set(req.expected_fields))
        return {"finding": finding.__dict__ if finding else None}
    except (ImportError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
