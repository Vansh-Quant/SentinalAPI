"""HTTP API routers, aggregated under /api.

Each sub-router carries its own prefix (e.g. /auth, /projects, /scans, /findings), so
they are included here without an extra prefix.
"""

from fastapi import APIRouter

from app.api import auth, findings, health, projects, scans

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(projects.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
