"""Scan Manager — Orchestrates async scan jobs, scanner execution, event logging, and result persistence.

Manages scan lifecycle: QUEUED -> RUNNING -> COMPLETED | FAILED | CANCELLED.
Streams progress and findings to WebSocket listeners.
Enforces Zero-Trust sandbox isolation.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict

from fastapi import BackgroundTasks
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.endpoint import Endpoint
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.scan_event import ScanEvent
from app.services.scanner_client import (
    ScannerClient,
    ScannerConnectionError,
    ScannerError,
    ScannerTimeoutError,
    is_sandboxed_url,
)
from app.services.security_sanitizer import sanitize_text
from app.services.ws_manager import manager as ws_manager

logger = logging.getLogger(__name__)


def record_scan_event(
    db: Session,
    scan_id: uuid.UUID,
    event_type: str,
    message: str,
    details: dict | None = None,
) -> ScanEvent:
    """Record a chronological event in the scan timeline."""
    event = ScanEvent(
        scan_id=scan_id,
        event_type=event_type,
        message=message,
        details=details,
    )
    db.add(event)
    db.commit()
    return event


class ScanManager:
    """Manages active scan background tasks and orchestrates scanner execution."""

    def __init__(self) -> None:
        self._running_tasks: Dict[str, asyncio.Task] = {}

    def is_running(self, scan_id: str) -> bool:
        task = self._running_tasks.get(scan_id)
        return task is not None and not task.done()

    async def start_scan(
        self,
        scan_id: uuid.UUID,
        target_url: str | None = None,
        identities: dict[str, str] | None = None,
        session_factory: sessionmaker = SessionLocal,
        background_tasks: BackgroundTasks | None = None,
    ) -> Scan:
        """Initialize scan background job."""
        sid_str = str(scan_id)

        with session_factory() as db:
            scan = db.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            if scan.status == "running" or self.is_running(sid_str):
                raise ValueError("Scan is already running")

            # Determine target sandbox URL
            resolved_target = target_url
            if not resolved_target and scan.spec:
                servers = scan.spec.get("servers", [])
                if servers and isinstance(servers, list) and len(servers) > 0:
                    spec_server = servers[0].get("url")
                    if spec_server and isinstance(spec_server, str):
                        resolved_target = spec_server

            if not resolved_target:
                resolved_target = settings.sandbox_base_url

            # Enforce Zero-Trust sandbox validation
            valid, reason = is_sandboxed_url(resolved_target)
            if not valid:
                scan.status = "failed"
                scan.error = reason
                db.commit()
                record_scan_event(db, scan_id, "scan_failed", f"Scan start rejected: {reason}")
                logger.error("Scan %s start rejected: %s", scan_id, reason)
                raise ValueError(reason)

            # Update state to QUEUED
            scan.status = "queued"
            scan.progress = 0.0
            scan.error = None
            scan.target_url = resolved_target
            scan.started_at = datetime.now(timezone.utc)
            db.commit()

            record_scan_event(
                db, scan_id, "scan_started", f"Scan queued for target {resolved_target}"
            )

            # Structured log
            logger.info("scan created/queued scan_id=%s target_url=%s", sid_str, resolved_target)

            if background_tasks:
                background_tasks.add_task(
                    self._run_scan_job,
                    scan_id,
                    resolved_target,
                    identities or {},
                    session_factory,
                )
            else:
                task = asyncio.create_task(
                    self._run_scan_job(
                        scan_id=scan_id,
                        target_url=resolved_target,
                        identities=identities or {},
                        session_factory=session_factory,
                    )
                )
                self._running_tasks[sid_str] = task
            return scan

    async def cancel_scan(
        self, scan_id: uuid.UUID, session_factory: sessionmaker = SessionLocal
    ) -> bool:
        """Cancel a running or queued scan job."""
        sid_str = str(scan_id)

        with session_factory() as db:
            scan = db.get(Scan, scan_id)
            if not scan:
                return False

            if scan.status in ("completed", "failed", "cancelled"):
                return False

            scan.status = "cancelled"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            record_scan_event(db, scan_id, "scan_cancelled", "Scan execution cancelled by user")

        # Cancel active task if present
        task = self._running_tasks.pop(sid_str, None)
        if task and not task.done():
            task.cancel()

        # Notify scanner client cancel if needed
        client = ScannerClient()
        asyncio.create_task(client.cancel_scan_job(sid_str))

        logger.info("scan cancelled scan_id=%s", sid_str)

        await ws_manager.broadcast_to_scan(
            sid_str,
            {
                "type": "status",
                "status": "cancelled",
                "message": "Scan execution cancelled by user",
            },
        )
        return True

    async def _run_scan_job(
        self,
        scan_id: uuid.UUID,
        target_url: str,
        identities: dict[str, str],
        session_factory: sessionmaker,
    ) -> None:
        sid_str = str(scan_id)
        logger.info("scan started scan_id=%s", sid_str)

        try:
            # 1. Update DB to RUNNING
            with session_factory() as db:
                scan = db.get(Scan, scan_id)
                if not scan:
                    return
                scan.status = "running"
                db.commit()
                record_scan_event(db, scan_id, "scan_running", "Scan engine initialized")

            await ws_manager.broadcast_to_scan(
                sid_str,
                {
                    "type": "status",
                    "status": "running",
                    "progress": 5.0,
                    "message": "Initializing scan engine",
                },
            )

            # 2. Load spec and endpoints from DB
            with session_factory() as db:
                scan = db.get(Scan, scan_id)
                if not scan:
                    return
                spec = scan.spec
                endpoints = db.execute(
                    select(Endpoint).where(Endpoint.scan_id == scan_id)
                ).scalars().all()

                record_scan_event(
                    db,
                    scan_id,
                    "openapi_parsed",
                    f"OpenAPI specification parsed successfully ({len(endpoints)} endpoints)",
                )

            # 3. Execute the real scanner engine. Scanner failures must fail the scan;
            # never synthesize findings.
            client = ScannerClient()
            result = await client.start_scan_job(
                scan_id=sid_str,
                target_url=target_url,
                openapi_spec=spec,
                identities=identities,
            )
            await self._persist_scanner_result(
                scan_id=scan_id,
                result=result,
                endpoints=endpoints,
                session_factory=session_factory,
            )

        except asyncio.CancelledError:
            logger.info("scan task cancelled during execution scan_id=%s", sid_str)
            with session_factory() as db:
                scan = db.get(Scan, scan_id)
                if scan:
                    scan.status = "cancelled"
                    db.commit()
            raise

        except Exception as exc:
            logger.exception("scan failed scan_id=%s: %s", sid_str, exc)
            with session_factory() as db:
                scan = db.get(Scan, scan_id)
                if scan:
                    scan.status = "failed"
                    scan.error = str(exc)
                    db.commit()
                    record_scan_event(db, scan_id, "scan_failed", f"Scan execution error: {exc}")

            await ws_manager.broadcast_to_scan(
                sid_str,
                {
                    "type": "error",
                    "status": "failed",
                    "message": f"Scan failed: {exc}",
                },
            )

        finally:
            self._running_tasks.pop(sid_str, None)

    async def _persist_scanner_result(
        self,
        scan_id: uuid.UUID,
        result: dict,
        endpoints: list[Endpoint],
        session_factory: sessionmaker,
    ) -> None:
        findings = result.get("findings", [])
        endpoint_map = {(e.method.upper(), e.path): e for e in endpoints}
        with session_factory() as db:
            for item in findings:
                ep = endpoint_map.get((str(item.get("method","GET")).upper(), item.get("endpoint")))
                finding = Finding(
                    scan_id=scan_id,
                    endpoint_id=ep.id if ep else None,
                    type=item.get("type","UNKNOWN"),
                    title=item.get("title","Security finding"),
                    severity=item.get("severity","INFO"),
                    confidence=float(item.get("confidence",0.0)),
                    category=item.get("category","security"),
                    description=item.get("description"),
                    impact=item.get("impact"),
                    remediation=item.get("remediation"),
                    status="open",
                    poc_request=item.get("poc"),
                    detail=item.get("evidence",{}),
                    test_id=f"{item.get('type','TEST')}-{item.get('endpoint','unknown')}",
                )
                db.add(finding)
                db.flush()
                evidence_data=item.get("evidence") or {}
                Evidence(
                    finding_id=finding.id,
                    kind="http_exchange",
                    request=str(evidence_data.get("attack_request",{})),
                    response=str(evidence_data.get("attack_response",{})),
                    original_request=str(evidence_data.get("baseline_request",{})),
                    modified_request=str(evidence_data.get("attack_request",{})),
                    original_response=str(evidence_data.get("baseline_response",{})),
                    modified_response=str(evidence_data.get("attack_response",{})),
                    poc_request=item.get("poc"),
                    relevant_headers={"Authorization":"[REDACTED]"},
                    relevant_response_fields=evidence_data.get("proof",{}),
                    metadata_json={"source":"real_scanner_engine","identity":evidence_data.get("identity")},
                )
                db.add(db.new_instance(Evidence) if False else Evidence(
                    finding_id=finding.id,
                    kind="http_exchange",
                    request=str(evidence_data.get("attack_request",{})),
                    response=str(evidence_data.get("attack_response",{})),
                    original_request=str(evidence_data.get("baseline_request",{})),
                    modified_request=str(evidence_data.get("attack_request",{})),
                    original_response=str(evidence_data.get("baseline_response",{})),
                    modified_response=str(evidence_data.get("attack_response",{})),
                    poc_request=item.get("poc"),
                    relevant_headers={"Authorization":"[REDACTED]"},
                    relevant_response_fields=evidence_data.get("proof",{}),
                    metadata_json={"source":"real_scanner_engine","identity":evidence_data.get("identity")},
                ))
            scan=db.get(Scan,scan_id)
            if scan:
                scan.status="completed"; scan.progress=100.0
                scan.endpoints_discovered=int(result.get("endpoints_discovered",len(endpoints)))
                scan.tests_run=int(result.get("tests_run",0))
                scan.tests_completed=scan.tests_run
                scan.tests_generated=scan.tests_run
                scan.completed_at=datetime.now(timezone.utc)
            db.commit()
            record_scan_event(db,scan_id,"scan_completed",f"Real scanner completed with {len(findings)} verified findings")


scan_manager = ScanManager()
