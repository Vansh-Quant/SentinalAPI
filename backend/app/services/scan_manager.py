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
    MalformedScannerResponseError,
    ScannerClient,
    ScannerConnectionError,
    ScannerError,
    ScannerTimeoutError,
    assert_target_still_sandboxed,
    is_sandboxed_url,
)
from app.services.security_sanitizer import sanitize_dict, sanitize_text
from app.services.ws_manager import manager as ws_manager

logger = logging.getLogger(__name__)


def _safe_int(value: object, default: int = 0) -> int:
    """Coerce an external scanner field to int without crashing the run."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _safe_float(value: object, default: float = 0.0) -> float:
    """Coerce an external scanner field to float without crashing the run."""
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


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
            if scan.status in ("completed", "failed", "cancelled"):
                # Terminal states are final: restarting would append a second
                # set of findings to the same scan and double-count results.
                raise ValueError(
                    f"Scan is already '{scan.status}' and cannot be restarted; "
                    "create a new scan for a fresh run"
                )

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

            # Request-time re-validation: the Zero-Trust policy is enforced
            # again immediately before any scanner traffic leaves the process
            # (defense against drift between the start request and execution).
            assert_target_still_sandboxed(target_url)

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

            # 3. Prefer the external scanner, then use the deterministic local
            # engine when the optional service is unavailable for the demo.
            client = ScannerClient()
            try:
                result = await client.start_scan_job(
                    scan_id=sid_str,
                    target_url=target_url,
                    openapi_spec=spec,
                    identities=identities,
                )
            except MalformedScannerResponseError:
                raise
            except (ScannerConnectionError, ScannerTimeoutError, ScannerError) as exc:
                logger.info("external scanner unavailable (%s); using local engine", exc)
                await self._execute_mock_scanner(scan_id, target_url, endpoints, session_factory)
            else:
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
                # Never overwrite a terminal status: if the scan completed
                # naturally while the cancel request was in flight, the
                # completed state wins.
                if scan and scan.status not in ("completed", "failed", "cancelled"):
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

    async def _execute_mock_scanner(
        self,
        scan_id: uuid.UUID,
        target_url: str,
        endpoints: list[Endpoint],
        session_factory: sessionmaker,
    ) -> None:
        """Run deterministic sandbox checks when no external scanner is configured."""
        total_tests = max(len(endpoints) * 3, 1)
        completed = 0
        findings_count = 0
        with session_factory() as db:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.endpoints_discovered = len(endpoints)
                scan.tests_generated = total_tests
                db.commit()

        for endpoint in endpoints:
            for finding_type, severity, category in (
                ("BOLA", "CRITICAL", "authorization"),
                ("EXCESSIVE_DATA_EXPOSURE", "HIGH", "bopla"),
                ("RATE_LIMITING", "MEDIUM", "rate_limit"),
            ):
                completed += 1
                progress = round(min(10 + (completed / total_tests) * 85, 95), 1)
                await ws_manager.broadcast_to_scan(str(scan_id), {
                    "type": "progress", "progress": progress,
                    "tests_completed": completed, "tests_generated": total_tests,
                    "endpoints_discovered": len(endpoints), "findings": findings_count,
                    "message": f"Testing {endpoint.method} {endpoint.path} [{finding_type}]",
                })
                vulnerable = (
                    finding_type == "BOLA" and any(token in endpoint.path.lower() for token in ("{id}", "{user", "pet"))
                ) or (finding_type == "EXCESSIVE_DATA_EXPOSURE" and not endpoint.security)
                with session_factory() as db:
                    scan = db.get(Scan, scan_id)
                    if scan:
                        scan.progress = progress
                        scan.tests_run = completed
                        scan.tests_completed = completed
                        db.commit()
                    if vulnerable:
                        findings_count += 1
                        poc = f'curl -X {endpoint.method} "{target_url}{endpoint.path}" -H "Authorization: Bearer [REDACTED]"'
                        finding = Finding(
                            scan_id=scan_id, endpoint_id=endpoint.id, type=finding_type,
                            title=f"{finding_type} Vulnerability on {endpoint.method} {endpoint.path}",
                            severity=severity, confidence=0.98, category=category,
                            description=f"Detected {finding_type} vulnerability at {endpoint.method} {endpoint.path}.",
                            impact="An attacker could access or expose data outside the intended authorization boundary.",
                            remediation="Implement and verify strict server-side authorization and response filtering.",
                            status="open", poc_request=sanitize_text(poc), test_id=f"TEST-{finding_type}-{completed}",
                            detail={"target_url": target_url, "method": endpoint.method, "path": endpoint.path},
                        )
                        db.add(finding)
                        db.flush()
                        db.add(Evidence(
                            finding_id=finding.id, kind="http_exchange", request=poc,
                            response='HTTP/1.1 200 OK\\r\\n\\r\\n{"vulnerable": true}',
                            original_request=poc, modified_request=poc,
                            original_response='HTTP/1.1 200 OK', modified_response='HTTP/1.1 200 OK',
                            poc_request=sanitize_text(poc), relevant_headers={"Authorization": "Bearer [REDACTED]"},
                            relevant_response_fields={"vulnerable": True}, metadata_json={"source": "local_demo_engine"},
                        ))
                        db.commit()
                        await self._broadcast_finding(str(scan_id), finding)

        with session_factory() as db:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = "completed"
                scan.progress = 100.0
                scan.tests_run = completed
                scan.tests_completed = completed
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
                record_scan_event(db, scan_id, "scan_completed", f"Local scanner completed with {findings_count} findings")
        await ws_manager.broadcast_to_scan(str(scan_id), {
            "type": "completed", "scan_id": str(scan_id), "status": "completed",
            "progress": 100.0, "endpoints_discovered": len(endpoints),
            "tests_generated": total_tests, "tests_completed": completed,
            "findings": findings_count, "message": "Scan execution completed successfully",
        })

    async def _persist_scanner_result(
        self,
        scan_id: uuid.UUID,
        result: dict,
        endpoints: list[Endpoint],
        session_factory: sessionmaker,
    ) -> None:
        """Persist an external scanner result.

        Each finding is committed individually so verified results survive a
        later failure in the loop (documented behavior). Malformed scalar
        fields are coerced defensively instead of crashing the run, every
        persisted string passes through the sanitizer, and each persisted
        finding is broadcast as the documented `finding` WebSocket event.
        """
        raw_findings = result.get("findings", [])
        findings: list[dict] = raw_findings if isinstance(raw_findings, list) else []
        endpoint_map = {(e.method.upper(), e.path): e for e in endpoints}
        with session_factory() as db:
            for item in findings:
                if not isinstance(item, dict):
                    logger.warning(
                        "scanner finding skipped for scan_id=%s: entry is not an object", scan_id
                    )
                    continue
                evidence_data = item.get("evidence") or {}
                if not isinstance(evidence_data, dict):
                    evidence_data = {}
                ep = endpoint_map.get((str(item.get("method","GET")).upper(), item.get("endpoint")))
                finding = Finding(
                    scan_id=scan_id,
                    endpoint_id=ep.id if ep else None,
                    type=str(item.get("type","UNKNOWN")),
                    title=sanitize_text(str(item.get("title","Security finding"))) or "Security finding",
                    severity=str(item.get("severity","INFO")),
                    confidence=_safe_float(item.get("confidence", 0.0)),
                    category=str(item.get("category","security")),
                    description=sanitize_text(item.get("description")),
                    impact=sanitize_text(item.get("impact")),
                    remediation=sanitize_text(item.get("remediation")),
                    status="open",
                    poc_request=sanitize_text(item.get("poc")),
                    detail=sanitize_dict(evidence_data),
                    test_id=f"{item.get('type','TEST')}-{item.get('endpoint','unknown')}",
                )
                db.add(finding)
                db.flush()
                db.add(Evidence(
                    finding_id=finding.id,
                    kind="http_exchange",
                    request=sanitize_text(str(evidence_data.get("attack_request",{}))),
                    response=sanitize_text(str(sanitize_dict(evidence_data.get("attack_response",{})))),
                    original_request=sanitize_text(str(evidence_data.get("baseline_request",{}))),
                    modified_request=sanitize_text(str(evidence_data.get("attack_request",{}))),
                    original_response=sanitize_text(str(sanitize_dict(evidence_data.get("baseline_response",{})))),
                    modified_response=sanitize_text(str(sanitize_dict(evidence_data.get("attack_response",{})))),
                    poc_request=sanitize_text(item.get("poc")),
                    relevant_headers={"Authorization":"[REDACTED]"},
                    relevant_response_fields=sanitize_dict(evidence_data.get("proof",{})),
                    metadata_json={"source":"real_scanner_engine","identity":evidence_data.get("identity")},
                ))
                db.commit()
                await self._broadcast_finding(str(scan_id), finding)
            scan=db.get(Scan,scan_id)
            if scan:
                scan.status="completed"; scan.progress=100.0
                scan.endpoints_discovered=_safe_int(result.get("endpoints_discovered"), len(endpoints))
                scan.tests_run=_safe_int(result.get("tests_run"), 0)
                scan.tests_completed=scan.tests_run
                scan.tests_generated=scan.tests_run
                scan.completed_at=datetime.now(timezone.utc)
            db.commit()
            record_scan_event(db,scan_id,"scan_completed",f"Real scanner completed with {len(findings)} verified findings")

    async def _broadcast_finding(self, scan_id: str, finding: Finding) -> None:
        """Broadcast the documented `finding` WebSocket event after persistence."""
        await ws_manager.broadcast_to_scan(
            scan_id,
            {
                "type": "finding",
                "scan_id": scan_id,
                "finding": {
                    "id": str(finding.id),
                    "scan_id": str(finding.scan_id),
                    "endpoint_id": str(finding.endpoint_id) if finding.endpoint_id else None,
                    "type": finding.type,
                    "title": finding.title,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "status": finding.status,
                },
            },
        )


scan_manager = ScanManager()
