"""Dashboard, Security Scoring, Attack Surface, Timeline, and Report service."""

import math
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.endpoint import Endpoint
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.scan_event import ScanEvent
from app.schemas.dashboard import (
    DashboardOut,
    EndpointAttackSurfaceList,
    EndpointAttackSurfaceOut,
    ReportOut,
    ScanEventOut,
    SeverityBreakdown,
)
from app.schemas.finding import EndpointBrief, EvidenceOut, FindingOut
from app.services.security_sanitizer import sanitize_dict, sanitize_text


def calculate_security_score(severity_counts: dict[str, int]) -> int:
    """Calculate a deterministic security score from 0 to 100 based on findings severity.

    Formula:
      Base Score = 100
      Deductions:
        - Critical: -25 points per finding
        - High:     -15 points per finding
        - Medium:   -5 points per finding
        - Low:      -2 points per finding
      Score = max(0, min(100, 100 - (25*crit + 15*high + 5*med + 2*low)))
    """
    crit = severity_counts.get("CRITICAL", 0) + severity_counts.get("critical", 0)
    high = severity_counts.get("HIGH", 0) + severity_counts.get("high", 0)
    med = severity_counts.get("MEDIUM", 0) + severity_counts.get("medium", 0)
    low = severity_counts.get("LOW", 0) + severity_counts.get("low", 0)

    deduction = (crit * 25) + (high * 15) + (med * 5) + (low * 2)
    return max(0, min(100, 100 - deduction))


def calculate_scan_duration(scan: Scan) -> float | None:
    """Calculate total duration of scan in seconds."""
    if not scan.started_at:
        return None
    end = scan.completed_at or datetime.now(timezone.utc)
    # Ensure timezone aware subtraction
    start_dt = scan.started_at
    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)

    duration = (end - start_dt).total_seconds()
    return round(max(0.0, duration), 2)


def get_dashboard_summary(db: Session, scan: Scan) -> DashboardOut:
    """Fetch dashboard metrics, severity breakdown, and security score."""
    findings = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev_upper = f.severity.upper() if f.severity else "LOW"
        sev_counts[sev_upper] = sev_counts.get(sev_upper, 0) + 1

    breakdown = SeverityBreakdown(
        critical=sev_counts["CRITICAL"],
        high=sev_counts["HIGH"],
        medium=sev_counts["MEDIUM"],
        low=sev_counts["LOW"],
    )

    score = calculate_security_score(sev_counts)
    duration = calculate_scan_duration(scan)

    return DashboardOut(
        scan_id=scan.id,
        security_score=score,
        endpoints=scan.endpoints_discovered,
        tests_run=scan.tests_run,
        tests_completed=scan.tests_completed,
        findings=len(findings),
        severity=breakdown,
        scan_status=scan.status,
        scan_duration=duration,
    )


def format_finding_out(finding: Finding, endpoint: Endpoint | None = None) -> FindingOut:
    """Format a Finding database instance into a sanitized FindingOut schema."""
    ep_brief = None
    if endpoint:
        ep_brief = EndpointBrief(method=endpoint.method, path=endpoint.path)
    elif finding.endpoint:
        ep_brief = EndpointBrief(method=finding.endpoint.method, path=finding.endpoint.path)

    # Format evidence if present
    evidence_out = None
    if finding.evidence and len(finding.evidence) > 0:
        ev = finding.evidence[0]
        evidence_out = EvidenceOut(
            original_request=sanitize_text(ev.original_request or ev.request),
            modified_request=sanitize_text(ev.modified_request),
            original_response=sanitize_text(ev.original_response or ev.response),
            modified_response=sanitize_text(ev.modified_response),
            poc_request=sanitize_text(ev.poc_request or finding.poc_request),
            relevant_headers=sanitize_dict(ev.relevant_headers),
            relevant_response_fields=sanitize_dict(ev.relevant_response_fields),
        )

    return FindingOut(
        id=finding.id,
        scan_id=finding.scan_id,
        endpoint_id=finding.endpoint_id,
        type=finding.type or "BOLA",
        title=finding.title,
        severity=finding.severity.upper() if finding.severity else "HIGH",
        confidence=finding.confidence if finding.confidence is not None else 0.95,
        endpoint=ep_brief,
        description=finding.description,
        impact=finding.impact,
        remediation=finding.remediation,
        evidence=evidence_out,
        poc_request=sanitize_text(finding.poc_request),
        status=finding.status or "open",
        created_at=finding.created_at,
    )


def get_attack_surface(
    db: Session, scan: Scan, page: int = 1, limit: int = 20
) -> EndpointAttackSurfaceList:
    """Fetch endpoint attack surface graph metrics with pagination."""
    page = max(1, page)
    limit = max(1, min(100, limit))
    offset = (page - 1) * limit

    total = db.execute(
        select(func.count()).select_from(Endpoint).where(Endpoint.scan_id == scan.id)
    ).scalar_one()

    endpoints = db.execute(
        select(Endpoint)
        .where(Endpoint.scan_id == scan.id)
        .order_by(Endpoint.path, Endpoint.method)
        .offset(offset)
        .limit(limit)
    ).scalars().all()

    items: list[EndpointAttackSurfaceOut] = []
    for ep in endpoints:
        # Related findings count and highest severity
        findings = db.execute(
            select(Finding).where(Finding.endpoint_id == ep.id)
        ).scalars().all()

        has_auth = bool(ep.security and len(ep.security) > 0)
        risk = "SAFE"
        if findings:
            severities = [f.severity.upper() for f in findings]
            if "CRITICAL" in severities:
                risk = "CRITICAL"
            elif "HIGH" in severities:
                risk = "HIGH"
            elif "MEDIUM" in severities:
                risk = "MEDIUM"
            else:
                risk = "LOW"
        elif not has_auth:
            risk = "MEDIUM"

        items.append(
            EndpointAttackSurfaceOut(
                id=ep.id,
                method=ep.method,
                path=ep.path,
                operation_id=ep.operation_id,
                summary=ep.summary,
                authentication_required=has_auth,
                risk_level=risk,
                related_findings=len(findings),
                tests_performed=3,  # Standard tests executed per endpoint
            )
        )

    return EndpointAttackSurfaceList(
        total=total,
        page=page,
        limit=limit,
        items=items,
    )


def generate_scan_report(db: Session, scan: Scan) -> ReportOut:
    """Generate executive report for a completed or in-progress scan."""
    dashboard = get_dashboard_summary(db, scan)
    findings_raw = db.execute(
        select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.severity)
    ).scalars().all()

    findings_out = [format_finding_out(f) for f in findings_raw]

    recommendations = []
    if dashboard.severity.critical > 0 or dashboard.severity.high > 0:
        recommendations.append(
            "Enforce strict server-side Authorization checks (BOLA / IDOR protection) on all object identifier parameters."
        )
    if any(f.type == "EXCESSIVE_DATA_EXPOSURE" for f in findings_raw):
        recommendations.append(
            "Filter API response DTOs to return only necessary properties to minimize sensitive data exposure (BOPLA)."
        )
    if any(f.type == "RATE_LIMITING" for f in findings_raw):
        recommendations.append(
            "Implement rate-limiting headers and throttle controls to protect API endpoints against automated abuse."
        )
    if not recommendations:
        recommendations.append("Maintain current zero-trust security posture and regularly re-scan API specifications.")

    exec_summary = (
        f"Zero-Trust Security Scan performed on spec '{scan.title or 'OpenAPI Spec'}'. "
        f"Discovered {scan.endpoints_discovered} API endpoints, executed {scan.tests_completed} security tests, "
        f"and identified {len(findings_raw)} vulnerabilities. Overall Security Score: {dashboard.security_score}/100."
    )

    severity_dict = {
        "critical": dashboard.severity.critical,
        "high": dashboard.severity.high,
        "medium": dashboard.severity.medium,
        "low": dashboard.severity.low,
    }

    metadata = {
        "openapi_version": scan.openapi_version,
        "spec_format": scan.spec_format,
        "target_url": scan.target_url,
        "endpoints_discovered": scan.endpoints_discovered,
        "tests_completed": scan.tests_completed,
    }

    return ReportOut(
        scan_id=scan.id,
        title=scan.title or "API Vulnerability Report",
        openapi_version=scan.openapi_version,
        scan_status=scan.status,
        created_at=scan.created_at,
        scan_duration=dashboard.scan_duration,
        executive_summary=exec_summary,
        security_score=dashboard.security_score,
        vulnerability_summary=dashboard.severity,
        findings=findings_out,
        severity_counts=severity_dict,
        recommendations=recommendations,
        scan_metadata=metadata,
    )
