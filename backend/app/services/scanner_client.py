"""Scanner Client — Handles HTTP communication between Backend and Scanner Engine.

Includes Zero-Trust sandbox validation, error handling, timeouts, retries,
and fallback mock scanner execution for standalone/offline operation.
"""

import asyncio
import logging
from urllib.parse import urlparse

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# Allowed sandbox hosts/prefixes for Zero-Trust validation
DEFAULT_ALLOWED_SANDBOX_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "sandbox",
    "test-api",
    "mock-api",
    "api-sandbox",
}


class ScannerError(Exception):
    """Base exception for scanner communication errors."""

    pass


class ScannerTimeoutError(ScannerError):
    """Raised when scanner engine times out."""

    pass


class ScannerConnectionError(ScannerError):
    """Raised when scanner engine is unreachable."""

    pass


class MalformedScannerResponseError(ScannerError):
    """Raised when scanner returns invalid JSON or structure."""

    pass


def is_sandboxed_url(url: str) -> tuple[bool, str]:
    """Validate that the target URL belongs to an explicitly allowed sandbox environment.

    Zero-Trust enforcement: arbitrary public internet targets are strictly prohibited.
    """
    if not url:
        return False, "Target URL is required"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid target URL format"

    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported URL scheme '{parsed.scheme}'; only http and https are permitted"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "Target URL must contain a valid hostname"

    # Check configured sandbox base URL hostname
    sandbox_parsed = urlparse(settings.sandbox_base_url)
    allowed_hosts = set(DEFAULT_ALLOWED_SANDBOX_HOSTS)
    if sandbox_parsed.hostname:
        allowed_hosts.add(sandbox_parsed.hostname.lower())

    # Allow localhost, 127.0.0.1, internal test subnets, or explicitly configured sandbox hosts
    if (
        hostname in allowed_hosts
        or hostname.endswith(".local")
        or hostname.endswith(".sandbox")
        or hostname.startswith("127.")
        or hostname.startswith("10.")
        or hostname.startswith("192.168.")
        or hostname.startswith("172.16.")
    ):
        return True, ""

    return (
        False,
        f"Target URL '{url}' is outside permitted sandbox environment. "
        "Zero-Trust Policy allows scanning only explicitly configured sandbox target APIs.",
    )


class ScannerClient:
    """Client for Scanner Engine REST API."""

    def __init__(self, base_url: str | None = None, timeout_seconds: float = 1.0, max_retries: int = 1):
        self.base_url = (base_url or settings.scanner_base_url).rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    async def start_scan_job(
        self,
        scan_id: str,
        target_url: str,
        openapi_spec: dict,
        identities: dict[str, str] | None = None,
    ) -> dict:
        """Send scan start request to scanner engine."""
        endpoint = f"{self.base_url}/scan/start"
        payload = {
            "scan_id": scan_id,
            "target_url": target_url,
            "openapi_spec": openapi_spec,
            "identities": identities or {},
        }

        # Structured log (omitting secrets)
        logger.info(
            "scanner request -> POST %s for scan_id=%s target_url=%s",
            endpoint,
            scan_id,
            target_url,
        )

        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    resp = await client.post(endpoint, json=payload)
                    resp.raise_for_status()

                    try:
                        data = resp.json()
                    except ValueError as e:
                        logger.error("scanner returned malformed JSON for scan_id=%s: %s", scan_id, e)
                        raise MalformedScannerResponseError("Scanner returned non-JSON response") from e

                    if not isinstance(data, dict):
                        raise MalformedScannerResponseError("Scanner payload must be a JSON object")

                    logger.info("scanner response <- 200 OK for scan_id=%s payload=%s", scan_id, data)
                    return data

            except httpx.TimeoutException as exc:
                last_error = ScannerTimeoutError(f"Scanner engine timed out after {self.timeout_seconds}s")
                logger.warning("scanner timeout attempt %d/%d for scan_id=%s", attempt, self.max_retries, scan_id)

            except httpx.ConnectError as exc:
                last_error = ScannerConnectionError(f"Cannot connect to scanner engine at {self.base_url}")
                logger.warning("scanner connect failed attempt %d/%d for scan_id=%s", attempt, self.max_retries, scan_id)

            except httpx.HTTPStatusError as exc:
                logger.error("scanner HTTP error %d for scan_id=%s: %s", exc.response.status_code, scan_id, exc.response.text)
                raise ScannerError(f"Scanner returned status {exc.response.status_code}") from exc

            except (ScannerError, MalformedScannerResponseError):
                raise

            except Exception as exc:
                last_error = ScannerError(f"Unexpected scanner communication error: {exc}")
                logger.error("scanner communication error attempt %d/%d: %s", attempt, self.max_retries, exc)

            if attempt < self.max_retries:
                await asyncio.sleep(0.5 * attempt)

        if last_error:
            raise last_error
        raise ScannerConnectionError("Scanner engine unreachable")

    async def cancel_scan_job(self, scan_id: str) -> bool:
        """Send cancel request to scanner engine."""
        endpoint = f"{self.base_url}/scan/{scan_id}/cancel"
        logger.info("scanner request -> POST %s for scan_id=%s", endpoint, scan_id)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(endpoint)
                return resp.status_code in (200, 202, 204)
        except Exception as exc:
            logger.warning("failed to send cancel request to scanner engine for scan_id=%s: %s", scan_id, exc)
            return False
