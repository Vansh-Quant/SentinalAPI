"""Scanner Client — Handles HTTP communication between Backend and Scanner Engine.

Includes Zero-Trust sandbox validation, error handling, timeouts, retries,
and fallback mock scanner execution for standalone/offline operation.
"""

import asyncio
import ipaddress
import logging
import socket
from urllib.parse import urlparse

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# Allowed sandbox hosts/prefixes for Zero-Trust validation.
# Only the provisioned container/demo names are accepted here; generic names
# (test-api, mock-api, ...) were removed so a stray DNS entry cannot become a
# scan target.
DEFAULT_ALLOWED_SANDBOX_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "sandbox",
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


def _ip_is_sandbox(ip: str) -> bool:
    """True when an IP address belongs to a private/loopback/link-local range."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _hostname_resolves_to_sandbox(hostname: str) -> tuple[bool, str]:
    """Resolve a hostname and require EVERY address to be sandbox-range.

    This closes the textual-allowlist bypass: '10.0.0.1.evil.com' or
    '172.16.attacker.net' match the string prefixes but resolve to public
    addresses, and public addresses are rejected here.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return False, f"Sandbox hostname '{hostname}' could not be resolved"
    if not infos:
        return False, f"Sandbox hostname '{hostname}' resolved to no addresses"
    for info in infos:
        ip = str(info[4][0])
        if not _ip_is_sandbox(ip):
            return False, (
                f"Sandbox hostname '{hostname}' resolves to non-private address {ip}; "
                "public internet targets are prohibited"
            )
    return True, ""


def is_sandboxed_url(url: str) -> tuple[bool, str]:
    """Validate that the target URL belongs to an explicitly allowed sandbox environment.

    Zero-Trust enforcement, in two layers:
      1. The hostname must match the textual allowlist (exact names, internal
         subnets, or the configured SANDBOX_BASE_URL host).
      2. The hostname must actually resolve to private/loopback/link-local IP
         addresses, defeating textual bypasses such as '10.0.0.1.evil.com'.
    Arbitrary public internet targets are strictly prohibited.
    """
    if not url:
        return False, "Target URL is required"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid target URL format"

    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported URL scheme '{parsed.scheme}'; only http and https are permitted"

    if parsed.username or parsed.password:
        return False, "Target URL must not embed credentials (userinfo)"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "Target URL must contain a valid hostname"

    # Layer 1: textual allowlist (configured sandbox host included)
    sandbox_parsed = urlparse(settings.sandbox_base_url)
    allowed_hosts = set(DEFAULT_ALLOWED_SANDBOX_HOSTS)
    if sandbox_parsed.hostname:
        allowed_hosts.add(sandbox_parsed.hostname.lower())

    textual_match = (
        hostname in allowed_hosts
        or hostname.endswith(".local")
        or hostname.endswith(".sandbox")
        or hostname.startswith("127.")
        or hostname.startswith("10.")
        or hostname.startswith("192.168.")
        or hostname.startswith("172.16.")
    )
    if not textual_match:
        return (
            False,
            f"Target URL '{url}' is outside permitted sandbox environment. "
            "Zero-Trust Policy allows scanning only explicitly configured sandbox target APIs.",
        )

    # Layer 2: resolved-IP verification (literal IPs are checked directly,
    # hostnames go through DNS; every resolved address must be sandbox-range).
    try:
        ipaddress.ip_address(hostname)
        return True, ""  # literal private-range IP already matched layer 1
    except ValueError:
        pass

    ok, reason = _hostname_resolves_to_sandbox(hostname)
    if not ok:
        return False, reason
    return True, ""


def assert_target_still_sandboxed(url: str) -> None:
    """Re-validate a target immediately before scan execution (request time).

    Raises ScannerError when the stored target no longer satisfies the
    Zero-Trust policy (defense in depth against TOCTOU drift between the
    start request and the actual outbound scan traffic).
    """
    valid, reason = is_sandboxed_url(url)
    if not valid:
        raise ScannerError(f"Zero-Trust re-validation failed at execution time: {reason}")


class ScannerClient:
    """Client for Scanner Engine REST API."""

    def __init__(self, base_url: str | None = None, timeout_seconds: float = 30.0, max_retries: int = 1):
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
                # follow_redirects stays disabled: a scan request must never
                # be silently forwarded to a host outside the sandbox policy.
                async with httpx.AsyncClient(
                    timeout=self.timeout_seconds, follow_redirects=False
                ) as client:
                    resp = await client.post(endpoint, json=payload)
                    resp.raise_for_status()

                    try:
                        data = resp.json()
                    except ValueError as e:
                        logger.error("scanner returned malformed JSON for scan_id=%s: %s", scan_id, e)
                        raise MalformedScannerResponseError("Scanner returned non-JSON response") from e

                    if not isinstance(data, dict):
                        raise MalformedScannerResponseError("Scanner payload must be a JSON object")

                    # Log a summary only — never the full payload, which can
                    # contain evidence excerpts with embedded credentials.
                    findings = data.get("findings")
                    logger.info(
                        "scanner response <- 200 OK for scan_id=%s status=%s findings=%s",
                        scan_id,
                        data.get("status"),
                        len(findings) if isinstance(findings, list) else "n/a",
                    )
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
