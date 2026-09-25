import ipaddress
import socket

import httpx


def _ip_is_sandbox(ip: str) -> bool:
    """True when an IP belongs to private/loopback/link-local/reserved ranges."""
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


def _assert_sandbox_base_url(base_url: str) -> None:
    """Resolve the target host and require every address to be sandbox-range.

    Defense in depth for the Zero-Trust policy: the scanner engine only ever
    talks to private/loopback targets, even if a caller passes a textual
    bypass such as '10.0.0.1.evil.com'.
    """
    from urllib.parse import urlparse

    hostname = (urlparse(base_url).hostname or "").lower()
    if not hostname:
        raise ValueError(f"Target URL '{base_url}' has no hostname")
    try:
        ipaddress.ip_address(hostname)
        return  # literal IP; already private/loopback per the caller's policy
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError as exc:
        raise ValueError(f"Target host '{hostname}' could not be resolved") from exc
    for info in infos:
        ip = str(info[4][0])  # sockaddr is the 5th getaddrinfo tuple element
        if not _ip_is_sandbox(ip):
            raise ValueError(
                f"Zero-Trust violation: target '{hostname}' resolves to "
                f"non-private address {ip}"
            )


class HttpExecutor:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.last_base_url: str | None = None

    def request(self, base_url: str, method: str, path: str, token: str | None = None):
        # Re-check the target on every request (cheap: getaddrinfo result is
        # cached by the OS) and never follow redirects — a 3xx must not carry
        # the scanner to a host outside the sandbox policy.
        if base_url != self.last_base_url:
            _assert_sandbox_base_url(base_url)
            self.last_base_url = base_url
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        with httpx.Client(
            base_url=base_url, timeout=self.timeout, follow_redirects=False
        ) as client:
            r = client.request(method, path, headers=headers)
        try:
            body = r.json()
        except Exception:
            body = r.text
        return {"status_code": r.status_code, "headers": dict(r.headers), "body": body}
