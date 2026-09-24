import httpx

class HttpExecutor:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def request(self, base_url: str, method: str, path: str, token: str | None = None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        with httpx.Client(base_url=base_url, timeout=self.timeout) as client:
            r = client.request(method, path, headers=headers)
        try:
            body = r.json()
        except Exception:
            body = r.text
        return {"status_code": r.status_code, "headers": dict(r.headers), "body": body}
