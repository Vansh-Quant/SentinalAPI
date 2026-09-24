from .models import Finding, Evidence

SENSITIVE = {"password","password_hash","token","secret","api_key","ssn","internal_notes","admin_flag"}

def analyze_response(endpoint: str, response: dict, expected_fields: set[str] | None = None) -> Finding | None:
    body = response.get("body")
    if not isinstance(body, dict):
        return None
    expected = expected_fields or set()
    exposed = sorted(k for k in body if k.lower() in SENSITIVE and k not in expected)
    if not exposed:
        return None
    evidence = Evidence(
        baseline_request={"endpoint": endpoint},
        attack_request={"endpoint": endpoint},
        baseline_response={"status_code": response.get("status_code")},
        attack_response=response,
        proof={"unauthorized_sensitive_properties": exposed},
    )
    poc = f"# Reproduce: request {endpoint} with the same authorized test identity and inspect the response."
    return Finding("BOPLA", endpoint, "HIGH", 0.94, "Broken Object Property Level Authorization", f"Sensitive properties exposed: {', '.join(exposed)}", evidence, poc)
