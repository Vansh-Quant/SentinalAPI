"""Evidence-grounded analyst.

This layer never decides whether a finding exists. It only supplies
structured explanation text for findings already verified by the scanner.
"""

def analyze_finding(item: dict) -> dict:
    kind = str(item.get("type", "")).upper()
    if kind == "BOLA":
        return {
            "description": item.get("description") or "Cross-identity access to an object was verified from observed HTTP responses.",
            "impact": "An authenticated caller may access another user's object.",
            "remediation": "Enforce server-side ownership or ACL checks for every object access.",
            "analysis_source": "deterministic",
        }
    if kind == "BOPLA":
        return {
            "description": item.get("description") or "The observed response contains sensitive properties outside the documented response contract.",
            "impact": "Sensitive internal or personal properties may be disclosed.",
            "remediation": "Return explicit response DTOs containing only authorized properties.",
            "analysis_source": "deterministic",
        }
    return {"analysis_source": "deterministic"}
