import re
from .models import Identity, Finding, Evidence
from .executor import HttpExecutor

_ID = re.compile(r"\{([^}]+)\}")

def scan_bola(base_url: str, endpoint_path: str, identity: Identity, own_id: str, other_id: str) -> Finding | None:
    executor = HttpExecutor()
    match = _ID.search(endpoint_path)
    if not match:
        return None
    param = match.group(1)
    own_path = endpoint_path.replace("{" + param + "}", str(own_id))
    other_path = endpoint_path.replace("{" + param + "}", str(other_id))
    baseline = executor.request(base_url, "GET", own_path, identity.token)
    attack = executor.request(base_url, "GET", other_path, identity.token)
    body = attack["body"]
    cross_access = attack["status_code"] < 300 and _contains_id(body, other_id)
    if not cross_access:
        return None
    evidence = Evidence(
        baseline_request={"method":"GET","path":own_path,"identity":identity.name},
        attack_request={"method":"GET","path":other_path,"identity":identity.name},
        baseline_response=baseline,
        attack_response=attack,
        proof={"cross_user_access": True, "requesting_identity": identity.name, "target_object": other_id},
    )
    poc = f"curl -i -H 'Authorization: Bearer $TOKEN' '{base_url.rstrip('/')}{other_path}'"
    return Finding("BOLA", endpoint_path, "HIGH", 0.99, "Broken Object Level Authorization", "An identity accessed an object belonging to another identity.", evidence, poc)

def _contains_id(body, object_id: str) -> bool:
    if isinstance(body, dict):
        return str(body.get("id")) == str(object_id) or any(_contains_id(v, object_id) for v in body.values())
    if isinstance(body, list):
        return any(_contains_id(v, object_id) for v in body)
    return str(object_id) in str(body)
