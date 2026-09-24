from pathlib import Path
import json
import yaml
from .models import Endpoint

def load_spec(source: str) -> dict:
    path = Path(source)
    raw = path.read_text(encoding="utf-8") if path.exists() else source
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return yaml.safe_load(raw)

def normalize(spec: dict) -> list[Endpoint]:
    if not isinstance(spec, dict) or "paths" not in spec:
        raise ValueError("Unsupported or invalid OpenAPI document")
    endpoints: list[Endpoint] = []
    for path, item in spec["paths"].items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in {"get","post","put","patch","delete","head","options"}:
                continue
            operation = operation or {}
            endpoints.append(Endpoint(
                method=method.upper(),
                path=path,
                operation_id=operation.get("operationId"),
                parameters=operation.get("parameters", []),
                response_schema=_response_schema(operation),
            ))
    return endpoints

def _response_schema(operation: dict):
    responses = operation.get("responses", {})
    for code in ("200", "201", "202"):
        content = responses.get(code, {}).get("content", {})
        app_json = content.get("application/json", {})
        if "schema" in app_json:
            return app_json["schema"]
    return None
