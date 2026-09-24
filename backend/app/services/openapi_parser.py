"""OpenAPI 3.x parsing and endpoint extraction.

Accepts JSON or YAML, validates the OpenAPI 3.x envelope, and extracts one
record per operation (method+path) with parameters, request body and effective
security requirements.
"""

import json
import logging
from typing import Any

import yaml

logger = logging.getLogger(__name__)

SUPPORTED_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


class OpenAPIError(ValueError):
    """Raised when the uploaded document is not a valid OpenAPI 3.x spec."""


def parse_spec(raw: bytes) -> tuple[dict[str, Any], str]:
    """Parse raw bytes into a dict; returns (document, format).

    Raises OpenAPIError for undecodable/invalid documents.
    """
    text = raw.decode("utf-8-sig", errors="strict")
    try:
        doc = json.loads(text)
        return doc, "json"
    except json.JSONDecodeError:
        pass
    try:
        doc = yaml.safe_load(text)
        if not isinstance(doc, dict):
            raise OpenAPIError("Document is not a mapping")
        return doc, "yaml"
    except yaml.YAMLError as exc:
        raise OpenAPIError(f"File is neither valid JSON nor YAML: {exc}") from exc


def validate_openapi(doc: dict[str, Any]) -> str:
    """Validate the OpenAPI 3.x envelope; returns the declared version."""
    version = doc.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise OpenAPIError(
            "Not an OpenAPI 3.x document (missing or unsupported 'openapi' field). "
            "OpenAPI 3.x is required."
        )
    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise OpenAPIError("OpenAPI document has no 'paths' object or it is empty")
    info = doc.get("info")
    if not isinstance(info, dict) or not isinstance(info.get("title"), str):
        raise OpenAPIError("OpenAPI document is missing info.title")
    return version


def extract_endpoints(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract operation records from paths; effective security resolved here."""
    global_security = doc.get("security") or []
    servers = doc.get("servers") or []
    base = servers[0].get("url") if servers and isinstance(servers[0], dict) else None

    out: list[dict[str, Any]] = []
    for path, path_item in (doc.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        if str(path).startswith("x-"):  # extensions, not real paths
            continue
        path_level_params = path_item.get("parameters") or []
        for method in SUPPORTED_METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            parameters = _merge_parameters(path_level_params, op.get("parameters") or [])
            security = op["security"] if isinstance(op.get("security"), list) else global_security
            out.append(
                {
                    "method": method.upper(),
                    "path": str(path),
                    "operation_id": op.get("operationId"),
                    "summary": op.get("summary"),
                    "description": op.get("description"),
                    "tags": op.get("tags") or [],
                    "parameters": parameters,
                    "request_body": op.get("requestBody"),
                    "security": security,
                    "server_url": base,
                }
            )
    return out


def _merge_parameters(path_level: list, op_level: list) -> list:
    """Operation-level parameters override path-level ones with same name+in."""
    def key(p: dict) -> tuple:
        return (p.get("name"), p.get("in"))

    merged = {key(p): p for p in path_level if isinstance(p, dict)}
    for p in op_level:
        if isinstance(p, dict):
            merged[key(p)] = p
    return list(merged.values())
