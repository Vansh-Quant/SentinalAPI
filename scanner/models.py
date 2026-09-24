from dataclasses import dataclass, field
from typing import Any

@dataclass
class Identity:
    name: str
    token: str
    role: str = "user"
    object_ids: set[str] = field(default_factory=set)

@dataclass
class Endpoint:
    method: str
    path: str
    operation_id: str | None = None
    parameters: list[dict[str, Any]] = field(default_factory=list)
    response_schema: dict[str, Any] | None = None

@dataclass
class Evidence:
    baseline_request: dict[str, Any]
    attack_request: dict[str, Any]
    baseline_response: dict[str, Any]
    attack_response: dict[str, Any]
    proof: dict[str, Any]

@dataclass
class Finding:
    kind: str
    endpoint: str
    severity: str
    confidence: float
    title: str
    description: str
    evidence: Evidence
    poc: str
