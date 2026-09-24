"""Security Sanitizer — Redacts credentials, tokens, and secrets from evidence & logs."""

import re
from typing import Any

# Regex patterns for sensitive headers and tokens
JWT_RE = re.compile(r"Bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", re.IGNORECASE)
AUTH_HEADER_RE = re.compile(r"(Authorization:\s*)[^\r\n]+", re.IGNORECASE)
API_KEY_HEADER_RE = re.compile(r"(x-api-key:\s*)[^\r\n]+", re.IGNORECASE)
COOKIE_RE = re.compile(r"(Cookie:\s*)[^\r\n]+", re.IGNORECASE)
SECRET_PARAM_RE = re.compile(r"((?:token|access_token|secret|password|key)=)[^&\s]+", re.IGNORECASE)

SENSITIVE_KEYS = {
    "password",
    "secret",
    "access_token",
    "refresh_token",
    "token",
    "api_key",
    "apikey",
    "client_secret",
    "private_key",
    "authorization",
    "cookie",
    "internal_notes",
    "admin_flag",
    "supplier_cost",
    "margin",
    "card_number",
    "payment_method",
}


def sanitize_text(text: str | None) -> str | None:
    """Redact sensitive JWT tokens, authorization headers, and secrets from text strings."""
    if not text or not isinstance(text, str):
        return text

    sanitized = JWT_RE.sub("Bearer [REDACTED]", text)
    sanitized = AUTH_HEADER_RE.sub(r"\1[REDACTED]", sanitized)
    sanitized = API_KEY_HEADER_RE.sub(r"\1[REDACTED]", sanitized)
    sanitized = COOKIE_RE.sub(r"\1[REDACTED]", sanitized)
    sanitized = SECRET_PARAM_RE.sub(r"\1[REDACTED]", sanitized)
    return sanitized


def sanitize_dict(data: Any) -> Any:
    """Recursively sanitize sensitive key-value pairs in dictionaries or lists."""
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            key_str = str(key).lower()
            if any(s in key_str for s in SENSITIVE_KEYS):
                result[key] = "[REDACTED]"
            else:
                result[key] = sanitize_dict(value)
        return result
    elif isinstance(data, list):
        return [sanitize_dict(item) for item in data]
    elif isinstance(data, str):
        return sanitize_text(data)
    return data
