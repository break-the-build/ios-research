"""Structured logging.

Logs are emitted as structured records. Human mode renders a compact line;
files receive JSON lines. Sensitive keys are redacted to avoid leaking
credentials or secrets into logs (a safety-audit requirement).
"""

from __future__ import annotations

import json
import sys
from typing import Any

from .clock import now_iso

_REDACT_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "auth", "credential", "credentials", "private_key",
}
# Substring rules catch compound real-world keys (access_token,
# session_token, client_secret, refresh_token, set_cookie, ...).
_REDACT_SUBSTRINGS = (
    "token", "secret", "password", "passwd", "apikey", "api_key",
    "api-key", "authorization", "credential", "private_key", "cookie",
)
_REDACTED = "***REDACTED***"

LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    if lowered in _REDACT_KEYS:
        return True
    return any(marker in lowered for marker in _REDACT_SUBSTRINGS)


def redact(fields: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``fields`` with sensitive values redacted.

    Recurses through nested dicts **and** lists/tuples so secrets do not
    leak just because they sit inside a collection.
    """
    def clean_value(value: Any) -> Any:
        if isinstance(value, dict):
            return redact(value)
        if isinstance(value, (list, tuple)):
            cleaned = [clean_value(item) for item in value]
            return cleaned if isinstance(value, list) else tuple(cleaned)
        return value

    clean: dict[str, Any] = {}
    for key, value in fields.items():
        clean[key] = _REDACTED if _is_sensitive(str(key)) \
            else clean_value(value)
    return clean


class Logger:
    def __init__(self, *, level: str = "info", verbose: bool = False,
                 quiet: bool = False, log_file=None, stream=None):
        self.level = LEVELS.get(level, 20)
        if verbose:
            self.level = LEVELS["debug"]
        if quiet:
            self.level = LEVELS["error"]
        self.log_file = log_file
        self.stream = stream or sys.stderr

    def log(self, level: str, event: str, **fields: Any) -> None:
        if LEVELS.get(level, 20) < self.level:
            return
        record = {"ts": now_iso(), "level": level, "event": event,
                  **redact(fields)}
        if self.log_file is not None:
            self.log_file.write(json.dumps(record, sort_keys=True) + "\n")
            self.log_file.flush()
        if level in ("warning", "error") or self.level <= LEVELS["debug"]:
            extra = " ".join(f"{k}={v}" for k, v in redact(fields).items())
            self.stream.write(f"[{level}] {event} {extra}".rstrip() + "\n")

    def debug(self, event: str, **f: Any) -> None:
        self.log("debug", event, **f)

    def info(self, event: str, **f: Any) -> None:
        self.log("info", event, **f)

    def warning(self, event: str, **f: Any) -> None:
        self.log("warning", event, **f)

    def error(self, event: str, **f: Any) -> None:
        self.log("error", event, **f)
