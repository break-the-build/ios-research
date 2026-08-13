"""Configuration management.

Configuration is a plain JSON document with defaults, workspace overrides, and
a deterministic hash used to stamp experiments for reproducibility.
"""

from __future__ import annotations

from typing import Any

from .hashing import config_hash

DEFAULT_CONFIG: dict[str, Any] = {
    "default_target": "mock:parser",
    "default_device": "mock:device",
    "fuzz": {
        "workers": 1,
        "max_cases": 1000,
        "timeout_ms": 1000,
        "seed": 0,
    },
    "limits": {
        "max_runtime_seconds": 600,
        "max_workers": 8,
        "max_storage_mb": 1024,
        "max_testcases": 100000,
    },
    "output": {
        "json_indent": 2,
    },
}


def merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge ``override`` onto ``base`` returning a new dict (immutable)."""
    out = dict(base)
    for key, value in override.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    def __init__(self, values: dict[str, Any] | None = None):
        self.values = merge(DEFAULT_CONFIG, values or {})

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.values
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted: str, value: Any) -> "Config":
        parts = dotted.split(".")
        new_values = _set_in(self.values, parts, value)
        return Config(new_values)

    @property
    def hash(self) -> str:
        return config_hash(self.values)


def _set_in(node: dict[str, Any], parts: list[str], value: Any) -> dict[str, Any]:
    key = parts[0]
    out = dict(node)
    if len(parts) == 1:
        out[key] = value
    else:
        child = out.get(key, {})
        if not isinstance(child, dict):
            child = {}
        out[key] = _set_in(child, parts[1:], value)
    return out
