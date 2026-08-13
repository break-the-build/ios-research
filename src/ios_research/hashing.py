"""Deterministic hashing helpers used across artifacts and experiments."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_bytes(data: bytes) -> str:
    """Return the hex SHA-256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def canonical_json(obj: Any) -> str:
    """Serialize ``obj`` to a canonical, stable JSON string.

    Keys are sorted and separators are fixed so the output is deterministic and
    suitable for hashing (e.g. configuration hashes).
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def config_hash(obj: Any) -> str:
    """Stable hash of a configuration-like object.

    Prefixed and truncated for readability while remaining collision-resistant
    for practical research use.
    """
    return "cfg_" + sha256_text(canonical_json(obj))[:16]
