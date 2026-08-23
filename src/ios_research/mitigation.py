"""Memory-safety mitigation provenance for research devices (#87).

Since September 2025 the newest Apple devices enforce **Memory Integrity
Enforcement** (always-on Enhanced MTE across OS and app processes), which
materially changes which exploitability outcomes are demonstrable. Evidence
gathered on a pre-MIE device does not automatically transfer to an MIE-era
device, and vice versa — so the generation of the device a finding was
*discovered* on versus *confirmed* on belongs in the provenance record.

This module derives a coarse ``mitigation_profile`` **only from artifacts
already recorded in the workspace** (declared hardware model strings and OS
version strings). It ships no authoritative hardware-identifier table:
device-model identifiers are deployment-specific data, maintained via the
workspace override ``config/mitigation-models.json``::

    {"mie-emte": ["iPhone17,*"], "pre-mie": ["iPhone14,*", "iPhone15,*"]}

Entries are exact strings or glob-style prefixes ending in ``*``. When no
table entry matches (or no override exists) the profile is ``"unknown"`` —
the probe fails closed and never guesses. Classification is read-only and
deterministic; nothing here grants new device capabilities.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from .errors import ValidationError
from .hashing import canonical_json, sha256_text

OVERRIDE_RELPATH = "config/mitigation-models.json"
SCHEMA_VERSION = 1

# Coarse generations, most-recent first.
MIE_EMTE = "mie-emte"        # always-on EMTE across OS/app processes (2025+)
PRE_MIE = "pre-mie"          # PAC/PPL era without enforced memory tagging
UNKNOWN = "unknown"

_PROFILES = (MIE_EMTE, PRE_MIE)
_TABLE_KEYS = ("mie-emte", "pre-mie")

_OS_MAJOR_RE = re.compile(r"(?<!\d)(\d{1,2})(?!\d)")


def load_model_table(workspace=None) -> dict[str, list[str]]:
    """Load the effective model table: workspace override or empty builtin.

    The override is researcher-authored JSON of the shape
    ``{"mie-emte": [...], "pre-mie": [...]}``. Its content hash pins whichever
    table was in force, mirroring the Target Flag taxonomy mechanism.
    """
    if workspace is not None and workspace.path(OVERRIDE_RELPATH).exists():
        try:
            import json
            data = json.loads(
                workspace.path(OVERRIDE_RELPATH).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValidationError(
                f"invalid mitigation model override: {exc}") from exc
        if not isinstance(data, dict):
            raise ValidationError("mitigation model override must be an object")
        unknown = [k for k in data if k not in _TABLE_KEYS]
        if unknown:
            raise ValidationError(
                f"mitigation model override has unknown profile keys: "
                f"{', '.join(sorted(unknown))}")
        table: dict[str, list[str]] = {}
        for key in _TABLE_KEYS:
            raw = data.get(key, [])
            if not isinstance(raw, list) or \
                    not all(isinstance(x, str) and x.strip() for x in raw):
                raise ValidationError(
                    f"mitigation model override key '{key}' must be a list "
                    f"of non-empty strings")
            table[key] = sorted(raw)
        return table
    return {key: [] for key in _TABLE_KEYS}


def table_info(table: dict[str, list[str]]) -> dict[str, Any]:
    body = {"schema_version": SCHEMA_VERSION,
            "profiles": {k: sorted(v) for k, v in sorted(table.items())}}
    return {"sha256": sha256_text(canonical_json(body)), "profiles": table}


def _matches(model: str, entries: list[str]) -> bool:
    lowered = model.lower()
    return any(fnmatch.fnmatch(lowered, e.lower()) for e in entries)


def os_major(os_train: str = "", os_version: str = "") -> int | None:
    """Extract the leading OS major (e.g. ``26.1`` -> ``26``)."""
    for candidate in (os_train or "", os_version or ""):
        m = _OS_MAJOR_RE.search(candidate.strip())
        if m:
            value = int(m.group(1))
            if 1 <= value <= 99:
                return value
    return None


def classify(hardware_model: str = "", os_train: str = "",
             os_version: str = "", table: dict[str, list[str]] | None = None
             ) -> dict[str, Any]:
    """Derive the mitigation profile from recorded provenance strings only.

    Returns a deterministic dict with ``mitigation_profile`` (one of
    ``mie-emte`` / ``pre-mie`` / ``unknown``), the matching ``basis``, the raw
    inputs echoed back, and the parsed OS major. Unknown inputs yield
    ``unknown`` rather than a guess.
    """
    table = table if table is not None else load_model_table(None)
    model = str(hardware_model or "").strip()
    profile = UNKNOWN
    basis = ""
    if model:
        for candidate in _PROFILES:
            if _matches(model, table.get(candidate, [])):
                profile = candidate
                basis = "model-table"
                break
    return {
        "schema_version": SCHEMA_VERSION,
        "mitigation_profile": profile,
        "basis": basis,
        "hardware_model": model,
        "os_train": str(os_train or "").strip(),
        "os_major": os_major(os_train, os_version),
    }


def summarize_profiles(entries: list[Any]) -> list[str]:
    """Distinct non-unknown profiles from matrix/metadata evidence entries."""
    seen: list[str] = []
    for item in entries or []:
        if isinstance(item, dict):
            profile = str(item.get("mitigation_profile", "") or "")
        elif isinstance(item, str):
            profile = item
        else:
            continue
        if profile in _PROFILES and profile not in seen:
            seen.append(profile)
    return seen


def mismatch_warning(entries: list[Any]) -> str | None:
    """Non-binding warning when evidence spans multiple generations."""
    profiles = summarize_profiles(entries)
    if len(profiles) > 1:
        return (
            "Evidence spans multiple memory-safety mitigation generations ("
            + ", ".join(sorted(profiles))
            + "). Exploitability reasoning may not transfer between them; "
              "record which generation each artifact came from.")
    return None
