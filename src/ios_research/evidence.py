"""Researcher-recorded evidence: sysdiagnose references, videos, logs (#38).

Apple's on-device bounty classes ask for artifacts the *researcher* records —
sysdiagnose bundles, timestamp-linked crash logs, screen recordings. This store
imports such local files against an existing crash record:

* every import is an explicit researcher action (the framework never starts a
  recording or pulls data off a device by itself),
* each artifact is copied into the workspace and pinned with a SHA-256
  integrity hash,
* video/screen recordings require an explicit ``redaction_ack`` so researchers
  consciously accept the redaction responsibility; the warning travels with
  the artifact,
* provenance (device id, build, process, capture timestamp) is stored exactly
  as supplied — it correlates evidence with input/device/reproduction time but
  is always distinguishable from tool-generated inference.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .clock import now_iso
from .errors import NotFoundError, ValidationError
from .hashing import sha256_bytes
from .ids import make_id
from .workspace import Workspace

EVIDENCE_SCHEMA_VERSION = 1

KINDS = ("crash-log", "sysdiagnose", "video", "screenshot", "syslog", "other")
_REDACTION_KINDS = ("video", "screenshot")


def _require_safe_name(name: str) -> str:
    candidate = Path(name)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.name:
        raise ValidationError("artifact file name must be a plain name")
    return candidate.name


class EvidenceStore:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.crashes = None  # late-bound to avoid an import cycle

    def _crash(self, crash_id: str):
        from .crashes import CrashStore
        store = CrashStore(self.ws)
        store.ensure_safe_id(crash_id)
        crash = store.get(crash_id)
        return crash

    def _rel(self, item_id: str) -> str:
        return f"findings/{item_id}/evidence.json"

    def import_file(self, crash_id: str, path: str | Path, kind: str, *,
                    device_id: str = "", build: str = "", process: str = "",
                    captured_at: str = "",
                    redaction_ack: bool = False,
                    notes: str = "") -> dict[str, Any]:
        """Copy one researcher-supplied artifact into the workspace."""
        if kind not in KINDS:
            raise ValidationError(
                f"unknown evidence kind '{kind}'; known: {', '.join(KINDS)}")
        crash = self._crash(crash_id)
        source = Path(path)
        if not source.is_file():
            raise NotFoundError(f"artifact not found: {source}")
        name = _require_safe_name(source.name)

        if kind in _REDACTION_KINDS and not redaction_ack:
            raise ValidationError(
                f"importing {kind} evidence requires --redaction-ack: the "
                f"researcher confirms review/redaction responsibility")

        blob = source.read_bytes()
        digest = sha256_bytes(blob)
        item_id = make_id("evidence", crash_id, kind, digest)
        rel_dir = f"crashes/{crash_id}/evidence"
        self.ws.write_bytes(f"{rel_dir}/{item_id}_{name}", blob)

        # Correlation is computed only from researcher-supplied timestamps;
        # the delta to the tool-recorded last-seen stays explicit evidence.
        correlation: dict[str, Any] = {}
        if captured_at:
            try:
                from datetime import datetime
                parsed_capture = datetime.fromisoformat(captured_at)
                parsed_seen = datetime.fromisoformat(crash.last_seen)
                if (parsed_capture.tzinfo is None) != \
                        (parsed_seen.tzinfo is None):
                    raise ValueError("mixed aware/naive timestamps")
                delta = (parsed_seen - parsed_capture).total_seconds()
                correlation = {
                    "reference": "crash.last_seen",
                    "delta_seconds": round(delta, 3),
                }
            except ValueError:
                correlation = {
                    "reference": "crash.last_seen",
                    "note": "captured_at not ISO-8601; no delta computed",
                }

        item = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "id": item_id,
            "kind": kind,
            "file": f"{rel_dir}/{item_id}_{name}",
            "sha256": digest,
            "size": len(blob),
            "linked_crash_id": crash_id,
            "device_id": device_id,
            "build": build,
            "process": process,
            "captured_at": captured_at,
            "correlation": correlation,
            "redaction_ack": bool(redaction_ack),
            "warnings": ([f"{kind} artifacts may contain personal data; "
                          "review before any external submission"]
                         if kind in _REDACTED_KINDS_WARN else []),
            "notes": notes,
            "imported_at": now_iso(),
            "source": "researcher-supplied",
        }
        self.ws.write_json(self._rel(item_id), item)
        return item

    def get(self, item_id: str) -> dict[str, Any]:
        rel = self._rel(item_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"evidence item '{item_id}' not found")
        return self.ws.read_json(rel)

    def list(self, crash_id: str) -> list[dict[str, Any]]:
        out = []
        base = self.ws.root / "findings"
        if not base.exists():
            return out
        for manifest in sorted(base.glob("*/evidence.json")):
            item = self.ws.read_json(str(manifest.relative_to(self.ws.root)))
            if item.get("linked_crash_id") == crash_id:
                out.append(item)
        return out

    def verify_integrity(self, item_id: str) -> bool:
        item = self.get(item_id)
        path = self.ws.path(item["file"])
        if not path.is_file():
            return False
        return sha256_bytes(path.read_bytes()) == item["sha256"]


# Kept separate so the module-level constant reads cleanly above.
_REDACTED_KINDS_WARN = _REDACTION_KINDS
