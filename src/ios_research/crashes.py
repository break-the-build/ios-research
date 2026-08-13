"""Crash records and storage with signature-based deduplication.

A crash is a normalized artifact capturing the triggering input, its hash, the
target/format, mutation lineage, timestamp, process info and diagnostics.
Crashes are deduplicated by their diagnostic *signature* within an experiment.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .artifacts import ArtifactStore
from .clock import now_iso
from .hashing import sha256_bytes
from .ids import make_id
from .workspace import Workspace


@dataclass
class CrashRecord:
    id: str
    experiment_id: str
    target: str
    fmt: str
    input_sha256: str
    input_size: int
    outcome: str
    detail: str
    classification: str
    signature: str
    diagnostics: dict[str, Any]
    lineage: dict[str, Any] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""
    count: int = 1
    reproduced: bool | None = None
    minimized_sha256: str | None = None
    analysis_id: str | None = None
    status: str = "new"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CrashStore:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.artifacts = ArtifactStore(workspace)

    def _rel(self, crash_id: str) -> str:
        return f"crashes/{crash_id}/crash.json"

    def get(self, crash_id: str) -> CrashRecord:
        rel = self._rel(crash_id)
        if not self.ws.path(rel).exists():
            from .errors import NotFoundError
            raise NotFoundError(f"crash '{crash_id}' not found")
        return CrashRecord(**self.ws.read_json(rel))

    def save(self, crash: CrashRecord) -> None:
        self.ws.write_json(self._rel(crash.id), crash.to_dict())

    def list(self) -> list[CrashRecord]:
        base = self.ws.dir("crashes")
        out = []
        for manifest in sorted(base.glob("*/crash.json")):
            out.append(CrashRecord(**self.ws.read_json(
                str(manifest.relative_to(self.ws.root)))))
        return out

    def input_bytes(self, crash: CrashRecord) -> bytes:
        return self.artifacts.get_bytes(crash.input_sha256)

    def record(self, *, experiment_id: str, target: str, fmt: str,
               data: bytes, exec_result, lineage: dict | None = None) -> CrashRecord:
        """Record (or dedupe) a crash from an execution result.

        Dedup key is the diagnostic signature within the experiment: repeated
        signatures increment ``count`` on the existing record rather than
        creating a new one.
        """
        diag = exec_result.diagnostics
        signature = diag.signature if diag else "sig_none"
        classification = diag.classification_hint if diag else "UNKNOWN"
        crash_id = make_id("crash", experiment_id, signature)

        # Persist the triggering input as a content-addressed artifact.
        artifact = self.artifacts.put(data, kind="crash-input")

        rel = self._rel(crash_id)
        if self.ws.path(rel).exists():
            existing = self.get(crash_id)
            existing.count += 1
            existing.last_seen = now_iso()
            self.save(existing)
            return existing

        now = now_iso()
        crash = CrashRecord(
            id=crash_id,
            experiment_id=experiment_id,
            target=target,
            fmt=fmt,
            input_sha256=artifact.sha256,
            input_size=len(data),
            outcome=exec_result.outcome,
            detail=exec_result.detail,
            classification=classification,
            signature=signature,
            diagnostics=diag.to_dict() if diag else {},
            lineage=lineage or {},
            first_seen=now,
            last_seen=now,
        )
        self.save(crash)
        # Store a copy of the raw input beside the record for convenience, plus
        # the normalized diagnostics under diagnostics/ for triage/analysis.
        self.ws.write_bytes(f"crashes/{crash_id}/original-input.bin", data)
        self.ws.write_json(f"crashes/{crash_id}/diagnostics/diagnostics.json",
                           crash.diagnostics)
        return crash

    def minimized_bytes(self, crash: CrashRecord) -> bytes | None:
        rel = f"crashes/{crash.id}/minimized-input.bin"
        if not self.ws.path(rel).exists():
            return None
        return self.ws.read_bytes(rel)

    def write_minimized(self, crash: CrashRecord, data: bytes) -> str:
        self.ws.write_bytes(f"crashes/{crash.id}/minimized-input.bin", data)
        # Also store content-addressed so report evidence references resolve.
        artifact = self.artifacts.put(data, kind="minimized-input")
        crash.minimized_sha256 = artifact.sha256
        self.save(crash)
        return crash.minimized_sha256
