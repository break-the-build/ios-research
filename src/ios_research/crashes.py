"""Crash records and storage with signature-based deduplication.

A crash is a normalized artifact capturing the triggering input, its hash, the
target/format, mutation lineage, timestamp, process info and diagnostics.
Crashes are deduplicated by their diagnostic *signature* per (target,
signature) across the whole workspace (#264): the record id is derived from
the target and signature only — never from the discovering experiment — so a
signature re-discovered by a later fuzz session bumps the canonical record
(count/``last_seen``, plus an ``experiment_ids`` attribution entry) instead of
creating a duplicate that would re-flow through minimize/reproduce/analyze.
"""

from __future__ import annotations

from pathlib import Path

from dataclasses import dataclass, field, asdict
from typing import Any

from .artifacts import ArtifactStore
from .clock import now_iso
from .errors import StateError, ValidationError
from .hashing import sha256_bytes
from .ids import make_id
from .targets.base import Outcome
from .workspace import Workspace, validate_component


def _crash_from_dict(data: dict) -> CrashRecord:
    """Build a record from persisted JSON with a stable error on drift."""
    try:
        crash = CrashRecord(**data)
    except TypeError:
        raise StateError(
            "crash record is corrupt or from an incompatible version",
            details={"keys": sorted(data)}) from None
    # Back-compat (#264): records persisted before workspace-global dedup have
    # no ``experiment_ids`` field; the legacy single-experiment field is the
    # sole contributor. Backfilling here makes every loaded record uniform so
    # scoping (list/get) can rely on membership alone.
    if not crash.experiment_ids:
        crash.experiment_ids = [crash.experiment_id]
    return crash


def _contributed(crash: CrashRecord, experiment_id: str | None) -> bool:
    """Whether ``experiment_id`` contributed to this crash record (#264).

    ``None`` means "no scoping" and matches everything. Falls back to the
    legacy single ``experiment_id`` for in-memory records that never went
    through :func:`_crash_from_dict` (e.g. hand-built fixtures) and therefore
    carry an empty ``experiment_ids`` list.
    """
    if experiment_id is None:
        return True
    return experiment_id in (crash.experiment_ids or [crash.experiment_id])


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
    # Contributing experiments (#264): every fuzz session whose (target,
    # signature) hit this record. ``experiment_id`` stays the canonical FIRST
    # contributor so pre-#264 consumers keep a stable value; records persisted
    # before #264 lack the list and are backfilled at load time. (Declared
    # among the defaulted fields because the dataclass requires defaults
    # after non-defaults.)
    experiment_ids: list[str] = field(default_factory=list)
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

    def get(self, crash_id: str, *, experiment_id: str | None = None) -> CrashRecord:
        validate_component(crash_id, what="crash id")
        rel = self._rel(crash_id)
        if not self.ws.path(rel).exists():
            from .errors import NotFoundError
            raise NotFoundError(f"crash '{crash_id}' not found")
        crash = _crash_from_dict(self.ws.read_json(rel))
        # Scoped reads (#264) accept any *contributing* experiment, not just
        # the one that first recorded the signature.
        if not _contributed(crash, experiment_id):
            raise ValidationError(
                f"crash '{crash_id}' is not in experiment '{experiment_id}'")
        return crash

    @staticmethod
    def ensure_safe_id(crash_id: str) -> None:
        """Reject crafted IDs that could turn record paths into traversals."""
        candidate = Path(crash_id)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValidationError(
                "crash id must name a record inside the workspace")

    @staticmethod
    def _attribute(crash: CrashRecord, experiment_id: str | None) -> None:
        """Add ``experiment_id`` as a contributor of ``crash`` (#264).

        No-op for unknown contributors; the legacy single ``experiment_id``
        field is left untouched so it keeps naming the FIRST experiment that
        recorded the signature.
        """
        if experiment_id is None:
            return
        if experiment_id not in (crash.experiment_ids or [crash.experiment_id]):
            crash.experiment_ids.append(experiment_id)

    def save(self, crash: CrashRecord) -> None:
        self.ws.write_json(self._rel(crash.id), crash.to_dict())

    def bump_count(self, crash_id: str, extra: int,
                   *, experiment_id: str | None = None) -> None:
        """Add ``extra`` to a crash's occurrence count in a single write.

        Lets a hot loop accumulate duplicate counts in memory and flush them
        once, instead of re-reading and rewriting the record per duplicate.

        Because the dedup key is workspace-global since #264, this is also the
        path a re-discovery from a *different* experiment takes (see
        ``FuzzEngine._flush_crashes``): instead of rejecting a non-member
        experiment, the call attributes it via ``experiment_ids``.
        """
        if extra <= 0:
            return
        crash = self.get(crash_id)
        self._attribute(crash, experiment_id)
        crash.count += extra
        crash.last_seen = now_iso()
        self.save(crash)

    def list(self, *, experiment_id: str | None = None) -> list[CrashRecord]:
        """List records in this workspace, optionally for one experiment.

        Scoped listing (#264) returns every record the experiment
        *contributed to* — including signatures first discovered under another
        experiment and later re-hit — falling back to the legacy single
        ``experiment_id`` for records persisted before #264.
        """
        base = self.ws.dir("crashes")
        out = []
        for manifest in sorted(base.glob("*/crash.json")):
            crash = _crash_from_dict(self.ws.read_json(
                str(manifest.relative_to(self.ws.root))))
            if _contributed(crash, experiment_id):
                out.append(crash)
        return out

    def input_bytes(self, crash: CrashRecord) -> bytes:
        return self.artifacts.get_bytes(crash.input_sha256)

    def record(self, *, experiment_id: str, target: str, fmt: str,
               data: bytes, exec_result, lineage: dict | None = None) -> CrashRecord:
        """Record (or dedupe) a crash from an execution result.

        The dedup key is the diagnostic signature scoped to the TARGET and is
        workspace-global (#264): a repeated signature — from the same or any
        later experiment — increments ``count``/refreshes ``last_seen`` on the
        canonical record and adds the contributing experiment to
        ``experiment_ids`` rather than creating a new record. The same
        signature under a different target remains a distinct record.
        """
        if exec_result.outcome != Outcome.CRASH:
            raise ValidationError(
                "only confirmed CRASH outcomes can be stored as crash records")
        diag = exec_result.diagnostics
        signature = diag.signature if diag else "sig_none"
        classification = diag.classification_hint if diag else "UNKNOWN"
        # Workspace-global identity (#264): derived from (target, signature)
        # only, deliberately independent of the discovering experiment, so
        # path existence doubles as the cross-session signature registry.
        crash_id = make_id("crash", target, signature)

        # Persist the triggering input as a content-addressed artifact.
        artifact = self.artifacts.put(data, kind="crash-input")

        rel = self._rel(crash_id)
        if self.ws.path(rel).exists():
            existing = self.get(crash_id)
            existing.count += 1
            existing.last_seen = now_iso()
            self._attribute(existing, experiment_id)
            self.save(existing)
            return existing

        now = now_iso()
        crash = CrashRecord(
            id=crash_id,
            experiment_id=experiment_id,
            experiment_ids=[experiment_id],
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
