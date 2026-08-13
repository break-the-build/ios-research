"""Fuzzing engine: deterministic, resumable mutation-based fuzzing.

The engine drives a target through many mutated inputs, records normalized
outcomes, and persists crashes (deduplicated by signature). Sessions are
persisted so they can be paused and resumed. Execution is fully deterministic
for a given ``(seed, corpus)`` — the reference engine runs sequentially and
records ``workers`` as metadata.

The engine only *identifies* abnormal behavior and crashes. It never generates
exploit payloads.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any

from . import mutation, targets
from .clock import now_iso
from .corpus import CorpusStore, Corpus
from .crashes import CrashStore
from .errors import NotFoundError, StateError
from .hashing import sha256_bytes
from .ids import make_id
from .targets.base import Outcome
from .workspace import Workspace

DEFAULT_BASE = b"MOCK" + bytes([1, 1]) + (2).to_bytes(2, "big") + b"ok"

RUNNING = "running"
PAUSED = "paused"
STOPPED = "stopped"
COMPLETED = "completed"


@dataclass
class FuzzSession:
    id: str
    experiment_id: str
    target: str
    corpus_id: str
    seed: int
    workers: int
    max_cases: int
    duration_s: float | None
    status: str = RUNNING
    base_shas: list[str] = field(default_factory=list)
    cursor: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)
    crashes: int = 0
    unique_crashes: int = 0
    crash_ids: list[str] = field(default_factory=list)
    started_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def stats(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "executed": self.cursor,
            "max_cases": self.max_cases,
            "progress": round(self.cursor / self.max_cases, 4)
            if self.max_cases else 1.0,
            "outcomes": dict(self.outcomes),
            "crashes": self.crashes,
            "unique_crashes": self.unique_crashes,
            "crash_ids": list(self.crash_ids),
        }


class FuzzEngine:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.corpus_store = CorpusStore(workspace)
        self.crash_store = CrashStore(workspace)

    def _rel(self, session_id: str) -> str:
        return f"fuzz/{session_id}.json"

    # persistence ---------------------------------------------------------
    def save(self, session: FuzzSession) -> None:
        session.updated_at = now_iso()
        self.ws.write_json(self._rel(session.id), session.to_dict())

    def get(self, session_id: str) -> FuzzSession:
        rel = self._rel(session_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"fuzz session '{session_id}' not found")
        return FuzzSession(**self.ws.read_json(rel))

    def list(self) -> list[FuzzSession]:
        return [FuzzSession(**d) for d in self.ws.list_json("fuzz")]

    def latest(self) -> FuzzSession | None:
        sessions = self.list()
        if not sessions:
            return None
        return sorted(sessions, key=lambda s: s.updated_at)[-1]

    # lifecycle -----------------------------------------------------------
    def create(self, *, experiment_id: str, target: str, corpus_id: str,
               seed: int, workers: int, max_cases: int,
               duration_s: float | None) -> FuzzSession:
        now = now_iso()
        session_id = make_id("experiment", "fuzz", experiment_id, target,
                             corpus_id, str(seed), str(max_cases), now)
        session_id = "fz_" + session_id.split("_", 1)[1]
        # Snapshot the base set at creation so the run is deterministic and
        # resume-invariant: crashing inputs added mid-run do not change bases.
        corpus = self.corpus_store.get(corpus_id)
        base_shas = [tc["sha256"] for tc in corpus.testcases]
        session = FuzzSession(
            id=session_id, experiment_id=experiment_id, target=target,
            corpus_id=corpus_id, seed=seed, workers=workers,
            max_cases=max_cases, duration_s=duration_s,
            base_shas=base_shas,
            status=RUNNING, started_at=now, updated_at=now,
            outcomes={o: 0 for o in Outcome.ALL},
        )
        self.save(session)
        return session

    def _bases(self, session: FuzzSession, corpus: Corpus) -> list[bytes]:
        bases = [self.corpus_store.read_bytes(corpus, sha)
                 for sha in session.base_shas]
        return bases or [DEFAULT_BASE]

    def advance(self, session: FuzzSession, *, max_new: int | None = None,
                deadline: float | None = None) -> FuzzSession:
        """Execute cases from the current cursor until a stop condition."""
        if session.status in (COMPLETED, STOPPED):
            return session
        session.status = RUNNING
        corpus = self.corpus_store.get(session.corpus_id)
        bases = self._bases(session, corpus)
        target = targets.create(session.target)
        fmt = target.formats[0] if target.formats else target.kind
        unique = set(session.crash_ids)
        executed_this = 0

        while session.cursor < session.max_cases:
            if max_new is not None and executed_this >= max_new:
                session.status = PAUSED
                break
            if deadline is not None and time.monotonic() >= deadline:
                session.status = PAUSED
                break

            i = session.cursor
            base = bases[i % len(bases)]
            mutated, strategy = mutation.mutate(base, session.seed, i)
            result = target.execute(mutated)
            session.outcomes[result.outcome] = \
                session.outcomes.get(result.outcome, 0) + 1

            if result.outcome in (Outcome.CRASH, Outcome.ABNORMAL):
                lineage = {"parent_sha256": sha256_bytes(base),
                           "mutation": strategy, "seed": session.seed,
                           "iteration": i}
                crash = self.crash_store.record(
                    experiment_id=session.experiment_id, target=session.target,
                    fmt=fmt, data=mutated, exec_result=result, lineage=lineage)
                session.crashes += 1
                if crash.id not in unique:
                    unique.add(crash.id)
                    session.crash_ids.append(crash.id)
                # Preserve the crashing input in the corpus with lineage.
                self.corpus_store.add_bytes(
                    corpus, mutated, origin="mutation",
                    parent=sha256_bytes(base), mutation=strategy,
                    seed=session.seed, iteration=i)

            session.cursor += 1
            executed_this += 1

        if session.cursor >= session.max_cases:
            session.status = COMPLETED
        session.unique_crashes = len(session.crash_ids)
        self.save(session)
        return session

    def resume(self, session: FuzzSession, *, max_new: int | None = None,
               deadline: float | None = None) -> FuzzSession:
        if session.status == COMPLETED:
            raise StateError(f"fuzz session '{session.id}' already completed")
        if session.status == STOPPED:
            raise StateError(f"fuzz session '{session.id}' was stopped")
        return self.advance(session, max_new=max_new, deadline=deadline)

    def pause(self, session: FuzzSession) -> FuzzSession:
        if session.status == RUNNING or session.status == PAUSED:
            session.status = PAUSED
            self.save(session)
        return session

    def stop(self, session: FuzzSession) -> FuzzSession:
        session.status = STOPPED
        self.save(session)
        return session
