"""Fuzzing engine: deterministic, resumable mutation-based fuzzing.

The engine drives a target through many mutated inputs, records normalized
outcomes, and persists crashes (deduplicated by signature). Sessions are
persisted so they can be paused and resumed. Execution is fully deterministic
for a given ``(seed, corpus)`` — the reference engine runs sequentially and
records ``workers`` as metadata.

The engine persists confirmed crashes and reports abnormal harness behavior
separately. It never generates exploit payloads.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any

from . import mutation, targets
from .clock import now_iso
from .coverage import normalize_features
from .corpus import CorpusStore, Corpus
from .crashes import CrashStore
from .dictionary import (DictionaryToken, load_dictionary, tokens_from_records,
                         tokens_to_records)
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
    strategy_weights: dict[str, int] = field(default_factory=dict)
    cursor: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)
    crashes: int = 0
    unique_crashes: int = 0
    crash_ids: list[str] = field(default_factory=list)
    coverage_available: bool | None = None
    coverage_features: list[str] = field(default_factory=list)
    coverage_retained_shas: list[str] = field(default_factory=list)
    coverage_selection_counts: dict[str, int] = field(default_factory=dict)
    coverage_adapter_errors: int = 0
    abnormal_events: int = 0
    last_abnormal_detail: str = ""
    dictionary_source: str = ""
    value_profile: bool = False
    token_uses: int = 0
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
            "coverage": {
                "available": self.coverage_available,
                "unique_features": len(self.coverage_features),
                "features": list(self.coverage_features),
                "retained_inputs": len(self.coverage_retained_shas),
                "selection_counts": dict(self.coverage_selection_counts),
                "adapter_errors": self.coverage_adapter_errors,
            },
            "abnormal_events": self.abnormal_events,
            "last_abnormal_detail": self.last_abnormal_detail,
            "guidance": {
                "dictionary_source": self.dictionary_source,
                "value_profile": self.value_profile,
                "token_uses": self.token_uses,
            },
        }


class FuzzEngine:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.corpus_store = CorpusStore(workspace)
        self.crash_store = CrashStore(workspace)

    def _rel(self, session_id: str) -> str:
        return f"fuzz/{session_id}.json"

    def _dict_rel(self, session_id: str) -> str:
        return f"fuzz/{session_id}.dict.json"

    # persistence ---------------------------------------------------------
    def save(self, session: FuzzSession) -> None:
        session.updated_at = now_iso()
        self.ws.write_json(self._rel(session.id), session.to_dict())

    def get(self, session_id: str) -> FuzzSession:
        rel = self._rel(session_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"fuzz session '{session_id}' not found")
        return FuzzSession(**self.ws.read_json(rel))

    def tokens_for(self, session: FuzzSession) -> list[DictionaryToken] | None:
        """Load the persisted dictionary for a session, if it has one."""
        rel = self._dict_rel(session.id)
        if not self.ws.path(rel).exists():
            return None
        records = self.ws.read_json(rel).get("tokens", [])
        return tokens_from_records(records) or None

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
               duration_s: float | None,
               strategy_weights: dict[str, int] | None = None,
               dictionary_path: str | None = None,
               dictionary_tokens: list[DictionaryToken] | None = None,
               value_profile: bool = False) -> FuzzSession:
        now = now_iso()
        session_id = make_id("experiment", "fuzz", experiment_id, target,
                             corpus_id, str(seed), str(max_cases), now)
        session_id = "fz_" + session_id.split("_", 1)[1]
        # Snapshot the base set at creation so the run is deterministic and
        # resume-invariant: crashing inputs added mid-run do not change bases.
        corpus = self.corpus_store.get(corpus_id)
        base_shas = [tc["sha256"] for tc in corpus.testcases]
        tokens = list(dictionary_tokens or [])
        if dictionary_path and tokens:
            raise StateError(
                "pass either dictionary_path or dictionary_tokens, not both")
        if dictionary_path:
            tokens = load_dictionary(dictionary_path)  # validated eagerly
        session = FuzzSession(
            id=session_id, experiment_id=experiment_id, target=target,
            corpus_id=corpus_id, seed=seed, workers=workers,
            max_cases=max_cases, duration_s=duration_s,
            base_shas=base_shas,
            strategy_weights=dict(strategy_weights or {}),
            status=RUNNING, started_at=now, updated_at=now,
            outcomes={o: 0 for o in Outcome.ALL},
            dictionary_source=(dictionary_path
                               or (tokens[0].source if tokens else "")),
            value_profile=bool(value_profile),
        )
        if tokens:
            self.ws.write_json(self._dict_rel(session.id), {
                "schema": 1,
                "tokens": tokens_to_records(tokens),
            })
        self.save(session)
        return session

    def _bases(self, session: FuzzSession, corpus: Corpus) -> list[bytes]:
        bases = [self.corpus_store.read_bytes(corpus, sha)
                 for sha in session.base_shas]
        return bases or [DEFAULT_BASE]

    def _select_base(self, session: FuzzSession, corpus: Corpus,
                     fallback_bases: list[bytes], iteration: int) -> bytes:
        """Select a coverage corpus entry deterministically when available."""
        if session.coverage_available is not True:
            return fallback_bases[iteration % len(fallback_bases)]
        shas = list(dict.fromkeys(session.base_shas + session.coverage_retained_shas))
        if not shas:
            return fallback_bases[iteration % len(fallback_bases)]
        # Fair, stable power schedule: least selected, then smaller input,
        # then content hash.  It is fully persisted in the session, so a
        # pause/resume sequence selects exactly the same parents as one run.
        entries = {tc["sha256"]: tc for tc in corpus.testcases}
        available = [sha for sha in shas if sha in entries]
        if not available:
            return fallback_bases[iteration % len(fallback_bases)]
        sha = min(available, key=lambda value: (
            session.coverage_selection_counts.get(value, 0),
            entries[value]["size"], value))
        session.coverage_selection_counts[sha] = \
            session.coverage_selection_counts.get(sha, 0) + 1
        return self.corpus_store.read_bytes(corpus, sha)

    def _features(self, target, data: bytes, result, session: FuzzSession):
        """Read optional adapter features without changing target semantics."""
        try:
            features = normalize_features(target.coverage_features(data, result))
        except Exception:  # optional observability must not break a campaign
            session.coverage_adapter_errors += 1
            return None
        if features is None:
            return None
        session.coverage_available = True
        return features

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
        struct_fn = target.structure_mutate
        tokens = self.tokens_for(session)
        strategies: tuple[str, ...] = mutation.STRATEGIES
        if tokens:
            strategies = mutation.STRATEGIES + mutation.DICT_STRATEGIES
        # Precompute the weighted strategy pool once (invariant for the run).
        pool = mutation.weighted_strategies(session.strategy_weights or None,
                                            strategies)
        unique = set(session.crash_ids)
        executed_this = 0

        # Batched persistence: accumulate crash counts and corpus additions in
        # memory and flush once before returning, instead of writing per case.
        # This is behavior-preserving at the pause/resume/complete boundaries,
        # which all flush here.
        crash_counts: dict[str, int] = {}
        crash_first: dict[str, tuple] = {}   # crash_id -> (data, result, lineage)
        corpus_dirty = False

        while session.cursor < session.max_cases:
            if max_new is not None and executed_this >= max_new:
                session.status = PAUSED
                break
            if deadline is not None and time.monotonic() >= deadline:
                session.status = PAUSED
                break

            i = session.cursor
            base = self._select_base(session, corpus, bases, i)
            mutated, strategy = mutation.mutate(
                base, session.seed, i, struct_fn=struct_fn, strategies=pool,
                tokens=tokens)
            if strategy.startswith("dict_"):
                session.token_uses += 1
            result = target.execute(mutated)
            session.outcomes[result.outcome] = \
                session.outcomes.get(result.outcome, 0) + 1

            features = self._features(target, mutated, result, session)
            known_features = set(session.coverage_features)
            new_features = tuple(feature for feature in (features or ())
                                 if feature not in known_features)
            if new_features:
                session.coverage_features = sorted(known_features | set(new_features))
                sha = sha256_bytes(mutated)
                if sha not in session.coverage_retained_shas:
                    session.coverage_retained_shas.append(sha)
                if self.corpus_store.add_bytes(
                        corpus, mutated, origin="mutation",
                        parent=sha256_bytes(base), mutation=strategy,
                        seed=session.seed, iteration=i,
                        coverage_features=features,
                        coverage_new_features=new_features,
                        persist=False) is not None:
                    corpus_dirty = True

            if result.outcome == Outcome.ABNORMAL:
                # Harness/tooling failures are operational evidence, not a
                # confirmed vulnerability. Keep a bounded session summary and
                # never assign them a synthetic crash signature.
                session.abnormal_events += 1
                session.last_abnormal_detail = result.detail[:500]

            if result.outcome == Outcome.CRASH:
                signature = result.diagnostics.signature \
                    if result.diagnostics else "sig_none"
                crash_id = make_id("crash", session.experiment_id, signature)
                session.crashes += 1
                crash_counts[crash_id] = crash_counts.get(crash_id, 0) + 1
                if crash_id not in crash_first:
                    crash_first[crash_id] = (mutated, result, {
                        "parent_sha256": sha256_bytes(base),
                        "mutation": strategy, "seed": session.seed,
                        "iteration": i})
                if crash_id not in unique:
                    unique.add(crash_id)
                    session.crash_ids.append(crash_id)
                # Preserve the crashing input in the corpus with lineage; defer
                # the manifest write until the end of the batch.
                if self.corpus_store.add_bytes(
                        corpus, mutated, origin="mutation",
                        parent=sha256_bytes(base), mutation=strategy,
                        seed=session.seed, iteration=i, persist=False) is not None:
                    corpus_dirty = True

            session.cursor += 1
            executed_this += 1

        # Flush batched corpus + crash state.
        if corpus_dirty:
            self.corpus_store.save(corpus)
        self._flush_crashes(session, fmt, crash_counts, crash_first)

        if session.cursor >= session.max_cases:
            session.status = COMPLETED
        session.unique_crashes = len(session.crash_ids)
        self.save(session)
        return session

    def _flush_crashes(self, session: FuzzSession, fmt: str,
                       crash_counts: dict[str, int],
                       crash_first: dict[str, tuple]) -> None:
        """Persist accumulated crashes: record each unique crash once, then add
        its total occurrence count in a single write."""
        for crash_id, count in crash_counts.items():
            if self.ws.path(f"crashes/{crash_id}/crash.json").exists():
                self.crash_store.bump_count(
                    crash_id, count, experiment_id=session.experiment_id)
            else:
                data, result, lineage = crash_first[crash_id]
                self.crash_store.record(
                    experiment_id=session.experiment_id, target=session.target,
                    fmt=fmt, data=data, exec_result=result, lineage=lineage)
                if count > 1:
                    self.crash_store.bump_count(
                        crash_id, count - 1,
                        experiment_id=session.experiment_id)

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
