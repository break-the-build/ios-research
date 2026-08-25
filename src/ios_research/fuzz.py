"""Fuzzing engine: deterministic, resumable mutation-based fuzzing.

The engine drives a target through many mutated inputs, records normalized
outcomes, and persists crashes (deduplicated by signature). Sessions are
persisted so they can be paused and resumed. Execution is fully deterministic
for a given ``(seed, corpus)`` — the reference engine runs sequentially and
records ``workers`` as metadata.

Parallel execution contract (#199)
----------------------------------
With ``--workers``/``--window`` greater than one the engine fans case
executions out to a thread pool over generation windows. The run stays a pure
function of ``(seed, window)``: mutation is derived per case index and
reduction happens strictly in index order on the calling thread, so the same
seed and window produce an identical case sequence and identical final state
regardless of thread scheduling. Coverage feedback observes session state as
of the start of the current generation window — feedback lag is at most
``window - 1`` cases (zero at ``window == 1``), so non-coverage targets
produce byte-identical sequences at every window width, while coverage-guided
targets legitimately observe slightly staler state than the serial loop.
Resume equivalence holds given identical settings: pausing between windows —
including mid-window via ``max_new``, since windows are never dispatched past
the remaining case budget — yields the same state and downstream sequence as
an uninterrupted run.

The engine persists confirmed crashes and reports abnormal harness behavior
separately. It never generates exploit payloads.
"""

from __future__ import annotations

import time
from pathlib import Path
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
from .executors import SerialExecutor, ThreadedBatchExecutor, MAX_WORKERS
from .hashing import sha256_bytes
from .ids import make_id
from .targets.base import Outcome
from .workspace import Workspace, validate_component

DEFAULT_BASE = b"MOCK" + bytes([1, 1]) + (2).to_bytes(2, "big") + b"ok"

# Hardening bound: mutated inputs larger than this are skipped (counted, never
# executed) so a runaway duplication-style mutation cannot exhaust memory on a
# real harness. Sessions persist the value, so resume behavior is identical.
DEFAULT_MAX_INPUT_BYTES = 1_048_576


def adapted_weights(current: dict[str, int], stats: dict[str, dict],
                    *, floor: int = 1, cap: int = 64,
                    max_factor: float = 2.0) -> dict[str, int]:
    """Bounded multiplicative strategy reweighting from yield stats (#203).

    ``stats`` maps strategy -> {"executions": int, "features": int} measured
    over the just-finished window. Each weight moves toward strategies whose
    novel-feature rate beats the overall rate, clamped to ``[floor, cap]`` and
    to a per-checkpoint factor of ``[1/max_factor, max_factor]`` so no single
    checkpoint can collapse exploration or explode a weight. Strategies with
    no measurements keep their current weight.
    """
    total_exec = sum(v.get("executions", 0) for v in stats.values())
    total_feat = sum(v.get("features", 0) for v in stats.values())
    if total_exec <= 0:
        return dict(current)
    overall_rate = total_feat / total_exec
    out: dict[str, int] = {}
    for strat, weight in current.items():
        w = max(0, int(weight))
        entry = stats.get(strat)
        if not entry or not entry.get("executions"):
            out[strat] = w or floor
            continue
        rate = entry.get("features", 0) / entry["executions"]
        scaled = (rate / overall_rate) if overall_rate > 0 else 1.0
        scaled = min(max_factor, max(1.0 / max_factor, scaled))
        out[strat] = max(floor, min(cap, int(round(w * scaled))))
    return out


def focus_phase_index(cursor: int, phase_len: int, count: int) -> int:
    """Deterministic focus-symbol rotation for multi-focus sessions (#205).

    The active symbol advances every ``phase_len`` executed cases; with a
    single symbol (or ``phase_len`` <= 0) the index is always 0.
    """
    if count <= 1 or phase_len <= 0:
        return 0
    return (max(0, cursor) // phase_len) % count


def checkpoint_due(*, pending: bool, cases_since_flush: int, elapsed_s: float,
                   checkpoint_cases: int, checkpoint_seconds: float) -> bool:
    """Whether a periodic checkpoint should flush right now (#208).

    A checkpoint only fires when there IS unflushed state. Either threshold
    triggers it; a value of ``0`` disables that mechanism entirely.
    """
    if not pending:
        return False
    if checkpoint_cases and cases_since_flush >= checkpoint_cases:
        return True
    if checkpoint_seconds and elapsed_s >= checkpoint_seconds:
        return True
    return False

RUNNING = "running"
PAUSED = "paused"
STOPPED = "stopped"
COMPLETED = "completed"


def _session_from_dict(data: dict) -> "FuzzSession":
    """Build a session from persisted JSON with a stable error on drift.

    A raw ``FuzzSession(**data)`` would surface schema drift or a corrupted
    record as ``TypeError``; raise :class:`StateError` instead so agents get a
    stable exit code and an actionable message.
    """
    try:
        return FuzzSession(**data)
    except TypeError:
        raise StateError(
            "fuzz session record is corrupt or from an incompatible version",
            details={"keys": sorted(data)}) from None


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
    window: int = 1
    checkpoint_cases: int = 256
    checkpoint_seconds: float = 30.0
    skip_duplicates: bool = False
    skipped_duplicate: int = 0
    seen_input_shas: list[str] = field(default_factory=list)
    adapt_strategies: bool = False
    strategy_adapt_every: int = 512
    cases_since_adapt: int = 0
    strategy_yield: dict = field(default_factory=dict)
    focus_symbols: list[str] = field(default_factory=list)
    focus_phase_len: int = 512
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
    sanitizer_profile: str = ""
    cases_since_new_feature: int = 0
    mutator_plugin_path: str = ""
    mutator_plugin_sha256: str = ""
    grammar_uses: int = 0
    max_input_bytes: int = 0
    skipped_oversize: int = 0
    sched_modes: tuple = ()
    sched_calls: int = 0
    llm_proposal_file: str = ""
    llm_budget: int = 0
    llm_cursor: int = 0
    llm_round: int = 0
    llm_stats: dict = field(default_factory=dict)
    focus_symbol: str = ""
    focus_distances: dict = field(default_factory=dict)
    focus_entry_distances: dict = field(default_factory=dict)
    focus_counts: dict = field(default_factory=dict)
    focus_biased: int = 0
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
            "workers": self.workers,
            "window": self.window,
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
            "focus": {
                "symbol": self.focus_symbol,
                "targets_reachable": sum(
                    1 for d in self.focus_distances.values() if d == 0),
                "biased_selections": self.focus_biased,
                "selection_counts": dict(self.focus_counts),
            } if self.focus_symbol else {},
            "sanitizer_profile": self.sanitizer_profile,
            "mutator_plugin": {
                "path": self.mutator_plugin_path,
                "sha256": self.mutator_plugin_sha256,
                "grammar_uses": self.grammar_uses,
            },
            "max_input_bytes": self.max_input_bytes,
            "skipped_oversize": self.skipped_oversize,
            "skipped_duplicate": self.skipped_duplicate,
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
        validate_component(session_id, what="fuzz session id")
        rel = self._rel(session_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"fuzz session '{session_id}' not found")
        return _session_from_dict(self.ws.read_json(rel))

    def tokens_for(self, session: FuzzSession) -> list[DictionaryToken] | None:
        """Load the persisted dictionary for a session, if it has one."""
        rel = self._dict_rel(session.id)
        if not self.ws.path(rel).exists():
            return None
        records = self.ws.read_json(rel).get("tokens", [])
        return tokens_from_records(records) or None

    def list(self) -> list[FuzzSession]:
        return [_session_from_dict(d) for d in self.ws.list_json("fuzz")]

    def latest(self) -> FuzzSession | None:
        sessions = self.list()
        if not sessions:
            return None
        return sorted(sessions, key=lambda s: s.updated_at)[-1]

    # lifecycle -----------------------------------------------------------
    def create(self, *, experiment_id: str, target: str, corpus_id: str,
               seed: int, workers: int, max_cases: int,
               duration_s: float | None, window: int | None = None,
               checkpoint_cases: int | None = None,
               checkpoint_seconds: float | None = None,
               skip_duplicates: bool = False,
               adapt_strategies: bool = False,
               strategy_adapt_every: int | None = None,
               focus_symbols: list[str] | None = None,
               focus_phase_len: int | None = None,
               strategy_weights: dict[str, int] | None = None,
               dictionary_path: str | None = None,
               dictionary_tokens: list[DictionaryToken] | None = None,
               value_profile: bool = False,
               sanitizer_profile: str | None = None,
               mutator_plugin_path: str | None = None,
               max_input_bytes: int | None = None,
               sched_modes: tuple = (),
               llm_proposal_file: str = "",
               llm_budget: int = 0,
               focus_symbol: str = "") -> FuzzSession:
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
        profile = ""
        if sanitizer_profile:
            from .sanitizers import validate_profile
            import sys
            check = validate_profile(
                sanitizer_profile,
                platform="darwin" if sys.platform == "darwin" else "linux")
            if not check["supported"]:
                raise StateError(
                    f"sanitizer profile '{sanitizer_profile}' is not usable: "
                    f"{check['reason']}",
                    details={"profile": sanitizer_profile})
            profile = sanitizer_profile
        # Plugin provenance: record the file hash so runs are auditable.
        # Loading a plugin executes its Python (user-declared, trusted input).
        plugin_sha = ""
        plugin_file = Path(mutator_plugin_path) if mutator_plugin_path \
            else None
        if plugin_file is not None and plugin_file.is_file():
            plugin_sha = sha256_bytes(plugin_file.read_bytes())
        elif plugin_file is not None:
            raise StateError(
                f"mutator plugin path does not exist: {mutator_plugin_path}",
                details={"path": str(mutator_plugin_path)})
        if sched_modes:
            from .races import validate_modes
            sched_modes = validate_modes(sched_modes)
        if bool(llm_proposal_file) != (llm_budget > 0):
            raise StateError(
                "llm mutation requires both --llm-proposals and a positive "
                "--llm-budget",
                details={"llm_proposal_file": llm_proposal_file,
                         "llm_budget": llm_budget})
        llm_stats: dict = {}
        if llm_proposal_file:
            from .llmmutate import empty_stats
            llm_stats = empty_stats()
        session = FuzzSession(
            id=session_id, experiment_id=experiment_id, target=target,
            corpus_id=corpus_id, seed=seed, workers=workers,
            max_cases=max_cases, duration_s=duration_s,
            window=(max(1, int(window)) if window is not None else 1),
            checkpoint_cases=(256 if checkpoint_cases is None
                              else max(0, int(checkpoint_cases))),
            checkpoint_seconds=(30.0 if checkpoint_seconds is None
                                else max(0.0, float(checkpoint_seconds))),
            skip_duplicates=bool(skip_duplicates),
            adapt_strategies=bool(adapt_strategies),
            strategy_adapt_every=(512 if strategy_adapt_every is None
                                  else max(1, int(strategy_adapt_every))),
            focus_symbols=[str(x) for x in (focus_symbols or []) if str(x)],
            focus_phase_len=(512 if focus_phase_len is None
                             else max(1, int(focus_phase_len))),
            base_shas=base_shas,
            strategy_weights=dict(strategy_weights or {}),
            status=RUNNING, started_at=now, updated_at=now,
            outcomes={o: 0 for o in Outcome.ALL},
            dictionary_source=(dictionary_path
                               or (tokens[0].source if tokens else "")),
            value_profile=bool(value_profile),
            sanitizer_profile=profile,
            mutator_plugin_path=str(mutator_plugin_path or ""),
            mutator_plugin_sha256=plugin_sha,
            max_input_bytes=(DEFAULT_MAX_INPUT_BYTES if max_input_bytes is None
                             else max(0, int(max_input_bytes))),
            sched_modes=tuple(sched_modes or ()),
            llm_proposal_file=str(llm_proposal_file),
            llm_budget=int(llm_budget),
            llm_stats=llm_stats,
            focus_symbol=str(focus_symbol or ""),
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

    def _ensure_focus_distances(self, session: FuzzSession, target) -> None:
        """One-time distance computation for directed scheduling (#73).

        Requires the target's optional ``callgraph`` hook; without it (or with
        an empty result) focus stays recorded but scheduling is unchanged.
        """
        if not session.focus_symbol or session.focus_distances:
            return
        graph_doc = getattr(target, "callgraph", None)
        if not callable(graph_doc):
            return
        try:
            doc = graph_doc()
            if not doc:
                return
            from .directed import load_callgraph, target_distances
            graph = load_callgraph(doc)
            session.focus_distances = target_distances(
                graph, {session.focus_symbol})
        except Exception:  # optional guidance must never break a campaign
            session.focus_distances = {}

    def _focus_tables(self, session: FuzzSession, target) -> dict:
        """Per-symbol distance tables for multi-focus rotation (#205).

        Computed fresh at advance() start — pure function of the target's
        callgraph, so resume determinism never depends on persisting them.
        Empty when the target lacks a usable callgraph hook.
        """
        graph_doc = getattr(target, "callgraph", None)
        if not callable(graph_doc):
            return {}
        try:
            doc = graph_doc()
            if not doc:
                return {}
            from .directed import load_callgraph, target_distances
            graph = load_callgraph(doc)
            return {symbol: target_distances(graph, {symbol})
                    for symbol in session.focus_symbols}
        except Exception:  # optional guidance must never break a campaign
            return {}

    def _focus_entry_distances(self, session: FuzzSession,
                               pairs: list[tuple[str, bytes]], target) -> dict:
        """Map corpus entries to call-graph distances via the target hook.

        The target's optional ``focus_symbol_for(data)`` says which modeled
        symbol an input exercises; combined with symbol-level distances this
        yields per-input weights. Results are cached on the session (by input
        sha) so pause/resume reproduces identical scheduling.
        """
        cached = session.focus_entry_distances
        symbol_for = getattr(target, "focus_symbol_for", None)
        for sha, data in pairs:
            if sha in cached:
                continue
            distance = None
            if callable(symbol_for):
                try:
                    symbol = symbol_for(data)
                except Exception:
                    symbol = None
                if symbol is not None:
                    distance = session.focus_distances.get(symbol)
            cached[sha] = distance
        return cached

    def _cached_input_bytes(self, corpus: Corpus, sha: str,
                            cache: dict[str, bytes] | None) -> bytes:
        """Corpus input bytes, served through the per-advance cache (#198).

        On a miss the bytes are read from disk once and memoized for the rest
        of the ``advance()`` call; the cache is never shared across calls, so
        nothing can go stale across pause/resume boundaries.
        """
        if cache is None:
            return self.corpus_store.read_bytes(corpus, sha)
        data = cache.get(sha)
        if data is None:
            data = self.corpus_store.read_bytes(corpus, sha)
            cache[sha] = data
        return data

    def _select_base(self, session: FuzzSession, corpus: Corpus,
                     fallback_bases: list[bytes], iteration: int,
                     target=None, *,
                     bytes_by_sha: dict[str, bytes] | None = None,
                     entries_index: dict[str, dict] | None = None,
                     fallback_shas: list[str] | None = None,
                     focus_distances_override: dict | None = None) -> bytes:
        """Select a coverage corpus entry deterministically when available.

        ``bytes_by_sha``, ``entries_index``, and ``fallback_shas`` are optional
        per-advance scheduling caches (#198) owned by the caller; when omitted
        (direct callers, tests) each is computed locally with identical
        results.
        """
        distances = (focus_distances_override
                     if focus_distances_override is not None
                     else session.focus_distances)
        if distances and fallback_bases:
            # Directed scheduling applies on both the coverage and fallback
            # paths (#73): weight each candidate by the distance of the
            # symbol its input exercises (via the target hook).
            from .directed import selection_weight, weighted_selection
            pairs: list[tuple[str, bytes]] = []
            seen = set()
            if fallback_shas is None:
                fallback_shas = [sha256_bytes(data) for data in fallback_bases]
            for sha, data in zip(fallback_shas, fallback_bases):
                if sha not in seen:
                    seen.add(sha)
                    pairs.append((sha, data))
            if session.coverage_available is True:
                entries = entries_index if entries_index is not None else {
                    tc["sha256"]: tc for tc in corpus.testcases}
                for sha in session.base_shas + session.coverage_retained_shas:
                    if sha in entries and sha not in seen:
                        seen.add(sha)
                        pairs.append((sha, self._cached_input_bytes(
                            corpus, sha, bytes_by_sha)))
            if focus_distances_override is not None:
                # Multi-focus (#205): per-symbol tables make the persisted
                # sha->distance cache ambiguous, so map fresh per window.
                symbol_for = getattr(target, "focus_symbol_for", None)
                entry_distances = {}
                for sha, data in pairs:
                    distance = None
                    if callable(symbol_for):
                        try:
                            symbol = symbol_for(data)
                        except Exception:
                            symbol = None
                        if symbol is not None:
                            distance = distances.get(symbol)
                    entry_distances[sha] = distance
            else:
                entry_distances = self._focus_entry_distances(session, pairs,
                                                              target)
            candidates = [(sha, entry_distances.get(sha)) for sha, _ in pairs]
            sha = weighted_selection(candidates, session.focus_counts)
            session.focus_counts[sha] = \
                session.focus_counts.get(sha, 0) + 1
            if selection_weight(entry_distances.get(sha)) > 1:
                session.focus_biased += 1
            # Honor the pick even when it resolves to a coverage-retained
            # entry (#196): ``pairs`` already carries those bytes from disk,
            # so mutating a different base here would silently discard the
            # scheduled selection.
            by_sha = {candidate_sha: data for candidate_sha, data in pairs}
            picked = by_sha.get(sha)
            if picked is not None:
                return picked
            return fallback_bases[iteration % len(fallback_bases)]
        if session.coverage_available is not True:
            return fallback_bases[iteration % len(fallback_bases)]
        shas = list(dict.fromkeys(session.base_shas + session.coverage_retained_shas))
        if not shas:
            return fallback_bases[iteration % len(fallback_bases)]
        # Fair, stable power schedule: least selected, then smaller input,
        # then content hash.  It is fully persisted in the session, so a
        # pause/resume sequence selects exactly the same parents as one run.
        entries = entries_index if entries_index is not None else {
            tc["sha256"]: tc for tc in corpus.testcases}
        available = [sha for sha in shas if sha in entries]
        if not available:
            return fallback_bases[iteration % len(fallback_bases)]
        sha = min(available, key=lambda value: (
            session.coverage_selection_counts.get(value, 0),
            entries[value]["size"], value))
        session.coverage_selection_counts[sha] = \
            session.coverage_selection_counts.get(sha, 0) + 1
        return self._cached_input_bytes(corpus, sha, bytes_by_sha)

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
        # Per-advance scheduling caches (#198): strictly scoped to this call
        # (seeded here, discarded on return) so resume behavior is unchanged
        # while per-case selection avoids repeated disk reads, hashing, and
        # manifest scans.
        bytes_by_sha: dict[str, bytes] = {}
        fallback_shas = [sha256_bytes(data) for data in bases]
        for sha, data in zip(fallback_shas, bases):
            if sha not in bytes_by_sha:
                bytes_by_sha[sha] = data
        entries_index = {tc["sha256"]: tc for tc in corpus.testcases}
        known_feature_set = set(session.coverage_features)
        target = targets.create(session.target)
        fmt = target.formats[0] if target.formats else target.kind
        struct_fn = target.structure_mutate
        self._ensure_focus_distances(session, target)
        focus_tables: dict = {}
        if session.focus_symbols:
            focus_tables = self._focus_tables(session, target)
        tokens = self.tokens_for(session)
        strategies: tuple[str, ...] = mutation.STRATEGIES
        if tokens:
            strategies = mutation.STRATEGIES + mutation.DICT_STRATEGIES
        # Weighted strategy pool (#203): recomputed when online adaptation
        # reweights session.strategy_weights at checkpoints; otherwise
        # computed once (invariant for the run).
        strategies_key = tuple(strategies)
        pool = mutation.weighted_strategies(session.strategy_weights or None,
                                            strategies)
        pool_set = set(pool)

        def _recount_pool() -> None:
            nonlocal pool, pool_set
            pool = mutation.weighted_strategies(
                session.strategy_weights or None, strategies_key)
            pool_set = set(pool)
        # Grammar-aware mutator plugin (#41): loaded from a user-declared
        # path; every call is isolated and falls back to generic mutation.
        plugin_host = None
        if session.mutator_plugin_path:
            from .grammar import PluginHost
            plugin_host = PluginHost().discover([session.mutator_plugin_path])
        unique = set(session.crash_ids)
        crashes_before = len(session.crash_ids)
        executed_this = 0

        # LLM-in-the-loop mutation (#71): proposals replace mutation for a
        # bounded number of cases. The raw line cursor makes the stream
        # resumable; proposals are untrusted data (hex bytes only).
        llm_active = bool(session.llm_proposal_file) and \
            session.llm_budget > 0
        llm_iter = None
        llm_exhausted = False
        if llm_active:
            from .llmmutate import FileProposalSource
            session.llm_round += 1
            source = FileProposalSource(session.llm_proposal_file)
            llm_iter = source.proposals_from(session.llm_cursor)

        # Batched persistence: accumulate crash counts and corpus additions in
        # memory and flush once before returning, instead of writing per case.
        # This is behavior-preserving at the pause/resume/complete boundaries,
        # which all flush here.
        crash_counts: dict[str, int] = {}
        crash_first: dict[str, tuple] = {}   # crash_id -> (data, result, lineage)
        corpus_dirty = False

        # Periodic checkpoints (#208): flush the batched accumulators mid-run
        # so a killed long run keeps its crash discoveries. Thresholds come
        # from the session; 0 disables a mechanism. Early flushes reuse the
        # exact end-of-call path and reset the accumulators, so records are
        # identical and nothing double-counts.
        ckpt_cases = int(session.checkpoint_cases)
        ckpt_seconds = float(session.checkpoint_seconds)
        cases_since_flush = 0
        last_flush_at = time.monotonic()

        def _checkpoint_due() -> bool:
            return checkpoint_due(
                pending=bool(crash_counts) or corpus_dirty,
                cases_since_flush=cases_since_flush,
                elapsed_s=time.monotonic() - last_flush_at,
                checkpoint_cases=ckpt_cases,
                checkpoint_seconds=ckpt_seconds)

        # Windowed generate -> execute -> reduce (#207/#199). A session with
        # workers=1 and window=1 keeps the serial executor and single-case
        # windows: byte-identical to the original strictly serial loop.
        # Otherwise executions fan out to a thread pool and generation widens
        # to a window of cases so the pool has work to overlap; an explicit
        # window setting wins over the worker count, falling back to it
        # (bounded at 64). Generation and reduction always stay on this
        # thread in index order, so session state evolves identically.
        workers_count = max(1, int(getattr(session, "workers", 1) or 1))
        window_setting = max(1, int(getattr(session, "window", 1) or 1))
        if workers_count > 1 or window_setting > 1:
            executor = ThreadedBatchExecutor(
                target, max(1, min(workers_count, MAX_WORKERS)))
        else:
            executor = SerialExecutor(target)
        window_size = max(1, min(
            (window_setting if window_setting > 1 else workers_count), 64))

        # Duplicate-input skip (#204): opt-in via the session flag. The seen
        # set seeds from persisted shas so resume reproduces identical skip
        # decisions; appends happen at generation time in case order.
        seen_inputs: set[str] = set(session.seen_input_shas)

        # Online strategy adaptation state (#203): windowed per-strategy yield
        # measured only while enabled; deterministic given the same settings.
        if session.adapt_strategies and not session.strategy_yield:
            session.strategy_yield = {}

        while session.cursor < session.max_cases:
            if max_new is not None and executed_this >= max_new:
                session.status = PAUSED
                break
            if deadline is not None and time.monotonic() >= deadline:
                session.status = PAUSED
                break
            # Never dispatch a window past the remaining case budget (#199):
            # the final window may be partial, but never oversized, so pause/
            # resume stays exact at the boundaries.
            budget = session.max_cases - session.cursor
            if max_new is not None:
                budget = min(budget, max_new - executed_this)

            # Multi-focus rotation (#205): the active symbol advances every
            # focus_phase_len executed cases; selection within this window
            # uses that symbol's distance table.
            active_focus = None
            if focus_tables:
                symbol = session.focus_symbols[focus_phase_index(
                    session.cursor, session.focus_phase_len,
                    len(session.focus_symbols))]
                active_focus = focus_tables.get(symbol)

            # --- generation (serial, index order) --------------------------
            # Each entry carries its generation context so reduction can apply
            # the existing bookkeeping verbatim: (index, base, input, strategy,
            # llm_note). Oversize skips are resolved HERE — counted and charged
            # to the budget, they never occupy an executor slot (#199).
            pending: list[tuple[int, bytes, bytes, str, str]] = []
            skipped = 0
            i = session.cursor
            for _ in range(max(0, min(window_size, budget))):
                base = self._select_base(session, corpus, bases, i, target,
                                         bytes_by_sha=bytes_by_sha,
                                         entries_index=entries_index,
                                         fallback_shas=fallback_shas,
                                         focus_distances_override=active_focus)
                mutated = None
                strategy = ""
                llm_note = ""
                if llm_active and not llm_exhausted and \
                        session.llm_stats["proposals_used"] < session.llm_budget:
                    from .llmmutate import (validate_proposal_bytes,
                                            repair_with_target)
                    try:
                        next_line, proposal = next(llm_iter)  # type: ignore[union-attr]
                    except StopIteration:
                        llm_exhausted = True
                    else:
                        session.llm_cursor = next_line
                        if proposal is None:
                            session.llm_stats["proposals_invalid"] += 1
                        else:
                            decoded = validate_proposal_bytes(proposal.data)
                            if decoded is None:
                                session.llm_stats["proposals_invalid"] += 1
                            else:
                                mutated = repair_with_target(decoded, target)
                                strategy = "llm-proposal"
                                llm_note = proposal.note
                                session.llm_stats["proposals_used"] += 1
                if mutated is None and llm_active:
                    session.llm_stats["fallback_iterations"] += 1
                if plugin_host is not None and plugin_host.plugins:
                    rng = mutation.rng_for(session.seed, i)
                    if len(bases) > 1 and i % 4 == 3:
                        plugin_outcome = plugin_host.crossover_bytes(
                            base, bases[(i + 1) % len(bases)], rng)
                    else:
                        plugin_outcome = plugin_host.mutate_bytes(base, rng)
                    if plugin_outcome is not None:
                        mutated, strategy = plugin_outcome
                        session.grammar_uses += 1
                if mutated is None:
                    mutated, strategy = mutation.mutate(
                        base, session.seed, i, struct_fn=struct_fn,
                        strategies=pool, tokens=tokens)
                if strategy.startswith("dict_"):
                    session.token_uses += 1
                if session.max_input_bytes and \
                        len(mutated) > session.max_input_bytes:
                    # Hardening bound: never hand an oversized input to a
                    # target. Skipping (rather than truncating) keeps executed
                    # inputs byte-identical to an uncapped run's same-index
                    # executions.
                    session.skipped_oversize += 1
                    skipped += 1
                    i += 1
                    continue
                if session.skip_duplicates:
                    # Never execute the same input twice within a session
                    # (#204). Checked after the oversize bound so an oversized
                    # candidate is accounted as oversize, not as a duplicate.
                    input_sha = sha256_bytes(mutated)
                    if input_sha in seen_inputs:
                        session.skipped_duplicate += 1
                        skipped += 1
                        i += 1
                        continue
                    seen_inputs.add(input_sha)
                    session.seen_input_shas.append(input_sha)
                if session.adapt_strategies and strategy in pool_set:
                    entry = session.strategy_yield.setdefault(
                        strategy, {"executions": 0, "features": 0})
                    entry["executions"] += 1
                self._perturb_target(target, session, i)
                pending.append((i, base, mutated, strategy, llm_note))
                i += 1

            # --- execution (index-keyed results, order preserved) ----------
            results = executor.run(
                [(index, data) for index, _, data, _, _ in pending])
            if len(results) != len(pending):  # pragma: no cover - contract guard
                raise StateError("executor returned the wrong number of results")

            # --- reduction (STRICTLY in index order) ------------------------
            for (index, base, mutated, strategy, llm_note), \
                    (result_index, result) in zip(pending, results):
                if result_index != index:  # pragma: no cover - contract guard
                    raise StateError(
                        "executor returned out-of-order results",
                        details={"expected": index, "got": result_index})
                session.outcomes[result.outcome] = \
                    session.outcomes.get(result.outcome, 0) + 1

                features = self._features(target, mutated, result, session)
                new_features = tuple(feature for feature in (features or ())
                                     if feature not in known_feature_set)
                if new_features:
                    known_feature_set.update(new_features)
                    if session.adapt_strategies and strategy in pool_set:
                        entry = session.strategy_yield.setdefault(
                            strategy, {"executions": 0, "features": 0})
                        entry["features"] += 1
                    session.coverage_features = sorted(known_feature_set)
                    session.cases_since_new_feature = 0
                    sha = sha256_bytes(mutated)
                    if sha not in session.coverage_retained_shas:
                        session.coverage_retained_shas.append(sha)
                        bytes_by_sha.setdefault(sha, mutated)
                    added = self.corpus_store.add_bytes(
                            corpus, mutated, origin="mutation",
                            parent=sha256_bytes(base), mutation=strategy,
                            seed=session.seed, iteration=index,
                            coverage_features=features,
                            coverage_new_features=new_features,
                            persist=False)
                    if added is not None:
                        corpus_dirty = True
                        # Keep the selection index fresh so the new entry is
                        # selectable on the very next case of this advance().
                        entries_index[added.sha256] = added.to_dict()

                if result.outcome == Outcome.ABNORMAL:
                    # Harness/tooling failures are operational evidence, not a
                    # confirmed vulnerability. Keep a bounded session summary and
                    # never assign them a synthetic crash signature.
                    session.abnormal_events += 1
                    session.last_abnormal_detail = result.detail[:500]

                if result.outcome == Outcome.CRASH:
                    parent_sha = sha256_bytes(base)
                    signature = result.diagnostics.signature \
                        if result.diagnostics else "sig_none"
                    crash_id = make_id("crash", session.experiment_id, signature)
                    session.crashes += 1
                    crash_counts[crash_id] = crash_counts.get(crash_id, 0) + 1
                    if crash_id not in crash_first:
                        crash_first[crash_id] = (mutated, result, {
                            "parent_sha256": parent_sha,
                            "mutation": strategy, "seed": session.seed,
                            "iteration": index,
                            **({"origin": "llm-proposal",
                                "round": session.llm_round, "note": llm_note}
                               if strategy == "llm-proposal" else {})})
                    if crash_id not in unique:
                        unique.add(crash_id)
                        session.crash_ids.append(crash_id)
                    # Preserve the crashing input in the corpus with lineage; defer
                    # the manifest write until the end of the batch.
                    added = self.corpus_store.add_bytes(
                            corpus, mutated, origin="mutation",
                            parent=parent_sha, mutation=strategy,
                            seed=session.seed, iteration=index, persist=False)
                    if added is not None:
                        corpus_dirty = True
                        bytes_by_sha.setdefault(sha256_bytes(mutated), mutated)
                        entries_index[added.sha256] = added.to_dict()
                if features is not None:
                    session.cases_since_new_feature += 1

            consumed = len(pending) + skipped
            session.cursor += consumed
            executed_this += consumed
            cases_since_flush += consumed

            # Strategy adaptation checkpoint (#203): bounded multiplicative
            # reweighting from this window's measured yield; floors keep every
            # strategy alive. Disabled sessions never enter this branch.
            if session.adapt_strategies:
                session.cases_since_adapt += consumed
                if session.cases_since_adapt >= session.strategy_adapt_every                         and any(v.get("executions") for v in
                                session.strategy_yield.values()):
                    session.strategy_weights = adapted_weights(
                        session.strategy_weights, session.strategy_yield)
                    _recount_pool()
                    session.strategy_yield = {}
                    session.cases_since_adapt = 0

            # Periodic checkpoint (#208): identical writes to the end-of-call
            # flush, then reset accumulators so the final flush cannot
            # double-count.
            if _checkpoint_due():
                if corpus_dirty:
                    self.corpus_store.save(corpus)
                    corpus_dirty = False
                self._flush_crashes(session, fmt, crash_counts, crash_first)
                crash_counts.clear()
                crash_first.clear()
                cases_since_flush = 0
                last_flush_at = time.monotonic()

        # Flush batched corpus + crash state.
        if corpus_dirty:
            self.corpus_store.save(corpus)
        self._flush_crashes(session, fmt, crash_counts, crash_first)

        # Crash-aware round feedback (#71): summarize new signatures so the
        # next proposal-generation round can be conditioned on them.
        if llm_active:
            new_sigs = session.crash_ids[crashes_before:]
            if new_sigs:
                from .llmmutate import summarize_round
                rounds = session.llm_stats.setdefault("rounds", [])
                rounds.append(summarize_round(session.llm_round, new_sigs))
                session.llm_stats["rounds"] = rounds[-20:]

        if session.cursor >= session.max_cases:
            session.status = COMPLETED
        session.unique_crashes = len(session.crash_ids)
        self.save(session)
        return session

    def _perturb_target(self, target, session: FuzzSession,
                        iteration: int) -> None:
        """Apply the session's scheduling-perturbation schedule, if any.

        Deterministic: the mode for case ``i`` is ``sched_modes[i % len]``.
        Targets without an optional ``perturb`` hook (and sessions without
        modes) are untouched; a failing perturbation never breaks a campaign
        and is not counted.
        """
        modes = session.sched_modes
        if not modes:
            return
        perturb = getattr(target, "perturb", None)
        if not callable(perturb):
            return
        try:
            perturb(modes[iteration % len(modes)], iteration)
        except Exception:
            return
        session.sched_calls += 1

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
