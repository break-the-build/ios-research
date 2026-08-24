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

import base64
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
from .errors import NotFoundError, StateError, ValidationError
from .hashing import sha256_bytes
from .ids import make_id
from .targets.base import Outcome
from .workspace import Workspace, validate_component

DEFAULT_BASE = b"MOCK" + bytes([1, 1]) + (2).to_bytes(2, "big") + b"ok"

# Hardening bound: mutated inputs larger than this are skipped (counted, never
# executed) so a runaway duplication-style mutation cannot exhaust memory on a
# real harness. Sessions persist the value, so resume behavior is identical.
DEFAULT_MAX_INPUT_BYTES = 1_048_576

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
    mutator_mode: str = ""
    proposer_id: str = ""
    llm_rounds: int = 0
    llm_budget: int = 0
    llm_rounds_done: int = 0
    llm_cases_used: int = 0
    llm_accepted: int = 0
    llm_rejected: int = 0
    llm_last_error: str = ""
    llm_queue: list[dict] = field(default_factory=list)
    max_input_bytes: int = 0
    skipped_oversize: int = 0
    sched_modes: tuple = ()
    sched_calls: int = 0
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
            "sanitizer_profile": self.sanitizer_profile,
            "mutator_plugin": {
                "path": self.mutator_plugin_path,
                "sha256": self.mutator_plugin_sha256,
                "grammar_uses": self.grammar_uses,
            },
            "llm_mutator": {
                "mode": self.mutator_mode,
                "proposer_id": self.proposer_id,
                "rounds_requested": self.llm_rounds,
                "rounds_done": self.llm_rounds_done,
                "budget": self.llm_budget,
                "cases_used": self.llm_cases_used,
                "accepted": self.llm_accepted,
                "rejected": self.llm_rejected,
                "last_error": self.llm_last_error,
            },
            "max_input_bytes": self.max_input_bytes,
            "skipped_oversize": self.skipped_oversize,
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
               duration_s: float | None,
               strategy_weights: dict[str, int] | None = None,
               dictionary_path: str | None = None,
               dictionary_tokens: list[DictionaryToken] | None = None,
               value_profile: bool = False,
               sanitizer_profile: str | None = None,
               mutator_plugin_path: str | None = None,
               max_input_bytes: int | None = None,
               sched_modes: tuple = (),
               mutator_mode: str = "",
               proposer_id: str = "",
               llm_rounds: int = 0,
               llm_budget: int = 0) -> FuzzSession:
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
        if mutator_mode:
            from .llmmutate import validate_budget
            if mutator_mode != "llm":
                raise ValidationError(
                    f"unknown mutator mode '{mutator_mode}'")
            if not proposer_id:
                raise ValidationError(
                    "mutator mode 'llm' requires a proposer identity")
            validate_budget(llm_rounds, llm_budget)
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
            sanitizer_profile=profile,
            mutator_plugin_path=str(mutator_plugin_path or ""),
            mutator_plugin_sha256=plugin_sha,
            mutator_mode=mutator_mode,
            proposer_id=proposer_id,
            llm_rounds=int(llm_rounds),
            llm_budget=int(llm_budget),
            max_input_bytes=(DEFAULT_MAX_INPUT_BYTES if max_input_bytes is None
                             else max(0, int(max_input_bytes))),
            sched_modes=tuple(sched_modes or ()),
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
                deadline: float | None = None,
                proposer=None) -> FuzzSession:
        """Execute cases from the current cursor until a stop condition.

        ``proposer`` (an optional :class:`~ios_research.llmmutate.Proposer`)
        drives LLM-in-the-loop rounds (#71); it is never persisted, so a
        resumed session drains its persisted proposal queue and falls back to
        generic mutation without any model attached.
        """
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
        # Grammar-aware mutator plugin (#41): loaded from a user-declared
        # path; every call is isolated and falls back to generic mutation.
        plugin_host = None
        if session.mutator_plugin_path:
            from .grammar import PluginHost
            plugin_host = PluginHost().discover([session.mutator_plugin_path])
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
            parent_sha: str | None = sha256_bytes(base)
            mutated = None
            strategy = ""
            if session.mutator_mode == "llm":
                picked = self._take_llm_input(
                    session, corpus, proposer, plugin_host, fmt,
                    crash_counts, crash_first)
                if picked is not None:
                    mutated, proposal_round = picked
                    strategy = f"llm:{session.proposer_id}@r{proposal_round}"
                    session.llm_cases_used += 1
                    parent_sha = None
                    # Every executed proposal is a provenance-tagged corpus
                    # entry so campaigns reproduce without the model (#71).
                    if self.corpus_store.add_bytes(
                            corpus, mutated, origin="llm", mutation=strategy,
                            seed=session.seed, iteration=i,
                            persist=False) is not None:
                        corpus_dirty = True
            if mutated is None and plugin_host is not None \
                    and plugin_host.plugins:
                rng = mutation.rng_for(session.seed, i)
                if len(bases) > 1 and i % 4 == 3:
                    outcome = plugin_host.crossover_bytes(
                        base, bases[(i + 1) % len(bases)], rng)
                else:
                    outcome = plugin_host.mutate_bytes(base, rng)
                if outcome is not None:
                    mutated, strategy = outcome
                    session.grammar_uses += 1
            if mutated is None:
                mutated, strategy = mutation.mutate(
                    base, session.seed, i, struct_fn=struct_fn,
                    strategies=pool, tokens=tokens)
            if strategy.startswith("dict_"):
                session.token_uses += 1
            if session.max_input_bytes and \
                    len(mutated) > session.max_input_bytes:
                # Hardening bound: never hand an oversized input to a target.
                # Skipping (rather than truncating) keeps executed inputs
                # byte-identical to an uncapped run's same-index executions.
                session.skipped_oversize += 1
                session.cursor += 1
                executed_this += 1
                continue
            self._perturb_target(target, session, i)
            result = target.execute(mutated)
            session.outcomes[result.outcome] = \
                session.outcomes.get(result.outcome, 0) + 1

            features = self._features(target, mutated, result, session)
            known_features = set(session.coverage_features)
            new_features = tuple(feature for feature in (features or ())
                                 if feature not in known_features)
            if new_features:
                session.coverage_features = sorted(known_features | set(new_features))
                session.cases_since_new_feature = 0
                sha = sha256_bytes(mutated)
                if sha not in session.coverage_retained_shas:
                    session.coverage_retained_shas.append(sha)
                if self.corpus_store.add_bytes(
                        corpus, mutated, origin="mutation",
                        parent=parent_sha, mutation=strategy,
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
                        "parent_sha256": parent_sha,
                        "mutation": strategy, "seed": session.seed,
                        "iteration": i})
                if crash_id not in unique:
                    unique.add(crash_id)
                    session.crash_ids.append(crash_id)
                # Preserve the crashing input in the corpus with lineage; defer
                # the manifest write until the end of the batch.
                if self.corpus_store.add_bytes(
                        corpus, mutated, origin="mutation",
                        parent=parent_sha, mutation=strategy,
                        seed=session.seed, iteration=i, persist=False) is not None:
                    corpus_dirty = True

            session.cursor += 1
            if features is not None:
                session.cases_since_new_feature += 1
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

    # LLM-in-the-loop rounds (#71) -----------------------------------------
    def _take_llm_input(self, session: FuzzSession, corpus: Corpus,
                        proposer, plugin_host, fmt: str,
                        crash_counts: dict[str, int],
                        crash_first: dict[str, tuple]) -> tuple[bytes, int] | None:
        """Pop the next validated model-proposed input, refilling on demand.

        Returns ``(data, round)`` or ``None`` when the budget is spent, the
        round budget is exhausted, or the queue is empty with no proposer
        attached (a resumed campaign finishes without any model).
        """
        if session.llm_cases_used >= session.llm_budget:
            return None
        if not session.llm_queue:
            if proposer is None or \
                    session.llm_rounds_done >= session.llm_rounds:
                return None
            self._refill_llm_queue(session, corpus, proposer, plugin_host,
                                   fmt, crash_counts, crash_first)
        if not session.llm_queue:
            return None
        entry = session.llm_queue.pop(0)
        return base64.b64decode(entry["d"]), entry["r"]

    def _refill_llm_queue(self, session: FuzzSession, corpus: Corpus,
                          proposer, plugin_host, fmt: str,
                          crash_counts: dict[str, int],
                          crash_first: dict[str, tuple]) -> None:
        """Run one proposal round; isolate failures and validate candidates.

        Candidates are size-bounded, format-repairable when a grammar plugin
        accepts them, and deduplicated against the corpus and pending queue.
        A proposer exception degrades to generic mutation for this iteration
        instead of aborting the campaign. Crashes from earlier in this batch
        are passed unflushed so they already steer the next round.
        """
        from . import llmmutate
        proposal_round = session.llm_rounds_done + 1
        remaining = session.llm_budget - session.llm_cases_used
        rounds_left = max(session.llm_rounds - proposal_round + 1, 1)
        per_round = min(-(-remaining // rounds_left),
                        llmmutate.MAX_PROPOSALS_PER_ROUND)
        context = self._llm_context(session, corpus, fmt,
                                    round_index=proposal_round,
                                    per_round=per_round,
                                    crash_counts=crash_counts,
                                    crash_first=crash_first)
        session.llm_rounds_done = proposal_round
        try:
            raw = list(proposer.propose(context))
        except Exception as exc:  # noqa: BLE001 - isolation boundary
            session.llm_last_error = f"round {proposal_round}: {exc}"[:300]
            return
        seen = set(corpus.shas)
        for entry in session.llm_queue:
            seen.add(entry["s"])
        accepted = rejected = 0
        for item in raw[:llmmutate.MAX_PROPOSALS_PER_ROUND]:
            checked = self._check_proposal(item, session, plugin_host, seen)
            if checked is None:
                rejected += 1
                continue
            blob, sha = checked
            seen.add(sha)
            if len(session.llm_queue) >= llmmutate.MAX_PROPOSALS_PER_ROUND:
                rejected += 1
                continue
            session.llm_queue.append(
                {"d": base64.b64encode(blob).decode("ascii"),
                 "r": proposal_round, "s": sha})
            accepted += 1
        session.llm_accepted += accepted
        session.llm_rejected += rejected

    @staticmethod
    def _check_proposal(item, session: FuzzSession, plugin_host,
                        seen: set[str]) -> tuple[bytes, str] | None:
        """Validate one raw candidate; ``None`` means rejected."""
        if not isinstance(item, (bytes, bytearray)):
            return None
        blob = bytes(item)
        if not blob:
            return None
        if session.max_input_bytes and len(blob) > session.max_input_bytes:
            return None
        if plugin_host is not None and plugin_host.plugins:
            repaired = plugin_host.repair_bytes(blob)
            if repaired is not None:
                blob = repaired
        if not blob:
            return None
        sha = sha256_bytes(blob)
        if sha in seen:
            return None
        return blob, sha

    def _llm_context(self, session: FuzzSession, corpus: Corpus, fmt: str,
                     *, round_index: int, per_round: int,
                     crash_counts: dict[str, int],
                     crash_first: dict[str, tuple]) -> dict:
        """Build the sanitized round context shipped to a proposer.

        Stored crashes and crashes pending in this batch are merged (pending
        wins), ordered deterministically by ``(last_seen, id)``, then the most
        recent few are redacted into bounded summaries.
        """
        from . import llmmutate
        origins: dict[str, int] = {}
        sizes: list[int] = []
        for tc in corpus.testcases:
            origin = tc.get("origin", "")
            origins[origin] = origins.get(origin, 0) + 1
            sizes.append(tc.get("size", 0))
        samples: list[str] = []
        for tc in corpus.testcases[:2]:
            try:
                data = self.corpus_store.read_bytes(corpus, tc["sha256"])
            except Exception:  # noqa: BLE001 - context must not fail a round
                continue
            samples.append(data[: llmmutate.MAX_SAMPLE_HEX // 2].hex())
        roots = [str(self.ws.root)]
        merged: dict[str, tuple[str, dict]] = {}
        for crash in self.crash_store.list(
                experiment_id=session.experiment_id):
            example = b""
            try:
                if crash.minimized_sha256:
                    example = self.crash_store.artifacts.get_bytes(
                        crash.minimized_sha256)
                else:
                    example = self.crash_store.input_bytes(crash)
            except Exception:  # noqa: BLE001 - few-shots are best-effort
                example = b""
            merged[crash.id] = (crash.last_seen, llmmutate.summarize_crash(
                crash_id=crash.id, signature=crash.signature,
                classification=crash.classification, detail=crash.detail,
                count=crash.count, input_sha256=crash.input_sha256,
                example_bytes=example, roots=roots))
        for crash_id, (data, result, _lineage) in crash_first.items():
            diag = result.diagnostics
            merged[crash_id] = ("", llmmutate.summarize_crash(
                crash_id=crash_id,
                signature=diag.signature if diag else "sig_none",
                classification=diag.classification_hint if diag else "UNKNOWN",
                detail=result.detail,
                count=crash_counts.get(crash_id, 1),
                input_sha256=sha256_bytes(data),
                example_bytes=data, roots=roots))
        ordered = sorted(merged.items(), key=lambda kv: (kv[1][0], kv[0]))
        return {
            "schema": llmmutate.CONTEXT_SCHEMA_VERSION,
            "round": round_index,
            "target": session.target,
            "format": fmt,
            "seed": session.seed,
            "corpus": {
                "id": corpus.id,
                "entries": len(corpus.testcases),
                "origins": dict(sorted(origins.items())),
                "mean_size": sum(sizes) // len(sizes) if sizes else 0,
                "sample_hex": samples,
            },
            "budget": {"remaining": session.llm_budget
                       - session.llm_cases_used,
                       "per_round_hint": per_round},
            "crashes": [entry[1][1]
                        for entry in
                        ordered[-llmmutate.MAX_FEEDBACK_CRASHES:]],
        }

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
               deadline: float | None = None,
               proposer=None) -> FuzzSession:
        if session.status == COMPLETED:
            raise StateError(f"fuzz session '{session.id}' already completed")
        if session.status == STOPPED:
            raise StateError(f"fuzz session '{session.id}' was stopped")
        return self.advance(session, max_new=max_new, deadline=deadline,
                            proposer=proposer)

    def pause(self, session: FuzzSession) -> FuzzSession:
        if session.status == RUNNING or session.status == PAUSED:
            session.status = PAUSED
            self.save(session)
        return session

    def stop(self, session: FuzzSession) -> FuzzSession:
        session.status = STOPPED
        self.save(session)
        return session
