"""End-to-end research orchestration.

A research run drives the full pipeline — environment discovery, target
selection, corpus validation/mutation, fuzzing, crash detection, deduplication,
minimization, reproduction, root-cause analysis, and differential testing — and
produces a research summary. State is persisted after every stage so an
interrupted run resumes from where it stopped.

Resource controls (max runtime/workers/storage/testcases) bound every run.
Running is a destructive/resource-consuming operation and requires explicit
researcher confirmation at the CLI layer.
"""

from __future__ import annotations

import platform
import time
from dataclasses import dataclass, field, asdict
from typing import Any

from . import targets
from .analysis import Analyzer
from .clock import now_iso
from .corpus import CorpusStore
from .crashes import CrashStore
from .devices import get as get_device
from .differential import DifferentialEngine
from .experiment import ExperimentStore
from .fuzz import FuzzEngine, DEFAULT_BASE
from .ids import make_id
from .parallel import TRIAGE_MINIMIZE_LOCK, map_ordered
from .triage import Triage
from .workspace import Workspace

# Ordered pipeline stages.
STAGES = (
    "discover_environment", "select_target", "validate_corpus", "mutate_corpus",
    "fuzz", "detect_crashes", "deduplicate", "minimize", "reproduce",
    "analyze", "differential_test", "summarize",
)

CREATED, RUNNING, PAUSED, COMPLETED, BLOCKED = \
    "created", "running", "paused", "completed", "blocked"

# Differential partners for targets that have a second "version".
_DIFF_PARTNERS = {"mock:parser": "mock:parser-v2"}

# Cap application happens at use sites, not here: triage fan-out and the
# fuzz-stage worker record both cap max_workers at 6 (#200/#209), and the
# fuzz engine itself executes serially today, so a recorded worker count is
# configuration provenance until the executor work lands (#199).
DEFAULT_LIMITS = {
    "max_runtime_seconds": 600,
    "max_workers": 8,
    "max_storage_mb": 1024,
    "max_testcases": 100000,
}


@dataclass
class ResearchRun:
    id: str
    name: str
    target: str
    seed: int
    max_cases: int
    limits: dict[str, Any]
    created_at: str
    status: str = CREATED
    cursor: int = 0
    stages: list[dict] = field(default_factory=list)
    refs: dict[str, Any] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _dir_size_mb(path) -> float:
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            total += p.stat().st_size
    return total / (1024 * 1024)


class ResearchOrchestrator:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def _rel(self, run_id: str) -> str:
        return f"research/{run_id}.json"

    # lifecycle -----------------------------------------------------------
    def create(self, *, name: str, target: str, seed: int, max_cases: int,
               limits: dict | None = None) -> ResearchRun:
        if not targets.is_registered(target):
            from .errors import UsageError
            raise UsageError(f"unknown target '{target}'")
        merged = dict(DEFAULT_LIMITS)
        merged.update(limits or {})
        run_id = make_id("research", name, target, str(seed), str(max_cases))
        run = ResearchRun(
            id=run_id, name=name, target=target, seed=seed,
            max_cases=min(max_cases, merged["max_testcases"]),
            limits=merged, created_at=now_iso(),
            stages=[{"name": s, "status": "pending", "note": ""}
                    for s in STAGES])
        self.save(run)
        return run

    def save(self, run: ResearchRun) -> None:
        run.updated_at = now_iso()
        self.ws.write_json(self._rel(run.id), run.to_dict())

    def get(self, run_id: str) -> ResearchRun:
        rel = self._rel(run_id)
        if not self.ws.path(rel).exists():
            from .errors import NotFoundError
            raise NotFoundError(f"research run '{run_id}' not found")
        return ResearchRun(**self.ws.read_json(rel))

    def list(self) -> list[ResearchRun]:
        return [ResearchRun(**d) for d in self.ws.list_json("research")]

    def latest(self) -> "ResearchRun | None":
        runs = self.list()
        return sorted(runs, key=lambda r: r.updated_at)[-1] if runs else None

    # control -------------------------------------------------------------
    def pause(self, run: ResearchRun) -> ResearchRun:
        if run.status in (RUNNING, CREATED, PAUSED):
            run.status = PAUSED
            self.save(run)
        return run

    def run(self, run: ResearchRun, *, max_stages: int | None = None,
            resume: bool = False) -> ResearchRun:
        if run.status == COMPLETED:
            return run
        run.status = RUNNING
        deadline = time.monotonic() + run.limits["max_runtime_seconds"]
        executed = 0

        while run.cursor < len(STAGES):
            if max_stages is not None and executed >= max_stages:
                run.status = PAUSED
                break
            if time.monotonic() >= deadline:
                self._mark(run, "timed out (max_runtime_seconds)")
                run.status = BLOCKED
                break
            # Storage guard before the expensive fuzz stage.
            if STAGES[run.cursor] == "fuzz":
                used = _dir_size_mb(self.ws.root)
                if used > run.limits["max_storage_mb"]:
                    self._mark(run, f"storage limit exceeded ({used:.1f} MB)")
                    run.status = BLOCKED
                    break

            stage = STAGES[run.cursor]
            note = getattr(self, f"_stage_{stage}")(run)
            run.stages[run.cursor] = {"name": stage, "status": "done",
                                      "note": note}
            run.cursor += 1
            executed += 1
            self.save(run)

        if run.cursor >= len(STAGES):
            run.status = COMPLETED
        self.save(run)
        return run

    def _mark(self, run: ResearchRun, note: str) -> None:
        run.stages[run.cursor] = {"name": STAGES[run.cursor],
                                  "status": "blocked", "note": note}
        self.save(run)

    def _workers(self, run: ResearchRun) -> int:
        """Effective stage fan-out width (#200): capped pool, never < 1."""
        return max(1, min(int(run.limits.get("max_workers", 1)), 6))

    # stages --------------------------------------------------------------
    def _stage_discover_environment(self, run: ResearchRun) -> str:
        run.refs["environment"] = {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "targets": [t["id"] for t in targets.list_targets()],
        }
        return f"{len(run.refs['environment']['targets'])} targets available"

    def _stage_select_target(self, run: ResearchRun) -> str:
        target = targets.create(run.target)
        run.refs["target"] = target.describe()
        run.refs["diff_partner"] = _DIFF_PARTNERS.get(run.target)
        return f"selected {run.target}"

    def _stage_validate_corpus(self, run: ResearchRun) -> str:
        store = CorpusStore(self.ws)
        name = f"research-{run.id}"
        corpus = store.create(name, target=run.target)
        for s in (targets.create(run.target).seeds() or [DEFAULT_BASE]):
            store.add_bytes(corpus, s, origin="seed")
        run.refs["corpus_id"] = corpus.id
        return f"corpus {corpus.id} with {len(corpus.testcases)} seed(s)"

    def _stage_mutate_corpus(self, run: ResearchRun) -> str:
        # Mutation happens within fuzzing; record the intended strategy set.
        from .mutation import STRATEGIES
        run.refs["mutation_strategies"] = list(STRATEGIES)
        return f"{len(STRATEGIES)} mutation strategies enabled"

    def _stage_fuzz(self, run: ResearchRun) -> str:
        cfg_hash = "cfg_research"
        device = get_device("mock:device")
        exp = ExperimentStore(self.ws).create(
            target=run.target, device=device.id, os_version=device.os_version,
            config_hash=cfg_hash, seed=run.seed,
            params={"driver": "research", "run_id": run.id})
        engine = FuzzEngine(self.ws)
        # Record the configured fan-out honestly (#209) instead of silently
        # clamping to 1: same cap policy as triage fan-out (_workers). The
        # engine currently executes serially regardless of this value, so it
        # is provenance — it reflects configuration intent, matching the
        # field's documented purpose — until the executor work lands (#199).
        effective = self._workers(run)
        from .config import Config
        session = engine.create(experiment_id=exp.id, target=run.target,
                                corpus_id=run.refs["corpus_id"], seed=run.seed,
                                workers=effective, max_cases=run.max_cases,
                                duration_s=None,
                                strategy_weights=Config().get("fuzz.strategy_weights"))
        session = engine.advance(session)
        run.refs["experiment_id"] = exp.id
        run.refs["fuzz_session_id"] = session.id
        run.refs["crash_ids"] = list(session.crash_ids)
        run.stats["fuzz_workers"] = effective
        run.stats["testcases_generated"] = session.cursor
        run.stats["outcomes"] = session.stats()["outcomes"]
        return f"{session.cursor} cases, {session.unique_crashes} unique crashes"

    def _stage_detect_crashes(self, run: ResearchRun) -> str:
        crash_ids = run.refs.get("crash_ids", [])
        run.stats["crashes_found"] = crash_ids
        return f"{len(crash_ids)} crash record(s)"

    def _stage_deduplicate(self, run: ResearchRun) -> str:
        # Crashes are deduped by signature at record time.
        run.stats["unique_crashes"] = len(run.refs.get("crash_ids", []))
        return f"{run.stats['unique_crashes']} unique after signature dedup"

    def _stage_minimize(self, run: ResearchRun) -> str:
        workers = self._workers(run)

        def minimize_one(cid: str) -> bool:
            # Fresh instances per item; the regression-corpus tail of
            # minimize is serialized process-wide (see parallel.py).
            triage = Triage(self.ws)
            with TRIAGE_MINIMIZE_LOCK:
                result = triage.minimize(triage.crashes.get(cid),
                                         workers=workers)
            return bool(result.get("minimized"))

        results = map_ordered(minimize_one, run.refs.get("crash_ids", []),
                              workers)
        minimized = sum(1 for ok in results if ok)
        run.stats["minimized_crashes"] = minimized
        return f"minimized {minimized} crash input(s)"

    def _stage_reproduce(self, run: ResearchRun) -> str:
        workers = self._workers(run)

        def reproduce_one(cid: str) -> bool:
            triage = Triage(self.ws)
            return triage.reproduce(triage.crashes.get(cid))["reproduced"]

        results = map_ordered(reproduce_one, run.refs.get("crash_ids", []),
                              workers)
        reproduced = sum(1 for ok in results if ok)
        run.stats["reproducible_crashes"] = reproduced
        return f"{reproduced} reproducible crash(es)"

    def _stage_analyze(self, run: ResearchRun) -> str:
        workers = self._workers(run)

        def analyze_one(cid: str):
            analyzer = Analyzer(self.ws)
            crash = CrashStore(self.ws).get(cid)
            return analyzer.analyze(crash)

        results = map_ordered(analyze_one, run.refs.get("crash_ids", []),
                              workers)
        analysis_ids = [a.id for a in results]
        memsafety = sum(
            1 for a in results
            if a.memory_safety_classification in (
                "spatial", "temporal", "type-confusion"))
        run.refs["analysis_ids"] = analysis_ids
        run.stats["memory_safety_issues"] = memsafety
        return f"analyzed {len(analysis_ids)}; {memsafety} memory-safety issue(s)"

    def _stage_differential_test(self, run: ResearchRun) -> str:
        partner = run.refs.get("diff_partner")
        if not partner:
            return "no differential partner for this target; skipped"
        engine = DifferentialEngine(self.ws)
        diff = engine.create(name=f"research-{run.id}", target_a=run.target,
                             target_b=partner, config_hash="cfg_research",
                             seed=run.seed)
        summary = engine.run(diff)
        run.refs["diff_id"] = diff.id
        run.stats["differential_findings"] = summary
        return (f"{summary['differing']} differing, "
                f"{summary['regressions']} regression(s)")

    def _stage_summarize(self, run: ResearchRun) -> str:
        run.refs["summary"] = self.summarize(run)
        return "summary generated"

    # summary -------------------------------------------------------------
    def summarize(self, run: ResearchRun) -> dict[str, Any]:
        stats = run.stats
        diff = stats.get("differential_findings", {})
        next_steps = self._recommendations(run)
        return {
            "research_id": run.id,
            "target": run.target,
            "status": run.status,
            "experiments_performed": 1 if run.refs.get("experiment_id") else 0,
            "targets_tested": [run.target]
            + ([run.refs["diff_partner"]] if run.refs.get("diff_partner") else []),
            "testcases_generated": stats.get("testcases_generated", 0),
            "crashes_found": len(stats.get("crashes_found", [])),
            "unique_crashes": stats.get("unique_crashes", 0),
            "reproducible_crashes": stats.get("reproducible_crashes", 0),
            "minimized_crashes": stats.get("minimized_crashes", 0),
            "potential_memory_safety_issues": stats.get("memory_safety_issues", 0),
            "differential_findings": {
                "differing": diff.get("differing", 0),
                "regressions": diff.get("regressions", 0)},
            "recommended_next_steps": next_steps,
        }

    def _recommendations(self, run: ResearchRun) -> list[str]:
        steps = []
        if run.stats.get("memory_safety_issues", 0):
            steps.append("Confirm attacker-control of faulting addresses for "
                         "memory-safety crashes via further authorized research.")
        if run.stats.get("unique_crashes", 0):
            steps.append("Generate responsible-disclosure reports "
                         "(ios-research report create <crash-id>).")
        diff = run.stats.get("differential_findings", {})
        if diff.get("regressions"):
            steps.append("Investigate differential regressions between versions.")
        steps.append("Expand the corpus and increase max-cases for deeper coverage.")
        return steps
