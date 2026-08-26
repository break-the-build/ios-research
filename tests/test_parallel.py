"""#200: ordered thread-pooled triage fan-out.

Covers the ``map_ordered`` primitive, ordered-output equivalence of every
fanned-out pipeline site between ``workers=1`` and ``workers=N``, exception
propagation parity, CLI/schema exposure of ``agent run --workers``, and a
deterministic concurrency-overlap probe against a sleeping stub target
(#274: peak-parallelism instrumentation instead of wall-clock ratios).
"""

from __future__ import annotations

import threading
import time

import pytest

from ios_research import __version__, targets as tgt
from ios_research.agent import Agent
from ios_research.analysis import Analyzer
from ios_research.context import Context
from ios_research.crashes import CrashStore
from ios_research.parallel import map_ordered
from ios_research.research import ResearchOrchestrator, COMPLETED
from ios_research.schema import build_cli_schema
from ios_research.targets import ExecResult, Outcome, Target, diagnostics
from ios_research.triage import Triage
from ios_research.workspace import Workspace


def _fresh_workspace(tmp_path, name) -> Workspace:
    ws = Workspace(tmp_path / name / ".ios-research")
    ws.init(framework_version=__version__, created_at="t")
    return ws


class _ResearchBareStub(Target):
    """Adapter-less deterministic target: worker-count-invariant streams.

    #199 makes the research fuzz stage honor configured workers, and with a
    coverage-guided target different worker counts legitimately explore in a
    different order (coverage feedback lag). This stub has no coverage
    adapter, so the exact-equality assertions in the equivalence test below
    keep their meaning for any worker count.
    """

    target_id = "test:research-bare"
    kind = "parser"
    description = "deterministic two-signature crash rule, no coverage hook"
    formats = ("bin",)

    def seeds(self):
        return [b"R\x00\x01"]

    def _run(self, data):
        ff = data.count(b"\xff")
        if ff >= 2:
            d = diagnostics.build(data, "NULL_DEREFERENCE", "TestMod",
                                  ["sym_a"])
            return ExecResult(outcome=Outcome.CRASH, detail="c1",
                              diagnostics=d)
        if ff == 1:
            d = diagnostics.build(data, "OUT_OF_BOUNDS_READ", "TestMod",
                                  ["sym_b"])
            return ExecResult(outcome=Outcome.CRASH, detail="c2",
                              diagnostics=d)
        return ExecResult(outcome=Outcome.REJECTED, detail="rej")


@pytest.fixture(autouse=True)
def _unregister_research_bare_stub():
    yield
    tgt._REGISTRY.pop(_ResearchBareStub.target_id, None)


# --- map_ordered unit behavior ----------------------------------------------
def test_map_ordered_single_and_empty_and_serial_paths():
    calls: list[int] = []

    def rec(x):
        calls.append(x)
        return x * 2

    assert map_ordered(rec, [], workers=1) == []
    assert map_ordered(rec, [1, 2, 3], workers=1) == [2, 4, 6]
    # workers<=1 must be the plain comprehension: strictly sequential.
    assert calls == [1, 2, 3]
    single_calls: list[int] = []
    assert map_ordered(lambda x: single_calls.append(x) or x * 2,
                       [3], workers=8) == [6]
    assert single_calls == [3]
    assert map_ordered(rec, [1, 2, 3], workers=0) == [2, 4, 6]


def test_map_ordered_parallel_preserves_input_order():
    # Later items finish first; output must still be in input order.
    items = list(range(8))

    def slow_descending(x):
        time.sleep(0.001 * (len(items) - x))
        return x * 10

    assert map_ordered(slow_descending, items, workers=4) == \
        [x * 10 for x in items]


def test_map_ordered_raises_same_type_in_both_modes():
    items = [1, 2, 3, 4]

    def boom(x):
        if x == 3:
            raise ValueError(f"bad item {x}")
        return x

    with pytest.raises(ValueError, match="bad item 3"):
        map_ordered(boom, items, workers=1)
    with pytest.raises(ValueError, match="bad item 3"):
        map_ordered(boom, items, workers=4)


# --- stub targets ------------------------------------------------------------
STUB_ID = "stub:fanout"


class SlowCrashStub(Target):
    """Deterministic crashing stub whose execute costs ~25ms (#200 smoke)."""

    target_id = STUB_ID
    kind = "parser"
    description = "test-only slow crashing stub"
    formats = ("stub-record",)
    mock = True

    def _run(self, data: bytes) -> ExecResult:
        time.sleep(0.025)
        if len(data) >= 4 and data[:4] == b"MOCK":
            # Symbols feed the diagnostic SIGNATURE (classification + symbols),
            # so they must vary per input: since #264 the record id is
            # (target, signature)-global and constant signatures would collapse
            # these fixtures into one shared record per workspace.
            diag = diagnostics.build(data, "OUT_OF_BOUNDS_READ",
                                     f"StubParser_{data.hex()}",
                                     [f"parse_{data.hex()}"])
            return ExecResult(outcome=Outcome.CRASH, detail="stub crash",
                              duration_ms=25, diagnostics=diag)
        return ExecResult(outcome=Outcome.REJECTED, detail="no", duration_ms=25)


class ExplodingStub(SlowCrashStub):
    """Same stub, but execute always raises (exception-parity check)."""

    def _run(self, data: bytes) -> ExecResult:
        raise RuntimeError("stub target exploded")


PROBE_ID = "stub:overlap-probe"


class OverlapProbeStub(SlowCrashStub):
    """Sleeping crash stub that records peak concurrent ``_run`` entries.

    #274: fan-out is verified by observing actual overlap (class-level peak
    concurrency while every worker sits inside a CPU-free sleep), not by
    comparing wall-clock durations, which inverted under runner load.
    Instances are created per reproduce call, hence the class-level counter.
    """

    target_id = PROBE_ID

    _lock = threading.Lock()
    _active = 0
    peak = 0

    def _run(self, data: bytes) -> ExecResult:
        with type(self)._lock:
            type(self)._active += 1
            type(self).peak = max(type(self).peak, type(self)._active)
        try:
            return super()._run(data)
        finally:
            with type(self)._lock:
                type(self)._active -= 1


@pytest.fixture(autouse=True)
def _unregister_probe_target():
    yield
    tgt._REGISTRY.pop(PROBE_ID, None)


@pytest.fixture(autouse=True)
def _unregister_stub_target():
    """Keep the stub out of the global registry (suite pollution guard,
    same pattern as tests/test_directed.py)."""
    yield
    tgt._REGISTRY.pop(STUB_ID, None)


def _record_slow_crashes(ws, count: int) -> list[str]:
    tgt.register(STUB_ID, lambda: SlowCrashStub())
    store = CrashStore(ws)
    ids = []
    for i in range(count):
        data = b"MOCK" + bytes([i]) * 12
        res = tgt.create(STUB_ID).execute(data)
        assert res.outcome == Outcome.CRASH
        ids.append(store.record(experiment_id=f"exp-{i}", target=STUB_ID,
                                fmt="stub-record", data=data,
                                exec_result=res).id)
    return ids


# --- Agent.run equivalence ----------------------------------------------------
def test_agent_run_workers_equivalence(tmp_path):
    results = []
    for i, workers in enumerate((1, 4)):
        ws = _fresh_workspace(tmp_path, f"agent-w{workers}")
        res = Agent(Context(workspace_path=str(ws.root))).run(
            target="mock:parser", seed=1, max_cases=200, workers=workers)
        assert res["unique_crashes"] >= 2  # multi-crash fixture sanity
        results.append(res)
    # Identical experiment/session/crash ids, stats, summaries AND order.
    assert results[0] == results[1]


def test_agent_run_serial_default_is_unchanged(tmp_path):
    ws = _fresh_workspace(tmp_path, "agent-default")
    res = Agent(Context(workspace_path=str(ws.root))).run(
        target="mock:parser", seed=1, max_cases=200)
    assert res["unique_crashes"] >= 2
    assert [c["crash_id"] for c in res["crashes"]] != []
    for c in res["crashes"]:
        assert set(c) == {"crash_id", "classification", "indicator",
                          "confidence"}


# --- research stages equivalence ---------------------------------------------
def test_research_stages_workers_equivalence(tmp_path):
    tgt.register(_ResearchBareStub.target_id, lambda: _ResearchBareStub())
    runs = []
    for workers in (1, 4):
        ws = _fresh_workspace(tmp_path, f"research-w{workers}")
        orch = ResearchOrchestrator(ws)
        run = orch.create(name="r", target=_ResearchBareStub.target_id,
                          seed=1, max_cases=200,
                          limits={"max_workers": workers})
        run = orch.run(run)
        assert run.status == COMPLETED
        runs.append((orch, run))
        assert len(run.refs.get("crash_ids", [])) >= 2
    (o1, r1), (o2, r2) = runs
    # fuzz_workers records configured concurrency (#209), not a result, and
    # therefore legitimately differs between the two configurations above.
    def result_stats(stats):
        return {k: v for k, v in stats.items() if k != "fuzz_workers"}
    assert result_stats(r1.stats) == result_stats(r2.stats)
    assert r1.refs["crash_ids"] == r2.refs["crash_ids"]
    # analysis_ids stay in crash-id order for any worker count.
    assert r1.refs["analysis_ids"] == r2.refs["analysis_ids"]
    assert [s["note"] for s in r1.stages] == [s["note"] for s in r2.stages]
    assert o1.summarize(r1) == o2.summarize(r2)


def test_research_worker_cap_is_applied(tmp_path):
    ws = _fresh_workspace(tmp_path, "research-cap")
    orch = ResearchOrchestrator(ws)
    run = orch.create(name="r", target="mock:parser", seed=1, max_cases=200,
                      limits={"max_workers": 64})
    assert orch._workers(run) == 6          # documented cap
    run = orch.run(run)
    assert run.status == COMPLETED


# --- analyze_batch -------------------------------------------------------------
def test_analyze_batch_order_identical_across_workers(tmp_path):
    ids_by_mode = {}
    analyses_by_mode = {}
    for workers in (1, 4):
        ws = _fresh_workspace(tmp_path, f"batch-w{workers}")
        recorded = _record_slow_crashes(ws, 5)
        out = Analyzer(ws).analyze_batch(workers=workers)
        # Store (sorted-id) order, identical to the serial comprehension.
        assert sorted(a.crash_id for a in out) == sorted(recorded)
        ids_by_mode[workers] = [a.id for a in out]
        analyses_by_mode[workers] = [a.to_dict() for a in out]
    assert ids_by_mode[1] == ids_by_mode[4]
    assert analyses_by_mode[1] == analyses_by_mode[4]


def test_analyze_batch_exception_parity_between_modes(tmp_path):
    for workers in (1, 4):
        ws = _fresh_workspace(tmp_path, f"boom-w{workers}")
        _record_slow_crashes(ws, 3)
        # Swap the registry entry: reproduce now raises mid-batch.
        tgt.register(STUB_ID, lambda: ExplodingStub())
        with pytest.raises(RuntimeError, match="stub target exploded"):
            Analyzer(ws).analyze_batch(workers=workers)


# --- speedup smoke -------------------------------------------------------------
def test_analyze_batch_fanout_actually_overlaps_executions(tmp_path):
    # #274: assert fan-out via observed peak concurrency, not wall-clock
    # ratios. Each item spends ~25ms inside a CPU-free sleep, so with 4
    # workers the pool is guaranteed to hold >1 in-flight _run at once,
    # regardless of machine load.
    tgt.register(PROBE_ID, lambda: OverlapProbeStub())
    for workers, expected_min_peak in ((4, 2), (1, 1)):
        ws = _fresh_workspace(tmp_path, f"overlap-w{workers}")
        store = CrashStore(ws)
        for i in range(6):
            data = b"MOCK" + bytes([i]) * 12
            res = tgt.create(PROBE_ID).execute(data)
            assert res.outcome == Outcome.CRASH
            store.record(experiment_id=f"exp-{i}", target=PROBE_ID,
                         fmt="stub-record", data=data, exec_result=res)
        OverlapProbeStub.peak = 0
        out = Analyzer(ws).analyze_batch(workers=workers)
        assert len(out) == 6
        assert OverlapProbeStub.peak >= expected_min_peak, (
            workers, OverlapProbeStub.peak)


# --- CLI / schema exposure -----------------------------------------------------
def test_agent_run_schema_exposes_workers():
    schema = build_cli_schema()
    run_cmd = schema["commands"]["agent"]["subcommands"]["run"]
    options = run_cmd["arguments"]["options"]
    workers = [o for o in options if "--workers" in o["flags"]]
    assert len(workers) == 1
    assert workers[0]["dest"] == "workers"
    assert workers[0]["required"] is False
