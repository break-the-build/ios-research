"""#200: ordered thread-pooled triage fan-out.

Covers the ``map_ordered`` primitive, ordered-output equivalence of every
fanned-out pipeline site between ``workers=1`` and ``workers=N``, exception
propagation parity, CLI/schema exposure of ``agent run --workers``, and a
generous wall-clock speedup smoke test against a sleeping stub target.
"""

from __future__ import annotations

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
            diag = diagnostics.build(data, "OUT_OF_BOUNDS_READ",
                                     f"StubParser_{data.hex()}", ["parse"])
            return ExecResult(outcome=Outcome.CRASH, detail="stub crash",
                              duration_ms=25, diagnostics=diag)
        return ExecResult(outcome=Outcome.REJECTED, detail="no", duration_ms=25)


class ExplodingStub(SlowCrashStub):
    """Same stub, but execute always raises (exception-parity check)."""

    def _run(self, data: bytes) -> ExecResult:
        raise RuntimeError("stub target exploded")


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
    runs = []
    for workers in (1, 4):
        ws = _fresh_workspace(tmp_path, f"research-w{workers}")
        orch = ResearchOrchestrator(ws)
        run = orch.create(name="r", target="mock:parser", seed=1,
                          max_cases=200,
                          limits={"max_workers": workers})
        run = orch.run(run)
        assert run.status == COMPLETED
        runs.append((orch, run))
        assert len(run.refs.get("crash_ids", [])) >= 2
    (o1, r1), (o2, r2) = runs
    assert r1.stats == r2.stats
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
def test_analyze_batch_fanout_is_faster_than_serial(tmp_path):
    timings = {}
    for workers in (1, 4):
        ws = _fresh_workspace(tmp_path, f"speed-w{workers}")
        _record_slow_crashes(ws, 6)
        analyzer = Analyzer(ws)
        start = time.perf_counter()
        out = analyzer.analyze_batch(workers=workers)
        timings[workers] = time.perf_counter() - start
        assert len(out) == 6
    # Each item sleeps ~25ms inside execute (GIL released); 6 items with 4
    # workers overlap heavily. Generous margin to stay flake-free.
    assert timings[4] < timings[1] * 0.75, timings


# --- CLI / schema exposure -----------------------------------------------------
def test_agent_run_schema_exposes_workers():
    schema = build_cli_schema()
    run_cmd = schema["commands"]["agent"]["subcommands"]["run"]
    options = run_cmd["arguments"]["options"]
    workers = [o for o in options if "--workers" in o["flags"]]
    assert len(workers) == 1
    assert workers[0]["dest"] == "workers"
    assert workers[0]["required"] is False
