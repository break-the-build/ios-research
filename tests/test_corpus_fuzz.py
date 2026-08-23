"""Phase 02 tests: corpus management, mutation, and the fuzz engine."""

from __future__ import annotations

import pytest

from ios_research import mutation
from ios_research.corpus import CorpusStore
from ios_research.crashes import CrashStore
from ios_research.fuzz import FuzzEngine, DEFAULT_BASE, COMPLETED, PAUSED
from ios_research.experiment import ExperimentStore
from ios_research.targets import create
from ios_research.targets.base import Outcome


# --- mutation determinism -------------------------------------------------
@pytest.mark.parametrize("strategy_fn", [
    mutation.mutate_byte, mutation.mutate_truncation, mutation.mutate_insertion,
    mutation.mutate_deletion, mutation.mutate_boundary, mutation.mutate_integer,
    mutation.mutate_structure_aware,
])
def test_mutators_are_deterministic(strategy_fn):
    a = strategy_fn(DEFAULT_BASE, mutation.rng_for(7, 3))
    b = strategy_fn(DEFAULT_BASE, mutation.rng_for(7, 3))
    assert a == b
    assert isinstance(a, bytes)


def test_mutate_dispatch_is_reproducible():
    for i in range(50):
        m1, s1 = mutation.mutate(DEFAULT_BASE, 42, i)
        m2, s2 = mutation.mutate(DEFAULT_BASE, 42, i)
        assert m1 == m2 and s1 == s2


def test_mutators_handle_empty_input():
    for fn in mutation._DISPATCH.values():
        assert isinstance(fn(b"", mutation.rng_for(1, 1)), bytes)


# --- corpus ---------------------------------------------------------------
def test_corpus_create_add_dedupe(workspace):
    store = CorpusStore(workspace)
    corpus = store.create("c1")
    assert store.add_bytes(corpus, b"aaa", origin="seed") is not None
    assert store.add_bytes(corpus, b"aaa", origin="seed") is None  # dedup on add
    store.add_bytes(corpus, b"bbb", origin="seed", dedupe=False)
    store.add_bytes(corpus, b"bbb", origin="seed", dedupe=False)
    removed = store.dedupe(corpus)
    assert removed == 1
    assert len(store.get(corpus.id).testcases) == 2


def test_corpus_minimize_keeps_one_per_behavior(workspace):
    store = CorpusStore(workspace)
    corpus = store.create("c2")
    # Two inputs that both cleanly reject collapse to one behavior.
    store.add_bytes(corpus, b"zzzz", origin="seed")
    store.add_bytes(corpus, b"yyyy", origin="seed")
    # One accepted, one OOB-read crash: distinct behaviors.
    store.add_bytes(corpus, DEFAULT_BASE, origin="seed")
    store.add_bytes(corpus, b"MOCK\x01\x01\xff\xff", origin="seed")
    stats = store.minimize(corpus, create("mock:parser"))
    assert stats["kept"] == stats["behaviors"]
    assert stats["removed"] >= 1


def test_corpus_import_directory(workspace, tmp_path):
    store = CorpusStore(workspace)
    corpus = store.create("c3")
    d = tmp_path / "seeds"
    d.mkdir()
    (d / "a.bin").write_bytes(b"one")
    (d / "b.bin").write_bytes(b"two")
    added = store.import_path(corpus, d)
    assert added == 2


# --- crash store ----------------------------------------------------------
def test_crash_store_dedupes_by_signature(workspace):
    store = CrashStore(workspace)
    target = create("mock:parser")
    data = b"MOCK\x01\xff\x00\x00"  # null-dispatch crash
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    c1 = store.record(experiment_id="exp1", target="mock:parser",
                      fmt="mock-record", data=data, exec_result=res)
    c2 = store.record(experiment_id="exp1", target="mock:parser",
                      fmt="mock-record", data=data, exec_result=res)
    assert c1.id == c2.id
    assert store.get(c1.id).count == 2
    assert len(store.list()) == 1


def test_crash_store_isolated_by_workspace_and_experiment(tmp_path):
    """Records from one workspace/experiment are never visible in another."""
    from ios_research import __version__
    from ios_research.errors import ValidationError
    from ios_research.workspace import Workspace

    ws_a = Workspace(tmp_path / "a" / ".ios-research")
    ws_b = Workspace(tmp_path / "b" / ".ios-research")
    ws_a.init(framework_version=__version__, created_at="t")
    ws_b.init(framework_version=__version__, created_at="t")
    result = create("mock:parser").execute(b"MOCK\x01\xff\x00\x00")
    store_a = CrashStore(ws_a)
    crash = store_a.record(experiment_id="exp-a", target="mock:parser",
                           fmt="mock", data=b"MOCK\x01\xff\x00\x00",
                           exec_result=result)
    assert [c.id for c in store_a.list(experiment_id="exp-a")] == [crash.id]
    assert store_a.list(experiment_id="exp-b") == []
    assert CrashStore(ws_b).list() == []
    with pytest.raises(ValidationError, match="not in experiment"):
        store_a.bump_count(crash.id, 1, experiment_id="exp-b")


def test_crash_store_rejects_abnormal_outcomes(workspace):
    from ios_research.errors import ValidationError
    from ios_research.targets.base import ExecResult

    with pytest.raises(ValidationError, match="confirmed CRASH"):
        CrashStore(workspace).record(
            experiment_id="exp", target="test", fmt="raw", data=b"x",
            exec_result=ExecResult(outcome=Outcome.ABNORMAL,
                                   detail="harness exited unexpectedly"))


# --- fuzz engine ----------------------------------------------------------
def _make_session(workspace, seed=1, max_cases=200):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="cfg_x", seed=seed)
    cs = CorpusStore(workspace)
    corpus = cs.create("f")
    cs.add_bytes(corpus, DEFAULT_BASE, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(experiment_id=exp.id, target="mock:parser",
                            corpus_id=corpus.id, seed=seed, workers=1,
                            max_cases=max_cases, duration_s=None)
    return engine, session


def test_fuzz_runs_to_completion_and_finds_crashes(workspace):
    engine, session = _make_session(workspace, seed=1, max_cases=200)
    session = engine.advance(session)
    assert session.status == COMPLETED
    assert session.cursor == 200
    assert session.unique_crashes > 0
    assert sum(session.outcomes.values()) == 200


def test_fuzz_reports_abnormal_harness_events_without_crash_records(
        workspace, monkeypatch):
    from ios_research.targets.base import ExecResult, Target
    import ios_research.fuzz as fuzzmod

    class AlwaysAbnormal(Target):
        target_id = "test:abnormal"

        def _run(self, data):
            return ExecResult(outcome=Outcome.ABNORMAL, detail="harness failed")

    monkeypatch.setattr(fuzzmod.targets, "create", lambda _target: AlwaysAbnormal())
    exp = ExperimentStore(workspace).create(
        target="test:abnormal", device="mock:device", os_version="17.0",
        config_hash="cfg", seed=1)
    corpus = CorpusStore(workspace).create("abnormal")
    CorpusStore(workspace).add_bytes(corpus, b"seed", origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(experiment_id=exp.id, target="test:abnormal",
                            corpus_id=corpus.id, seed=1, workers=1,
                            max_cases=3, duration_s=None)
    session = engine.advance(session)
    assert session.abnormal_events == 3
    assert session.last_abnormal_detail == "harness failed"
    assert session.crashes == 0
    assert session.crash_ids == []
    assert engine.crash_store.list() == []


def test_fuzz_is_reproducible_across_runs(tmp_path):
    from ios_research.workspace import Workspace
    from ios_research import __version__
    results = []
    for name in ("a", "b"):
        ws = Workspace(tmp_path / name / ".ios-research")
        ws.init(framework_version=__version__, created_at="t")
        engine, session = _make_session(ws, seed=99, max_cases=150)
        session = engine.advance(session)
        results.append((session.cursor, sorted(session.crash_ids),
                        tuple(sorted(session.outcomes.items()))))
    assert results[0] == results[1]


def test_fuzz_resume_matches_single_run(tmp_path):
    from ios_research.workspace import Workspace
    from ios_research import __version__
    # Single run.
    ws1 = Workspace(tmp_path / "single" / ".ios-research")
    ws1.init(framework_version=__version__, created_at="t")
    e1, s1 = _make_session(ws1, seed=5, max_cases=180)
    s1 = e1.advance(s1)

    # Chunked (paused/resumed) run.
    ws2 = Workspace(tmp_path / "chunk" / ".ios-research")
    ws2.init(framework_version=__version__, created_at="t")
    e2, s2 = _make_session(ws2, seed=5, max_cases=180)
    s2 = e2.advance(s2, max_new=50)
    assert s2.status == PAUSED and s2.cursor == 50
    s2 = e2.resume(s2, max_new=50)
    s2 = e2.resume(s2)  # finish remaining
    assert s2.status == COMPLETED
    assert s2.cursor == s1.cursor == 180
    assert sorted(s2.crash_ids) == sorted(s1.crash_ids)
    assert s2.outcomes == s1.outcomes
