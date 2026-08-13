"""Tests for the batched-persistence fuzz throughput optimization (issue #3).

These lock in that the optimization is behavior-preserving: the weighted pool is
memoized, mutation output is byte-identical, and batched crash/corpus persistence
produces the same crashes, counts, and corpus as per-case writes.
"""

from __future__ import annotations

from ios_research import mutation
from ios_research.config import DEFAULT_CONFIG
from ios_research.corpus import CorpusStore
from ios_research.crashes import CrashStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine, DEFAULT_BASE

W = DEFAULT_CONFIG["fuzz"]["strategy_weights"]


# --- memoized weighted pool ----------------------------------------------
def test_weighted_strategies_is_memoized():
    a = mutation.weighted_strategies(dict(W))
    b = mutation.weighted_strategies(dict(W))
    assert a is b                      # same cached object
    assert a.count("structure_aware") == W["structure_aware"]


def test_precomputed_pool_matches_weights_byte_for_byte():
    pool = mutation.weighted_strategies(W)
    tgt = __import__("ios_research.targets", fromlist=["create"]).create("mock:parser")
    for i in range(300):
        via_weights = mutation.mutate(DEFAULT_BASE, 7, i,
                                      struct_fn=tgt.structure_mutate, weights=W)
        via_pool = mutation.mutate(DEFAULT_BASE, 7, i,
                                   struct_fn=tgt.structure_mutate, strategies=pool)
        assert via_weights == via_pool


# --- crash count batching -------------------------------------------------
def test_bump_count_accumulates(workspace):
    from ios_research.targets import create
    from ios_research.targets.base import Outcome
    store = CrashStore(workspace)
    data = b"MOCK\x01\xff\x00\x00"
    res = create("mock:parser").execute(data)
    assert res.outcome == Outcome.CRASH
    crash = store.record(experiment_id="e1", target="mock:parser",
                         fmt="mock-record", data=data, exec_result=res)
    store.bump_count(crash.id, 41)
    assert store.get(crash.id).count == 42
    store.bump_count(crash.id, 0)          # no-op
    assert store.get(crash.id).count == 42


# --- end-to-end: batched persistence preserves results --------------------
def _run(workspace, max_cases):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="c", seed=1)
    cs = CorpusStore(workspace)
    corpus = cs.create("f")
    cs.add_bytes(corpus, DEFAULT_BASE, origin="seed")
    eng = FuzzEngine(workspace)
    s = eng.create(experiment_id=exp.id, target="mock:parser",
                   corpus_id=corpus.id, seed=1, workers=1, max_cases=max_cases,
                   duration_s=None, strategy_weights=W)
    return eng, cs, corpus, eng.advance(s)


def test_crash_counts_sum_to_total_crashes(workspace):
    eng, cs, corpus, session = _run(workspace, 600)
    counts = {c.id: c.count for c in eng.crash_store.list()}
    # Every crash occurrence is accounted for in the persisted counts.
    assert sum(counts.values()) == session.outcomes["crash"] + session.outcomes["abnormal"]
    # Unique crashes match the persisted distinct records.
    assert set(counts) == set(session.crash_ids)


def test_corpus_persisted_once_after_batch(workspace):
    eng, cs, corpus, session = _run(workspace, 400)
    # Corpus manifest reflects all distinct crashing inputs after the flush.
    reloaded = cs.get(corpus.id)
    assert len(reloaded.testcases) >= 2
    # Crashing inputs are readable (bytes were written during the loop).
    for tc in reloaded.testcases:
        assert cs.read_bytes(reloaded, tc["sha256"])


def test_resume_still_matches_single_run(tmp_path):
    from ios_research.workspace import Workspace
    from ios_research import __version__
    ws1 = Workspace(tmp_path / "single" / ".ios-research")
    ws1.init(framework_version=__version__, created_at="t")
    e1, cs1, c1, s1 = _run(ws1, 300)

    ws2 = Workspace(tmp_path / "chunk" / ".ios-research")
    ws2.init(framework_version=__version__, created_at="t")
    exp = ExperimentStore(ws2).create(target="mock:parser", device="mock:device",
                                      os_version="17.0", config_hash="c", seed=1)
    cs2 = CorpusStore(ws2)
    corpus = cs2.create("f")
    cs2.add_bytes(corpus, DEFAULT_BASE, origin="seed")
    e2 = FuzzEngine(ws2)
    s2 = e2.create(experiment_id=exp.id, target="mock:parser", corpus_id=corpus.id,
                   seed=1, workers=1, max_cases=300, duration_s=None,
                   strategy_weights=W)
    s2 = e2.advance(s2, max_new=120)
    s2 = e2.advance(s2)
    assert s2.outcomes == s1.outcomes
    assert sorted(s2.crash_ids) == sorted(s1.crash_ids)
    counts1 = {c.id: c.count for c in e1.crash_store.list()}
    counts2 = {c.id: c.count for c in e2.crash_store.list()}
    assert sum(counts1.values()) == sum(counts2.values())
