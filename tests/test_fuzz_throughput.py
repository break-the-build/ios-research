"""Tests for the batched-persistence fuzz throughput optimization (issue #3).

These lock in that the optimization is behavior-preserving: the weighted pool is
memoized, mutation output is byte-identical, and batched crash/corpus persistence
produces the same crashes, counts, and corpus as per-case writes.
"""

from __future__ import annotations

from ios_research import mutation, targets
from ios_research.config import DEFAULT_CONFIG
from ios_research.corpus import CorpusStore
from ios_research.crashes import CrashStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine, DEFAULT_BASE
from ios_research.targets.base import ExecResult, Outcome, Target

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
    assert sum(counts.values()) == session.outcomes["crash"]
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


# --- per-advance scheduling caches (#198) ---------------------------------
class _NovelCoverageTarget(Target):
    target_id = "test:novel-coverage"
    kind = "parser"
    description = "reports a novel coverage feature for every distinct input"
    formats = ("bin",)

    def seeds(self):
        return [b"A"]

    def coverage_features(self, data, result):
        return ("feat:" + data.hex(),)

    def _run(self, data):
        return ExecResult(outcome=Outcome.ACCEPTED, detail="ok", duration_ms=1)


class _NovelDirectedTarget(_NovelCoverageTarget):
    target_id = "test:novel-directed"
    description = "directed stub with a callgraph and per-input novel features"

    def seeds(self):
        return [b"A", b"B"]

    def callgraph(self):
        return {"nodes": ["entry", "sink"],
                "edges": [["entry", "sink"]]}

    def focus_symbol_for(self, data):
        return "sink"


def _novel_run(workspace, *, target, corpus_name, seed_count, max_cases,
               focus_symbol=""):
    exp = ExperimentStore(workspace).create(
        target=target, device="mock:device", os_version="17.0",
        config_hash="c", seed=19)
    store = CorpusStore(workspace)
    corpus = store.create(corpus_name)
    for n in range(seed_count):
        store.add_bytes(corpus, bytes([65 + n]) * 4, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(experiment_id=exp.id, target=target,
                            corpus_id=corpus.id, seed=19, workers=1,
                            max_cases=max_cases, duration_s=None,
                            focus_symbol=focus_symbol)
    return store, engine, session


def test_retained_entry_is_selectable_within_same_advance(workspace):
    """Index freshness (#198): once an input is retained mid-run it must be
    selectable on a later case of the SAME advance() call."""
    targets.register("test:novel-coverage", lambda: _NovelCoverageTarget())
    try:
        _, engine, session = _novel_run(
            workspace, target="test:novel-coverage", corpus_name="freshness",
            seed_count=1, max_cases=40)
        session = engine.advance(session)
    finally:
        targets._REGISTRY.pop("test:novel-coverage", None)
    # Fair schedule: every retained entry starts at selection count 0, so the
    # first retention is immediately the least-selected candidate and must be
    # picked while the run continues (a stale per-advance index would hide it).
    assert set(session.coverage_selection_counts) & \
        set(session.coverage_retained_shas)


def test_directed_resume_equivalence_with_midrun_retention(tmp_path):
    """Directed-mode equivalence fixture (#198): with retained entries present,
    pause/resume must reproduce the identical base-selection sequence of one
    single advance() call."""
    from ios_research import __version__
    from ios_research.workspace import Workspace

    targets.register("test:novel-directed", lambda: _NovelDirectedTarget())
    try:
        snapshots = []
        for name, chunks in (("single", None), ("split", (17, 23))):
            ws = Workspace(tmp_path / name / ".ios-research")
            ws.init(framework_version=__version__, created_at="t")
            _, engine, session = _novel_run(
                ws, target="test:novel-directed", corpus_name="dir-fresh",
                seed_count=2, max_cases=60, focus_symbol="sink")
            if chunks:
                session = engine.advance(session, max_new=chunks[0])
                session = engine.resume(session, max_new=chunks[1])
                session = engine.resume(session)
            else:
                session = engine.advance(session)
            snapshots.append((
                dict(session.outcomes),
                list(session.coverage_features),
                list(session.coverage_retained_shas),
                dict(session.coverage_selection_counts),
                dict(session.focus_counts),
                dict(session.focus_entry_distances),
                session.focus_biased,
                session.cursor))
    finally:
        targets._REGISTRY.pop("test:novel-directed", None)
    assert snapshots[0] == snapshots[1]
    # Sanity: the run actually retained inputs mid-run and used every case.
    assert snapshots[0][-1] == 60
    assert snapshots[0][2]


class _CountingCorpusStore(CorpusStore):
    """CorpusStore that counts hot-loop disk reads."""

    def __init__(self, workspace):
        super().__init__(workspace)
        self.read_calls: list[str] = []

    def read_bytes(self, corpus, sha256):
        self.read_calls.append(sha256)
        return super().read_bytes(corpus, sha256)


def test_selection_reads_scale_with_distinct_shas_not_cases(tmp_path):
    """Scaling smoke test (#198): read_bytes call count per advance() equals
    the number of DISTINCT input shas seeded/selected -- never one read per
    executed case -- and stays flat when the corpus grows 1x -> 4x."""
    from ios_research import __version__
    from ios_research.workspace import Workspace

    targets.register("test:novel-coverage", lambda: _NovelCoverageTarget())
    try:
        read_totals = []
        for k in (1, 4):
            ws = Workspace(tmp_path / f"k{k}" / ".ios-research")
            ws.init(framework_version=__version__, created_at="t")
            counting = _CountingCorpusStore(ws)
            _, engine, session = _novel_run(
                ws, target="test:novel-coverage", corpus_name=f"reads-{k}",
                seed_count=k, max_cases=80)
            engine.corpus_store = counting
            session = engine.advance(session)
            assert session.cursor == 80
            # Each sha is read at most once per advance(): no repeated reads.
            assert len(counting.read_calls) == len(set(counting.read_calls))
            # Bounded by corpus size (bases seeded once), not by case count.
            assert len(counting.read_calls) <= k
            read_totals.append(len(counting.read_calls))
    finally:
        targets._REGISTRY.pop("test:novel-coverage", None)
    assert read_totals == [1, 4]
