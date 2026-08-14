"""Phase 06 tests: differential testing and regression detection."""

from __future__ import annotations

from ios_research.corpus import CorpusStore
from ios_research.differential import DifferentialEngine
from ios_research.targets import create
from ios_research.targets.base import Outcome


def _make(workspace):
    engine = DifferentialEngine(workspace)
    diff = engine.create(name="v1v2", target_a="mock:parser",
                         target_b="mock:parser-v2", config_hash="cfg_x")
    return engine, diff


def test_v2_fixes_null_dispatch():
    data = b"MOCK\x01\xff\x00\x00"
    assert create("mock:parser").execute(data).outcome == Outcome.CRASH
    assert create("mock:parser-v2").execute(data).outcome == Outcome.ACCEPTED


def test_v2_introduces_version2_regression():
    data = b"MOCK\x02\x01\x00\x02payload"
    assert create("mock:parser").execute(data).outcome == Outcome.ACCEPTED
    assert create("mock:parser-v2").execute(data).outcome == Outcome.CRASH


def test_diff_run_detects_transitions_and_regressions(workspace):
    engine, diff = _make(workspace)
    summary = engine.run(diff)
    assert summary["testcases"] == 6
    assert summary["regressions"] >= 1
    # both a fix (CRASH->NORMAL) and a regression (NORMAL->CRASH) appear
    assert "NORMAL->CRASH" in summary["transitions"]
    assert "CRASH->NORMAL" in summary["transitions"]


def test_diff_is_reproducible(tmp_path):
    from ios_research.workspace import Workspace
    from ios_research import __version__
    summaries = []
    for name in ("a", "b"):
        ws = Workspace(tmp_path / name / ".ios-research")
        ws.init(framework_version=__version__, created_at="t")
        engine = DifferentialEngine(ws)
        diff = engine.create(name="d", target_a="mock:parser",
                             target_b="mock:parser-v2", config_hash="cfg_x")
        summaries.append(engine.run(diff))
    assert summaries[0] == summaries[1]


def test_diff_report_lists_regressions(workspace):
    engine, diff = _make(workspace)
    engine.run(diff)
    report = engine.report(diff)
    assert report["regression_count"] >= 1
    assert all(r["is_regression"] for r in report["regressions"])


def test_diff_identical_targets_have_no_differences(workspace):
    engine = DifferentialEngine(workspace)
    diff = engine.create(name="same", target_a="mock:parser",
                         target_b="mock:parser", config_hash="cfg_x")
    summary = engine.run(diff)
    assert summary["differing"] == 0
    assert summary["regressions"] == 0


def test_regression_direction_distinguishes_fixes_from_regressions(workspace):
    # Pins the regression *direction*: B-worse-than-A is a regression; a fix
    # (CRASH -> NORMAL) must never be flagged as one.
    engine, diff = _make(workspace)
    engine.run(diff)
    results = engine.results(diff)
    rank = {"NORMAL": 0, "REJECT": 0, "TIMEOUT": 2, "CRASH": 3}
    regressions = [r for r in results if r["is_regression"]]
    fixes = [r for r in results
             if r["a"]["category"] == "CRASH" and r["b"]["category"] == "NORMAL"]
    assert regressions, "v2 introduces a regression that must be detected"
    assert fixes, "v2 fixes some v1 crashes"
    for r in regressions:                      # every regression is B worse than A
        assert rank[r["b"]["category"]] > rank[r["a"]["category"]]
    for f in fixes:                            # a fix is not a regression
        assert f["is_regression"] is False


def test_differs_flag_covers_signature_only_differences(workspace):
    # An input that crashes BOTH versions but with different signatures
    # (v1: use-after-free; v2: version-2 OOB write) must be flagged as differing
    # even though the outcome *category* (CRASH) is the same.
    cs = CorpusStore(workspace)
    corpus = cs.create("sigdiff")
    same_crash = b"MOCK\x02\x01\x00\x02\xde\xad"   # v1 UAF, v2 OOB-write
    cs.add_bytes(corpus, same_crash, origin="seed")
    engine = DifferentialEngine(workspace)
    diff = engine.create(name="sd", target_a="mock:parser",
                         target_b="mock:parser-v2", config_hash="cfg_x",
                         corpus_id=corpus.id)
    engine.run(diff)
    r = engine.results(diff)[0]
    assert r["a"]["category"] == "CRASH" and r["b"]["category"] == "CRASH"
    assert r["a"]["signature"] != r["b"]["signature"]
    assert r["differs"] is True                # signature-only difference counts
    assert r["is_regression"] is False         # same severity, not a regression
