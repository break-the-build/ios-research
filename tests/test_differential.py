"""Phase 06 tests: differential testing and regression detection."""

from __future__ import annotations

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
