"""Continuous regression fuzzing, flaky triage, trends, symbolication (#49)."""

from __future__ import annotations

import pytest

from ios_research.campaign import RegressionCampaignEngine, apply_symbol_map
from ios_research.errors import NotFoundError, ValidationError
from ios_research.targets.base import Diagnostics, ExecResult, Outcome, Target


class FlakyCrashTarget(Target):
    """Crashes on ~half of executions with a stable signature."""

    target_id = "test:camp-flaky"
    kind = "mock-parser"
    description = "flaky crash source for triage tests"
    calls = 0

    def _run(self, data: bytes) -> ExecResult:
        FlakyCrashTarget.calls += 1
        if FlakyCrashTarget.calls % 2:
            return ExecResult(
                outcome=Outcome.CRASH,
                diagnostics=Diagnostics(signature="sig_flaky",
                                        classification_hint="UNKNOWN"))
        return ExecResult(outcome=Outcome.ACCEPTED)


@pytest.fixture()
def flaky_target():
    FlakyCrashTarget.calls = 0
    from ios_research import targets as tr
    tr.register("test:camp-flaky", lambda: FlakyCrashTarget())
    yield
    tr._REGISTRY.pop("test:camp-flaky", None)


def test_stable_crash_is_confirmed(workspace):
    engine = RegressionCampaignEngine(workspace)
    summary = engine.run(target_id="mock:parser", cases=200, seed=1,
                         trials=3)
    assert summary["unique_signatures"] >= 1
    assert all(t["status"] == "confirmed"
               for t in summary["signatures"].values())
    assert summary["confirmed"] == summary["unique_signatures"]
    assert summary["campaign_id"]


def test_flaky_signature_is_isolated_not_promoted(workspace, flaky_target):
    engine = RegressionCampaignEngine(workspace)
    summary = engine.run(target_id="test:camp-flaky", cases=100, seed=2,
                         trials=4)
    assert summary["flaky_isolated"] >= 1
    assert summary["confirmed"] == 0
    statuses = {t["status"] for t in summary["signatures"].values()}
    assert "flaky" in statuses


def test_trend_report_diffs_against_previous_run(workspace):
    engine = RegressionCampaignEngine(workspace)
    first = engine.run(target_id="mock:parser", cases=150, seed=3, trials=1)
    second = engine.run(target_id="mock:parser", cases=300, seed=3, trials=1)
    trend = engine.ws.read_json(engine._trend_rel(second["campaign_id"]))
    assert trend["delta_vs_previous"] is not None
    deltas = trend["delta_vs_previous"]
    assert deltas["cases"] == 300 - 150
    assert deltas["corpus_size"] >= 0   # corpus only grows across runs
    # The very first run has no predecessor.
    first_trend = engine.ws.read_json(engine._trend_rel(first["campaign_id"]))
    assert first_trend["delta_vs_previous"] is None


def test_symbolication_marks_unsymbolicated_frames_explicitly():
    frames = ["ImageIO`decode_frame", "0x1028a8b24 in ???"]
    mapped = apply_symbol_map(frames, {"decode_frame": "ImageIO!decode_frame"})
    assert mapped[0] == "ImageIO`decode_frame ImageIO!decode_frame"
    assert "(unsymbolicated)" in mapped[1]
    # No map at all: everything is explicit.
    raw = apply_symbol_map(frames, None)
    assert all("(unsymbolicated)" in f for f in raw)


def test_regression_gate_flags_reproducible_regression(workspace):
    engine = RegressionCampaignEngine(workspace)
    report = engine.gate(target_baseline="mock:parser",
                         target_candidate="mock:parser-v2")
    assert report["kind"] == "regression-gate"
    assert report["regressions_flagged"] >= 1
    # mock:parser-v2's regression is deterministic -> gate passes because the
    # flagged regressions reproduce stably (they are *real*, stable findings).
    assert report["passed"] is True
    assert all(r["stably_reproduced"] for r in report["gated_regressions"])
    persisted = workspace.path(f"research/gate-{report['diff_id']}.json")
    assert persisted.is_file()


def test_trials_bounds_and_unknown_target(workspace):
    engine = RegressionCampaignEngine(workspace)
    with pytest.raises(ValidationError):
        engine.run(target_id="mock:parser", cases=10, trials=51)
    with pytest.raises(NotFoundError):
        engine.run(target_id="missing:t", cases=10)


def test_campaign_persisted_and_listed(workspace):
    engine = RegressionCampaignEngine(workspace)
    out = engine.run(target_id="mock:parser", cases=50, seed=9, trials=1)
    record = engine.get(out["campaign_id"])
    assert record.status == "run"
    assert record.id in {c.id for c in engine.list()}
