"""Tests for suspicious-point triage agents (`spoints` command group)."""

from __future__ import annotations

import json

import pytest

from ios_research.cli import main
from ios_research.errors import NotFoundError
from ios_research.spoints import (
    SpointsEngine, cluster_points, extract_points, jaccard,
)


def _record_crash(ctx, *, target="mock:parser", data=b"MOCK\x01\x01\x00\x10payload",
                  experiment="exp_test", stack=None, classification=None):
    """Create a real crash record by executing the target on crashing input.

    Using the target's own diagnostics guarantees reproduce() succeeds, so the
    verified/points/PoC stages of the pipeline are exercised.
    """
    from ios_research import targets as tgt
    from ios_research.crashes import CrashStore
    from ios_research.targets.base import Outcome

    result = tgt.create(target).execute(data)
    assert result.outcome == Outcome.CRASH, "test input must crash the target"
    if classification is not None:
        result.diagnostics.classification_hint = classification
        result.diagnostics.signature = \
            f"sig_{classification}_{result.diagnostics.signature}"
    if stack is not None:
        result.diagnostics.stack_trace = stack
    store = CrashStore(ctx.workspace())
    return store.record(experiment_id=experiment, target=target, fmt="bin",
                        data=data, exec_result=result)


# --- point extraction --------------------------------------------------------
def test_extract_points_scores_by_depth_and_severity():
    class FakeCrash:
        classification = "USE_AFTER_FREE"
        diagnostics = {"stack_trace":
                       ["Mod`alpha", "beta_only", "Mod`gamma", ""]}

    pts = extract_points(FakeCrash())
    assert len(pts) == 4
    assert pts[0] == {"module": "Mod", "symbol": "alpha",
                      "frame_index": 0, "score": 40}
    assert pts[1]["module"] == "" and pts[1]["symbol"] == "beta_only"
    assert all(pts[i]["score"] > pts[i + 1]["score"]
               for i in range(3))


def test_extract_points_empty_trace():
    class FakeCrash:
        classification = "UNKNOWN"
        diagnostics = {}

    assert extract_points(FakeCrash()) == []


# --- clustering --------------------------------------------------------------
def test_jaccard_basics():
    a = frozenset({"x", "y"})
    assert jaccard(a, a) == 1.0
    assert jaccard(a, frozenset({"x"})) == 0.5
    assert jaccard(frozenset(), a) == 0.0


def test_cluster_points_groups_overlapping_crashes():
    items = [
        {"crash_id": "c1", "points": [{"symbol": "s1"}, {"symbol": "s2"}],
         "total_score": 10},
        {"crash_id": "c2", "points": [{"symbol": "s1"}, {"symbol": "s2"}],
         "total_score": 8},
        {"crash_id": "c3", "points": [{"symbol": "zzz"}],
         "total_score": 20},
    ]
    clusters = cluster_points(items)
    assert len(clusters) == 2
    pair = [c for c in clusters if c["size"] == 2][0]
    assert pair["representative"] in ("c1", "c2")
    assert sorted(pair["members"]) == ["c1", "c2"]
    lone = [c for c in clusters if c["size"] == 1][0]
    assert lone["members"] == ["c3"]


def test_cluster_points_deterministic_order():
    items = [
        {"crash_id": f"c{i}",
         "points": [{"symbol": s} for s in (f"s{i}", "shared")],
         "total_score": 5} for i in range(4)
    ]
    one = cluster_points(items)
    two = cluster_points(items)
    assert one == two


# --- full pipeline against the mock target -----------------------------------
def test_engine_run_end_to_end(ctx):
    crash = _record_crash(ctx)
    engine = SpointsEngine(ctx.workspace())
    report = engine.run()
    assert report.stats["crashes"] == 1
    assert report.id.startswith("spt_")
    entry = report.results[0]
    assert entry["crash_id"] == crash.id


def test_engine_run_is_rerunnable(ctx):
    _record_crash(ctx)
    engine = SpointsEngine(ctx.workspace())
    r1 = engine.run()
    r2 = engine.run()
    # Deterministic pipeline + derived report id => rerunning the same scope
    # refreshes the same record rather than duplicating history.
    assert r1.id == r2.id
    assert r1.stats == r2.stats
    assert len(engine.list()) == 1
    stored = engine.get(r2.id)
    assert stored.stats == r2.stats


def test_engine_run_scope_and_limit(ctx):
    _record_crash(ctx, experiment="exp_a")
    _record_crash(ctx, experiment="exp_b")
    engine = SpointsEngine(ctx.workspace())
    report = engine.run(experiment_id="exp_a")
    assert report.stats["crashes"] == 1
    with pytest.raises(NotFoundError):
        engine.run(experiment_id="exp_missing")
    with pytest.raises(Exception):
        engine.run(limit=0)


def test_engine_run_empty_workspace_raises(ctx):
    engine = SpointsEngine(ctx.workspace())
    with pytest.raises(NotFoundError):
        engine.run()


# --- CLI surface -------------------------------------------------------------
def test_cli_spoints_roundtrip(ctx, capsys):
    ws = str(ctx.workspace().root)
    _record_crash(ctx)

    rc = main(["spoints", "run", "--json", "--workspace", ws])
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    rid = out["data"]["report_id"]
    assert out["data"]["stats"]["crashes"] == 1

    rc = main(["spoints", "list", "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and payload["data"]["count"] == 1

    rc = main(["spoints", "show", rid, "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and payload["data"]["id"] == rid
    assert isinstance(payload["data"]["clusters"], list)


def test_cli_spoints_points_unknown_crash(ctx, capsys):
    ws = str(ctx.workspace().root)
    _record_crash(ctx)
    main(["spoints", "run", "--workspace", ws])
    capsys.readouterr()

    rc = main(["spoints", "run", "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    rid = payload["data"]["report_id"]

    rc = main(["spoints", "points", rid, "nope", "--json",
               "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 3  # NOT_FOUND
    assert payload["ok"] is False
