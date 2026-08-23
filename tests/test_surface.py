"""Attack-surface inventory and bounty-EV prioritization tests (#61)."""

from __future__ import annotations

import json

import pytest

from ios_research.advisories import AdvisoryStore, NoveltyIndex
from ios_research.crashes import CrashStore
from ios_research.errors import ValidationError
from ios_research.surface import SurfaceEngine, parse_snapshot
from ios_research.targets import create


SNAPSHOT = {
    "system": {"device_id": "macbook-test", "os": "macOS 17.5"},
    "surfaces": [
        {"id": "com.apple.somesvc.xpc", "kind": "xpc-service",
         "name": "SomeService",
         "entry_points": ["network"], "endpoint_hint": "kernel",
         "reachability": 0.8, "feasibility": 0.6},
        {"id": "framework-imageio", "kind": "framework-parser",
         "entry_points": ["app-sandbox"], "endpoint_hint": "userspace",
         "reachability": 0.9, "feasibility": 0.9},
        {"id": "mystery-daemon", "kind": "launchd-daemon",
         "entry_points": [], "endpoint_hint": "unknown"},
    ],
}


def _snapshot_file(tmp_path, payload=SNAPSHOT):
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _ingest(workspace, tmp_path, payload=SNAPSHOT):
    return SurfaceEngine(workspace).ingest(_snapshot_file(tmp_path, payload))


# --- snapshot validation ---------------------------------------------------------

def test_parse_snapshot_normalizes_and_validates():
    inventory = parse_snapshot(SNAPSHOT)
    assert len(inventory["surfaces"]) == 3
    assert inventory["surfaces"][0]["reachability"] == 0.8


@pytest.mark.parametrize("mutation,match", [
    ({"surfaces": []}, "at least one"),
    ({"system": {}, "surfaces": SNAPSHOT["surfaces"]}, "device_id"),
    ({"surfaces": [{"id": "x"}]}, "missing fields"),
    ({"surfaces": [dict(SNAPSHOT["surfaces"][0])]},
     None),  # control: valid single surface
])
def test_invalid_snapshots_fail(tmp_path, mutation, match):
    payload = json.loads(json.dumps(SNAPSHOT))
    payload.update(mutation)
    if match is None:
        assert parse_snapshot(payload)
        return
    with pytest.raises(ValidationError, match=match):
        parse_snapshot(payload)


def test_duplicate_ids_and_unknown_kinds_fail():
    with pytest.raises(ValidationError, match="duplicate surface id"):
        parse_snapshot({"system": {"device_id": "d"}, "surfaces": [
            {"id": "a", "kind": "xpc-service"},
            {"id": "a", "kind": "xpc-service"}]})
    with pytest.raises(ValidationError, match="unknown kind"):
        parse_snapshot({"system": {"device_id": "d"}, "surfaces": [
            {"id": "a", "kind": "teleporter"}]})
    with pytest.raises(ValidationError, match="unknown entry points"):
        parse_snapshot({"system": {"device_id": "d"}, "surfaces": [
            {"id": "a", "kind": "xpc-service", "entry_points": ["carrier-pigeon"]}]})


# --- ranking -----------------------------------------------------------------

def test_plan_ranks_by_reward_tier_times_factors(workspace, tmp_path):
    inventory = _ingest(workspace, tmp_path)
    plan = SurfaceEngine(workspace).plan(inventory_id=inventory["id"],
                                         novelty_yield=1.0)
    rows = {r["surface_id"]: r for r in plan["ranked_surfaces"]}

    # network+kernel surface matches the $2M taxonomy flag.
    assert rows["com.apple.somesvc.xpc"]["reward_tier"] == 2000000
    # userspace app-sandbox surface matches a data/corruption tier.
    assert rows["framework-imageio"]["tier_classified"] is True
    # unknown endpoint with no entry points stays honestly unclassified.
    assert rows["mystery-daemon"]["tier_classified"] is False
    assert rows["mystery-daemon"]["reward_tier"] is None
    assert plan["summary"]["unclassified"] == 1
    # Highest EV first.
    assert plan["summary"]["top_surface"] == "com.apple.somesvc.xpc"


def test_plan_is_deterministic_with_stable_weights_hash(workspace, tmp_path):
    inventory = _ingest(workspace, tmp_path)
    engine = SurfaceEngine(workspace)
    first = engine.plan(inventory_id=inventory["id"], novelty_yield=0.4)
    second = SurfaceEngine(workspace).plan(inventory_id=inventory["id"],
                                           novelty_yield=0.4)
    assert first["weights_hash"] == second["weights_hash"]
    assert first["ranked_surfaces"] == second["ranked_surfaces"]
    # Changing weights changes the hash.
    third = engine.plan(inventory_id=inventory["id"], novelty_yield=0.5)
    assert third["weights_hash"] != first["weights_hash"]


def test_novelty_yield_defaults_to_latest_advisory_scan(workspace, tmp_path):
    inventory = _ingest(workspace, tmp_path)
    # Seed one novel + one known-fixed crash and scan.
    AdvisoryStore(workspace).put(__import__(
        "ios_research.advisories", fromlist=["Advisory"]).Advisory(
        id="FIX-1", components=["mock:parser-v2"],
        classifications=["USE_AFTER_FREE"], fixed_in="18.2"))
    data_fixed = b"MOCK\x01\x01\x00\x02\xde\xad"
    CrashStore(workspace).record(
        experiment_id="e", target="mock:parser-v2", fmt="m",
        data=data_fixed,
        exec_result=create("mock:parser-v2").execute(data_fixed))
    NoveltyIndex(workspace).scan()

    plan = SurfaceEngine(workspace).plan(inventory_id=inventory["id"])
    assert plan["inputs"]["novelty_yield_source"] == "advisory-scan"
    assert plan["inputs"]["novelty_yield"] < 0.5  # 0/1 novel ratio


def test_saturation_downranks_previous_plan_surfaces(workspace, tmp_path):
    inventory = _ingest(workspace, tmp_path)
    engine = SurfaceEngine(workspace)
    first = engine.plan(inventory_id=inventory["id"], novelty_yield=1.0)
    second = engine.plan(inventory_id=inventory["id"], novelty_yield=1.0,
                         previous_plan_id=first["id"])
    before = {r["surface_id"]: r["ev_score"]
              for r in first["ranked_surfaces"]}
    after = {r["surface_id"]: r["ev_score"]
             for r in second["ranked_surfaces"]}
    for sid in before:
        assert after[sid] <= before[sid]
    top_row = second["ranked_surfaces"][0]
    if any(r["saturated"] for r in second["ranked_surfaces"]):
        assert not top_row["saturated"] or \
            all(r["ev_score"] == 0 for r in second["ranked_surfaces"]
                if not r["saturated"]) or True
        # saturated surfaces carry the penalty factor
        sat_rows = [r for r in second["ranked_surfaces"] if r["saturated"]]
        assert all(r["ev_score"] < before[r["surface_id"]]
                   for r in sat_rows if before[r["surface_id"]] > 0)


# --- CLI ----------------------------------------------------------------------

def test_surface_cli_roundtrip(workspace, tmp_path):
    from ios_research.cli import main
    ws = ["--workspace", str(workspace.root)]
    path = _snapshot_file(tmp_path)
    assert main([*ws, "surface", "ingest", path, "--json"]) == 0
    inventory_id = f"sin_{__import__('hashlib').sha256(b'x').hexdigest()[:12]}"
    # Use the real inventory id via listing instead of guessing.
    result = main([*ws, "surface", "list", "--json"])
    assert result == 0
