"""Delivery-provenance tests (#106): zero-click declaration round-trips."""

from __future__ import annotations

import json

from ios_research.bounty import BountyReadiness
from ios_research.cli import main
from ios_research.crashes import CrashStore
from ios_research.experiment import ExperimentStore
from ios_research.targetflags import candidates_for
from ios_research.targets import create

TAXONOMY = {
    "taxonomy_version": 2,
    "sha256": "test",
    "flags": [
        {"id": "network-zero-click-userspace", "label": "net zero-click",
         "entry_point": "network", "outcome": "userspace",
         "reward_hint": 350000, "keywords": ["nomatch-me"],
         "indicators": [], "evidence_required": []},
        {"id": "wireless-proximity-app", "label": "proximity",
         "entry_point": "wireless-proximity", "outcome": "app",
         "reward_hint": 1000000, "keywords": ["bluetooth"],
         "indicators": [], "evidence_required": []},
    ],
}


def _analysis():
    return {"likely_affected_component": "", "exploitability_classification": ""}


def _crash(target="voicememo:thing"):
    return {"target": target, "diagnostics": {"modules": []}}


def test_candidates_without_delivery_do_not_include_network_flags():
    out = candidates_for(_crash(), _analysis(), TAXONOMY)
    assert out == []


def test_zero_click_delivery_surfaces_network_candidates_low_confidence():
    out = candidates_for(_crash(), _analysis(), TAXONOMY,
                         experiment_params={"delivery": "zero-click"})
    by_id = {c["flag_id"]: c for c in out}
    assert by_id["network-zero-click-userspace"]["confidence"] == "LOW"
    # non-network flags stay keyword-gated even with delivery set
    assert "wireless-proximity-app" not in by_id


def test_keyword_match_wins_to_medium_even_with_delivery():
    out = candidates_for(_crash(target="bluetooth:thing"), _analysis(),
                         TAXONOMY, experiment_params={"delivery": "zero-click"})
    by_id = {c["flag_id"]: c for c in out}
    assert by_id["wireless-proximity-app"]["confidence"] == "LOW"  # keyword only
    assert by_id["network-zero-click-userspace"]["confidence"] == "LOW"


def _seed_workspace_with_delivery(workspace, delivery):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="cfg_x", seed=3,
        params={"delivery": delivery} if delivery else None)
    data = b"MOCK\x01\x01\xff\xff" + b"A" * 20
    result = create("mock:parser").execute(data)
    crash = CrashStore(workspace).record(
        experiment_id=exp.id, target="mock:parser", fmt="mock-record",
        data=data, exec_result=result)
    return exp, crash


def test_report_and_bounty_validate_carry_delivery_provenance(workspace):
    _, crash = _seed_workspace_with_delivery(workspace, "zero-click")
    readiness = BountyReadiness(workspace)
    report = readiness.reports.create(crash.id)
    assert report.sections["delivery_provenance"]["delivery"] == "zero-click"
    report.sections["affected_versions"]["os_version"] = "17.5"
    report.sections["affected_versions"]["device"] = "authorized test device"
    out = readiness.validate(report, {"contact": "r@example.test"})
    assert out["target_flags"]["delivery"] == "zero-click"


def test_no_delivery_key_when_unset(workspace):
    _, crash = _seed_workspace_with_delivery(workspace, None)
    readiness = BountyReadiness(workspace)
    report = readiness.reports.create(crash.id)
    assert "delivery_provenance" not in report.sections
    report.sections["affected_versions"]["os_version"] = "17.5"
    report.sections["affected_versions"]["device"] = "authorized test device"
    out = readiness.validate(report, {"contact": "r@example.test"})
    assert "delivery" not in out["target_flags"]


def test_cli_experiment_create_accepts_delivery_flag(workspace):
    ws = str(workspace.root)
    rc = main(["--workspace", ws, "--json", "experiment", "create",
               "--target", "mock:parser", "--device", "mock:device",
               "--delivery", "zero-click"])
    assert rc == 0
    store = ExperimentStore(workspace)
    exps = store.list()
    assert exps and exps[-1].params.get("delivery") == "zero-click"


def test_cli_fuzz_start_persists_delivery_param(workspace):
    ws = str(workspace.root)
    rc = main(["--workspace", ws, "--json", "fuzz", "start",
               "--target", "mock:parser", "--max-cases", "20",
               "--delivery", "one-click"])
    assert rc == 0
    exps = ExperimentStore(workspace).list()
    assert any((e.params or {}).get("delivery") == "one-click" for e in exps)


def test_cli_rejects_unknown_delivery_choice(workspace):
    import pytest
    ws = str(workspace.root)
    with pytest.raises(SystemExit) as ei:
        main(["--workspace", ws, "--json", "experiment", "create",
              "--target", "mock:parser", "--device", "mock:device",
              "--delivery", "carrier-pigeon"])
    assert ei.value.code != 0
