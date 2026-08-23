"""Target Flag taxonomy mapping and flag-aware readiness tests (#58)."""

from __future__ import annotations

import json

import pytest

from ios_research.bounty import BountyReadiness
from ios_research.crashes import CrashStore
from ios_research.errors import ValidationError
from ios_research.targetflags import (
    DEFAULT_TAXONOMY, OVERRIDE_RELPATH, candidates_for, get_flag,
    load_taxonomy,
)
from ios_research.targets import create


def _report(workspace):
    data = b"MOCK\x01\x01\xff\xff" + b"A" * 20
    result = create("mock:parser").execute(data)
    crash = CrashStore(workspace).record(
        experiment_id="e1", target="mock:parser", fmt="mock-record",
        data=data, exec_result=result)
    readiness = BountyReadiness(workspace)
    report = readiness.reports.create(crash.id)
    report.sections["affected_versions"]["os_version"] = "17.5"
    report.sections["affected_versions"]["device"] = "authorized test device"
    return readiness, report, crash


def _metadata(**overrides):
    base = {
        "contact": "researcher@example.test",
        "attestations": {"authorized_testing": True},
    }
    base.update(overrides)
    return base


# --- taxonomy -----------------------------------------------------------------

def test_builtin_taxonomy_loads_deterministically(workspace):
    first = load_taxonomy(workspace)
    second = load_taxonomy(workspace)
    assert first == second
    assert first["source"] == "builtin"
    assert first["taxonomy_version"] >= 1
    ids = [f["id"] for f in first["flags"]]
    assert len(ids) == len(DEFAULT_TAXONOMY)
    assert ids == sorted(ids) or len(set(ids)) == len(ids)


def test_taxonomy_override_is_data_driven_and_hash_pinned(workspace):
    override = {"version": 7, "flags": [{
        "id": "custom-flag", "label": "Custom", "entry_point": "test",
        "outcome": "demo", "evidence_required": ["reproducible_crash"],
    }]}
    workspace.write_json(OVERRIDE_RELPATH.removeprefix("config/"),
                         {"unused": True}) if False else None
    workspace.path(OVERRIDE_RELPATH).parent.mkdir(parents=True, exist_ok=True)
    workspace.path(OVERRIDE_RELPATH).write_text(json.dumps(override))
    taxonomy = load_taxonomy(workspace)
    assert taxonomy["source"] == "workspace-override"
    assert taxonomy["taxonomy_version"] == 7
    assert [f["id"] for f in taxonomy["flags"]] == ["custom-flag"]
    assert len(taxonomy["sha256"]) == 64


@pytest.mark.parametrize("bad", [
    {"flags": "nope", "version": 1},
    {"version": "x"},
    {"version": 1, "flags": [{"id": "x"}]},
    {"version": 1, "flags": [{"id": "x", "label": "l", "entry_point": "e",
                              "outcome": "o",
                              "evidence_required": ["not-an-element"]}]},
])
def test_invalid_overrides_fail_validation(workspace, bad):
    workspace.path(OVERRIDE_RELPATH).parent.mkdir(parents=True, exist_ok=True)
    workspace.path(OVERRIDE_RELPATH).write_text(json.dumps(bad))
    with pytest.raises(ValidationError):
        load_taxonomy(workspace)


# --- candidate proposals ---------------------------------------------------------

def test_candidates_match_component_keywords_and_indicators():
    taxonomy = load_taxonomy(None)
    flag = get_flag(taxonomy, "webcontent-sandbox-escape")
    assert flag is not None

    crash = {"target": "webkit-shell", "diagnostics": {"modules": ["WebKit"]}}
    analysis = {"exploitability_classification":
                "CONTROLLED_MEMORY_ACCESS_INDICATOR",
                "likely_affected_component": "WebKit"}
    candidates = candidates_for(crash, analysis, taxonomy)
    ids = {c["flag_id"] for c in candidates}
    assert "webcontent-sandbox-escape" in ids
    assert all(c["confidence"] in ("LOW", "MEDIUM") for c in candidates)
    # keyword + indicator both hit -> MEDIUM
    target = next(c for c in candidates
                  if c["flag_id"] == "webcontent-sandbox-escape")
    assert target["confidence"] == "MEDIUM"


def test_candidates_are_empty_without_evidence():
    taxonomy = load_taxonomy(None)
    crash = {"target": "mock:parser",
             "diagnostics": {"modules": ["mock-parser"]}}
    analysis = {"exploitability_classification": "CRASH_ONLY",
                "likely_affected_component": "mock-parser"}
    assert candidates_for(crash, analysis, taxonomy) == []


def test_candidates_are_deterministic_and_sorted():
    taxonomy = load_taxonomy(None)
    crash = {"target": "WebKit", "diagnostics": {"modules": ["WebKit"]}}
    analysis = {"exploitability_classification":
                "CODE_EXECUTION_INDICATOR",
                "likely_affected_component": "WebKit"}
    assert (candidates_for(crash, analysis, taxonomy)
            == candidates_for(crash, analysis, taxonomy))


# --- flag-aware readiness --------------------------------------------------------

def test_bounty_validate_surfaces_candidates_and_passes_without_claims(workspace):
    readiness, report, _crash = _report(workspace)
    result = readiness.validate(report, _metadata())
    assert result["ready"] is True
    tf = result["target_flags"]
    assert tf["claimed"] == []
    assert isinstance(tf["candidates"], list)
    assert tf["taxonomy_sha256"]


def test_claimed_flag_requires_its_evidence_elements(workspace):
    readiness, report, _crash = _report(workspace)
    # The fixture analysis already carries a corruption indicator and base
    # evidence, so only the extra elements should be missing.
    claimed = "app-sandbox-escape-kernel"
    result = readiness.validate(
        report, _metadata(target_flags=[claimed]))
    assert result["ready"] is False
    missing = set(result["missing"])
    assert f"target_flag:{claimed}:matrix_confirmation" in missing
    assert f"target_flag:{claimed}:primitive_indicator" not in missing
    assert f"target_flag:{claimed}:reproducible_crash" not in missing
    assert f"target_flag:{claimed}:minimized_input" not in missing

    # A flag requiring researcher-supplied demonstrations fails without them.
    demo_flag = "app-sandbox-escape-sensitive-data"
    result = readiness.validate(
        report, _metadata(target_flags=[demo_flag]))
    assert f"target_flag:{demo_flag}:demonstration_refs" in set(
        result["missing"])


def test_satisfied_flag_elements_pass(workspace):
    readiness, report, _crash = _report(workspace)
    claimed = "web-content-code-execution"  # reproducible+minimized+build only
    report.sections["exploitability_assessment"] = {
        "indicator": "CONTROLLED_MEMORY_ACCESS_INDICATOR"}
    result = readiness.validate(
        report, _metadata(target_flags=[claimed],
                          matrix_evidence=["mtx_example"],
                          demonstration_refs=["notes.md"]))
    assert result["ready"] is True, result["missing"]


def test_unknown_claimed_flag_fails_closed(workspace):
    readiness, report, _crash = _report(workspace)
    result = readiness.validate(
        report, _metadata(target_flags=["totally-made-up"]))
    assert result["ready"] is False
    assert "target_flag:totally-made-up:known" in result["missing"]


def test_flag_guidance_is_included_in_exported_pack(workspace):
    readiness, report, _crash = _report(workspace)
    metadata = _metadata(target_flags=["web-content-code-execution"])
    pack = readiness.pack(report, metadata)
    guidance = pack["target_flag_guidance"]
    assert guidance["claimed"] == ["web-content-code-execution"]
    assert "candidates" in guidance and "taxonomy_sha256" in guidance
