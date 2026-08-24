"""Mitigation-provenance tests: MIE/EMTE generation classification (#87)."""

from __future__ import annotations

import json

import pytest

from ios_research.bounty import BountyReadiness
from ios_research.crashes import CrashStore
from ios_research.errors import ValidationError
from ios_research.matrix import ReproductionMatrixEngine
from ios_research.mitigation import (
    MIE_EMTE, OVERRIDE_RELPATH, PRE_MIE, UNKNOWN, classify, load_model_table,
    mismatch_warning, os_major, summarize_profiles,
)
from ios_research.targets import create
from ios_research.targets.ips import parse_metadata


CRASHING_INPUT = b"MOCK\x01\x01\xff\xff" + b"A" * 20


@pytest.fixture
def workspace(tmp_path):
    from ios_research.context import Context
    from ios_research.workspace import Workspace
    from ios_research import __version__
    from ios_research.clock import now_iso
    ws = Workspace(tmp_path / ".ios-research")
    ws.init(framework_version=__version__, created_at=now_iso())
    return ws


def _cells(*models):
    return [{"device_id": "mock:device", "model": m,
             "os_name": "iOS", "os_version": "26.1", "build": "23A344"}
            for m in models]


# --- classification -------------------------------------------------------------

def test_classify_fails_closed_without_table_entries():
    out = classify(hardware_model="iPhone99,1")
    assert out["mitigation_profile"] == UNKNOWN
    assert out["basis"] == ""
    assert out["hardware_model"] == "iPhone99,1"


def test_classify_uses_override_table_prefixes(workspace):
    path = workspace.path(OVERRIDE_RELPATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "mie-emte": ["iPhone17,*"],
        "pre-mie": ["iPhone14,*", "iPhone15,*"]}))
    table = load_model_table(workspace)
    assert classify("iPhone17,3", "26.1", table=table)[
        "mitigation_profile"] == MIE_EMTE
    assert classify("iPhone14,2", "17.5", table=table)[
        "mitigation_profile"] == PRE_MIE


def test_classify_exact_entry_and_case_insensitive():
    table = {"mie-emte": ["ipad16,1"], "pre-mie": []}
    assert classify("iPad16,1", table=table)[
        "mitigation_profile"] == MIE_EMTE
    assert classify("ipad16,1", table=table)["basis"] == "model-table"


def test_classify_echoes_inputs_and_os_major():
    out = classify(hardware_model="X", os_train="iOS 26.1", os_version="")
    assert out["os_major"] == 26
    assert out["os_train"] == "iOS 26.1"


def test_os_major_parsing_edges():
    assert os_major("", "18.5") == 18
    assert os_major("", "26.1") == 26
    assert os_major("", "") is None
    assert os_major("", "junk") is None
    assert os_major("", "9.7") == 9  # single-digit majors still parse


def test_invalid_overrides_fail_validation(workspace):
    path = workspace.path(OVERRIDE_RELPATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    for bad in (
            {"bogus-key": ["x"]},
            {"mie-emte": "not-a-list"},
            {"mie-emte": [42]},
            "not-an-object"):
        path.write_text(json.dumps(bad) if not isinstance(bad, str) else bad)
        with pytest.raises(ValidationError):
            load_model_table(workspace)


# --- matrix integration ---------------------------------------------------------

def test_matrix_cells_carry_mitigation_profile(workspace):
    engine = ReproductionMatrixEngine(workspace)
    run = engine.create(target="mock:parser", input_bytes=CRASHING_INPUT,
                        trials=2, seed=1, cells=_cells("MockPhone"))
    summary = engine.run(engine.get(run.id))
    cell = summary["per_cell"][0]
    assert cell["mitigation_profile"] == UNKNOWN  # no override -> fail closed
    assert summary["mitigation_profiles"] == []
    assert summary["warnings"] == []


def test_matrix_warns_when_generations_mixed(workspace):
    path = workspace.path(OVERRIDE_RELPATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mie-emte": ["MIE*"],
                                "pre-mie": ["OLD*"]}))
    engine = ReproductionMatrixEngine(workspace)
    run = engine.create(target="mock:parser", input_bytes=CRASHING_INPUT,
                        trials=2, seed=1, cells=_cells("MIE-Phone",
                                                       "OLD-Phone"))
    summary = engine.run(engine.get(run.id))
    assert set(summary["mitigation_profiles"]) == {MIE_EMTE, PRE_MIE}
    assert summary["warnings"], "expected a mixed-generation warning"
    # warning is non-binding: reproducible count unchanged by it
    assert summary["reproducible_cells"] >= 0


def test_matrix_no_warning_for_single_generation(workspace):
    path = workspace.path(OVERRIDE_RELPATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mie-emte": ["MockPhone"], "pre-mie": []}))
    engine = ReproductionMatrixEngine(workspace)
    run = engine.create(target="mock:parser", input_bytes=CRASHING_INPUT,
                        trials=2, seed=1, cells=_cells("MockPhone"))
    summary = engine.run(engine.get(run.id))
    assert summary["warnings"] == []
    assert summary["mitigation_profiles"] == [MIE_EMTE]


# --- bounty warnings -------------------------------------------------------------

def _report_with_metadata(ws, metadata):
    result = create("mock:parser").execute(CRASHING_INPUT)
    crash = CrashStore(ws).record(
        experiment_id="e1", target="mock:parser", fmt="mock-record",
        data=CRASHING_INPUT, exec_result=result)
    readiness = BountyReadiness(ws)
    report = readiness.reports.create(crash.id)
    report.sections["affected_versions"]["os_version"] = "26.1"
    return readiness.validate(report, metadata)


def test_bounty_matrix_generation_mismatch_is_warning_not_error(workspace):
    metadata = {
        "contact": "r@example.test",
        "attestations": {"authorized_testing": True},
        "matrix_evidence": [
            {"cell": "a", "mitigation_profile": "pre-mie"},
            {"cell": "b", "mitigation_profile": "mie-emte"},
        ]}
    result = _report_with_metadata(workspace, metadata)
    assert result["ready"] is True, result["missing"]
    assert result["warnings"]
    assert "pre-mie" in result["warnings"][0]
    # no check was added by the warning path
    assert not [c for c in result["checks"]
                if c["id"].startswith("mitigation")]


def test_bounty_single_generation_produces_no_warning(workspace):
    metadata = {
        "contact": "r@example.test",
        "attestations": {"authorized_testing": True},
        "matrix_evidence": [{"mitigation_profile": "mie-emte"}]}
    result = _report_with_metadata(workspace, metadata)
    assert result["ready"] is True
    assert result["warnings"] == []


def test_summarize_profiles_handles_strings_and_dicts():
    entries = ["mie-emte", {"mitigation_profile": "pre-mie"},
               {"mitigation_profile": "unknown"}, None, 42]
    assert summarize_profiles(entries) == [MIE_EMTE, PRE_MIE]
    assert mismatch_warning([{"mitigation_profile": "mie-emte"}]) is None


# --- .ips hardware-model extraction ----------------------------------------------

def test_parse_metadata_hardware_model_modern_json():
    text = json.dumps({"app_name": "x"}) + "\n" + json.dumps({
        "procName": "targetd",
        "modelCode": "iPhone17,2",
        "captureTime": "2026-01-01 00:00:00.000 +0000",
        "exception": {"type": "EXC_BAD_ACCESS"},
    })
    meta = parse_metadata(text)
    assert meta["hardware_model"] == "iPhone17,2"
    assert meta["process"] == "targetd"


def test_parse_metadata_hardware_model_legacy_text():
    text = ("Process: targetd [123]\n"
            "Hardware Model: iPhone14,3\n"
            "OS Version: iPhone OS 17.5 (21F90)\n"
            "Exception Type: EXC_BAD_ACCESS (SIGSEGV)\n")
    meta = parse_metadata(text)
    assert meta["hardware_model"] == "iPhone14,3"
    assert meta["os_build"] == "21F90"
