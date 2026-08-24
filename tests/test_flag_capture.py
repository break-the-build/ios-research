"""Commpage/TCC Target Flag capture detection tests (#84)."""

from __future__ import annotations

import json

import pytest

from ios_research.bounty import BountyReadiness
from ios_research.crashes import CrashStore
from ios_research.flagcapture import (
    COMM_PAGE64_BASE_ADDRESS, detect_commpage, parse_tccutil_output,
)
from ios_research.targets import create
from ios_research.targetflags import DEFAULT_TAXONOMY, load_taxonomy


# --- fixtures ------------------------------------------------------------------

def _diag(*, registers=None, far="0x0000000000000000",
          pc="0x0000000102dd44e4", exc="EXC_BAD_ACCESS"):
    return {
        "exception_type": exc,
        "faulting_address": far,
        "instruction_address": pc,
        "registers": registers if registers is not None else {
            "pc": pc, "lr": "0x0000000102dd44dc",
            "x0": "0x0", "x1": "0x1",
        },
    }


_SUPPLIED = {
    "value": "0x08ad752109466b05",
    "address": "0x08ad752109466b06",
    "kern_value": "0xfffefd0000001234",
    "kern_address": "0xfffefd00000abcd0",
}


@pytest.fixture
def workspace(tmp_path):
    from ios_research.context import Context
    from ios_research.workspace import Workspace
    from ios_research import __version__
    from ios_research.clock import now_iso
    ws = Workspace(tmp_path / ".ios-research")
    ws.init(framework_version=__version__, created_at=now_iso())
    Context(workspace_path=str(ws.root))
    return ws


def _crash_with_diag(ws, diag):
    """Record a crash whose stored diagnostics carry crafted register state."""
    data = b"MOCK\x01\x01\xff\xff" + b"A" * 20
    result = create("mock:parser").execute(data)
    crash = CrashStore(ws).record(
        experiment_id="e1", target="mock:parser", fmt="mock-record",
        data=data, exec_result=result)
    crash.diagnostics.update(diag)
    CrashStore(ws).save(crash)
    return crash


def _report_for(ws, crash):
    readiness = BountyReadiness(ws)
    report = readiness.reports.create(crash.id)
    report.sections["affected_versions"]["os_version"] = "26.1"
    return readiness, report


# --- taxonomy v2 ---------------------------------------------------------------

def test_taxonomy_v2_includes_pcc_tiers_and_new_element():
    # v3 (#115): registered new target-family keywords; version bumped
    # deliberately so stale cached taxonomies are invalidated.
    assert load_taxonomy(None)["taxonomy_version"] == 3
    ids = {f["id"] for f in DEFAULT_TAXONOMY}
    assert {"pcc-request-data-access", "pcc-privileged-network-request-data",
            "pcc-unattested-code-execution", "pcc-config-disclosure"} <= ids
    # The new evidence element is available to override taxonomies.
    from ios_research.targetflags import _EVIDENCE
    assert "target_flag_capture" in _EVIDENCE
    override = {"version": 9, "flags": [{
        "id": "custom", "label": "C", "entry_point": "t", "outcome": "o",
        "evidence_required": ["target_flag_capture"]}]}
    # validation of the element happens through load_taxonomy's override path;
    # exercise it via a temp workspace below instead of here.
    assert override["version"] == 9


def test_override_taxonomy_may_require_target_flag_capture(workspace):
    override = {"version": 3, "flags": [{
        "id": "capture-flag", "label": "Capture", "entry_point": "browser",
        "outcome": "demo",
        "evidence_required": ["target_flag_capture"]}]}
    path = workspace.path("config/target-flags.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(override))
    taxonomy = load_taxonomy(workspace)
    assert taxonomy["source"] == "workspace-override"
    flag = next(f for f in taxonomy["flags"] if f["id"] == "capture-flag")
    assert flag["evidence_required"] == ["target_flag_capture"]


def test_physical_access_flag_keywords_cover_locked_device_surfaces():
    flag = next(f for f in DEFAULT_TAXONOMY
                if f["id"] == "physical-access-sensitive-data")
    assert {"lockdownd", "usb", "iap2", "notification"} <= set(flag["keywords"])


# --- commpage detection ----------------------------------------------------------

def test_supplied_values_register_control_userspace_high():
    regs = {"pc": "0x100000000", "x8": _SUPPLIED["value"]}
    out = detect_commpage(_diag(registers=regs), supplied=_SUPPLIED)
    assert out == {"mechanism": "commpage", "primitive": "register-control",
                   "space": "userspace", "bit_width": 64,
                   "confidence": "HIGH", "basis": "supplied-values",
                   "register": "x8"}


def test_supplied_values_register_control_kernel_space():
    regs = {"pc": "0xffffff8000000000", "x20": _SUPPLIED["kern_value"]}
    out = detect_commpage(_diag(registers=regs), supplied=_SUPPLIED)
    assert out["space"] == "kernel"
    assert out["primitive"] == "register-control"


def test_supplied_values_arbitrary_read_write_via_far():
    out = detect_commpage(
        _diag(far=_SUPPLIED["address"]), supplied=_SUPPLIED)
    assert out["primitive"] == "arbitrary-read-write"
    assert out["space"] == "userspace"
    assert out["confidence"] == "HIGH"


def test_supplied_values_code_execution_via_pc():
    out = detect_commpage(_diag(pc=_SUPPLIED["kern_address"]),
                          supplied=_SUPPLIED)
    assert out["primitive"] == "code-execution"
    assert out["space"] == "kernel"


def test_structural_low_confidence_read_write_pattern():
    addr = "0x08ad752109466b05"
    regs = {"pc": "0x0000000102dd44e4", "x8": addr}
    out = detect_commpage(_diag(registers=regs, far=addr))
    assert out["confidence"] == "LOW"
    assert out["basis"] == "structural"
    assert out["primitive"] == "arbitrary-read-write"


def test_no_detection_without_match():
    regs = {"pc": "0x0000000102dd44e4", "x0": "0x0"}
    assert detect_commpage(_diag(registers=regs), supplied=_SUPPLIED) is None
    assert detect_commpage(_diag()) is None
    assert detect_commpage({}) is None
    assert detect_commpage(None) is None  # type: ignore[arg-type]


def test_int_inputs_accepted_for_supplied_values():
    value = int(_SUPPLIED["value"], 16)
    out = detect_commpage(_diag(registers={"x3": value}),
                          supplied={"value": value})
    assert out["primitive"] == "register-control"
    assert out["register"] == "x3"


def test_commpage_constants_exposed():
    info_base = COMM_PAGE64_BASE_ADDRESS + 0x320
    assert info_base > COMM_PAGE64_BASE_ADDRESS
    from ios_research.flagcapture import commpage_info
    info = commpage_info()
    assert info["offsets"]["value"] == "0x320"
    assert info["offsets"]["kern_address"] == "0x338"


# --- tccutil parsing -------------------------------------------------------------

def test_parse_tccutil_modified_user():
    out = parse_tccutil_output("User: modified\nSystem: default\n")
    assert out == {"parsed": True, "user": "modified",
                   "system": "default", "captured": True}


def test_parse_tccutil_default_both_is_not_captured():
    out = parse_tccutil_output("User: default\nSystem: default\n")
    assert out["parsed"] is True
    assert out["captured"] is False


def test_parse_tccutil_garbage_is_unparsed_and_not_captured():
    out = parse_tccutil_output("nothing to see here\n")
    assert out["parsed"] is False
    assert out["captured"] is False
    assert parse_tccutil_output("")["captured"] is False


# --- analyze / bounty-validate integration ---------------------------------------

def test_analyze_records_structural_capture(workspace):
    from ios_research.analysis import Analyzer
    addr = "0x08ad752109466b05"
    crash = _crash_with_diag(workspace, _diag(registers={"x8": addr}, far=addr))
    analysis = Analyzer(workspace).analyze(CrashStore(workspace).get(crash.id))
    capture = analysis.extra.get("target_flag_capture")
    assert capture is not None
    assert capture["basis"] == "structural"
    # deterministic: re-running analyze reproduces the same capture block
    again = Analyzer(workspace).analyze(CrashStore(workspace).get(crash.id))
    assert again.extra["target_flag_capture"] == capture


def test_analyze_omits_capture_key_when_no_pattern(workspace):
    from ios_research.analysis import Analyzer
    crash = _crash_with_diag(workspace, _diag())
    analysis = Analyzer(workspace).analyze(CrashStore(workspace).get(crash.id))
    assert "target_flag_capture" not in analysis.extra


def test_bounty_validate_passes_when_no_capture_evidence(workspace):
    readiness, report = _report_for(workspace, _crash_with_diag(workspace, _diag()))
    result = readiness.validate(report, {
        "contact": "r@example.test",
        "attestations": {"authorized_testing": True}})
    assert result["ready"] is True
    assert result["target_flags"]["capture"] is None
    assert "target_flag_capture" not in set(result["missing"])


def test_bounty_validate_binding_tccutil_failure_fails_ready(workspace, tmp_path):
    readiness, report = _report_for(workspace, _crash_with_diag(workspace, _diag()))
    tcc_file = tmp_path / "tcc.txt"
    tcc_file.write_text("User: default\nSystem: default\n")
    result = readiness.validate(report, {
        "contact": "r@example.test",
        "attestations": {"authorized_testing": True}},
        tccutil_output=tcc_file.read_text())
    assert result["ready"] is False
    assert "target_flag_capture" in result["missing"]
    assert result["target_flags"]["tccutil"]["captured"] is False


def test_bounty_validate_binding_tccutil_success_passes(workspace, tmp_path):
    readiness, report = _report_for(workspace, _crash_with_diag(workspace, _diag()))
    tcc_file = tmp_path / "tcc.txt"
    tcc_file.write_text("User: modified\nSystem: default\n")
    result = readiness.validate(report, {
        "contact": "r@example.test",
        "attestations": {"authorized_testing": True}},
        tccutil_output=tcc_file.read_text())
    assert result["ready"] is True
    check = next(c for c in result["checks"]
                 if c["id"] == "target_flag_capture")
    assert check["passed"] is True


def test_element_check_satisfied_by_metadata_capture(workspace):
    readiness, report = _report_for(workspace, _crash_with_diag(workspace, _diag()))
    metadata = {"contact": "r@example.test",
                "attestations": {"authorized_testing": True},
                "target_flags": ["capture-flag"],
                "tccutil_captured": True}
    override = {"version": 3, "flags": [{
        "id": "capture-flag", "label": "Capture", "entry_point": "browser",
        "outcome": "demo", "evidence_required": ["target_flag_capture"]}]}
    path = workspace.path("config/target-flags.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(override))
    result = readiness.validate(report, metadata)
    assert result["ready"] is True, result["missing"]  # element satisfied via metadata
    assert "target_flag:capture-flag:target_flag_capture" \
        not in set(result["missing"])


def test_bounty_validate_uses_supplied_commpage_values(workspace):
    readiness, report = _report_for(
        workspace, _crash_with_diag(workspace, _diag(registers={"x8": "0x08ad752109466b05"})))
    result = readiness.validate(report, {
        "contact": "r@example.test",
        "attestations": {"authorized_testing": True},
        "commpage_values": {
            "value": "0x08ad752109466b05"}})
    capture = result["target_flags"]["capture"]
    assert capture is not None
    assert capture["primitive"] == "register-control"
    assert capture["confidence"] == "HIGH"
    check = next(c for c in result["checks"]
                 if c["id"] == "target_flag_capture")
    assert check["passed"] is True
