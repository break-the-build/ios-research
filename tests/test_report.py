"""Phase 08 tests: vulnerability reporting."""

from __future__ import annotations

from ios_research.crashes import CrashStore
from ios_research.report import ReportGenerator, render_markdown, _REQUIRED_SECTIONS
from ios_research.targets import create
from ios_research.targets.base import Outcome
from ios_research.triage import Triage


def _crash(workspace, data=b"MOCK\x01\x01\xff\xff" + b"A" * 40):
    store = CrashStore(workspace)
    res = create("mock:parser").execute(data)
    assert res.outcome == Outcome.CRASH
    return store.record(experiment_id="exp1", target="mock:parser",
                        fmt="mock-record", data=data, exec_result=res)


def test_report_has_all_required_sections(workspace):
    crash = _crash(workspace)
    report = ReportGenerator(workspace).create(crash.id)
    for section in _REQUIRED_SECTIONS:
        assert section in report.sections
        assert report.sections[section] not in (None, "", [], {})


def test_report_evidence_traces_to_artifacts(workspace):
    crash = _crash(workspace)
    report = ReportGenerator(workspace).create(crash.id)
    ev = report.evidence
    assert ev["crash_id"] == crash.id
    assert ev["experiment_id"] == "exp1"
    assert ev["input_sha256"] == crash.input_sha256
    assert ev["crash_signature"] == crash.signature


def test_report_validates_clean(workspace):
    crash = _crash(workspace)
    gen = ReportGenerator(workspace)
    report = gen.create(crash.id)
    assert gen.validate(report)["valid"] is True


def test_validation_flags_missing_evidence(workspace):
    crash = _crash(workspace)
    gen = ReportGenerator(workspace)
    report = gen.create(crash.id)
    report.evidence["input_sha256"] = ""  # corrupt evidence
    result = gen.validate(report)
    assert result["valid"] is False
    assert any("input_sha256" in i for i in result["issues"])


def test_validation_flags_overclaimed_exploitability(workspace):
    crash = _crash(workspace)
    gen = ReportGenerator(workspace)
    report = gen.create(crash.id)
    report.sections["exploitability_assessment"]["indicator"] = \
        "CODE_EXECUTION_INDICATOR"  # overclaim vs analysis
    result = gen.validate(report)
    assert result["valid"] is False
    assert any("exploitability" in i for i in result["issues"])


def test_validation_flags_empty_section(workspace):
    # An empty (not None) required section must be flagged as missing.
    crash = _crash(workspace)
    gen = ReportGenerator(workspace)
    report = gen.create(crash.id)
    report.sections["security_impact"] = ""       # present but empty
    result = gen.validate(report)
    assert result["valid"] is False
    assert any("security_impact" in i for i in result["issues"])
    # Also empty list/dict sections.
    report2 = gen.create(crash.id)
    report2.sections["reproduction_steps"] = []
    assert gen.validate(report2)["valid"] is False


def test_validation_flags_forbidden_content(workspace):
    crash = _crash(workspace)
    gen = ReportGenerator(workspace)
    report = gen.create(crash.id)
    report.sections["security_impact"] += " includes shellcode"
    result = gen.validate(report)
    assert result["valid"] is False
    assert any("forbidden" in i for i in result["issues"])


def test_markdown_export_mentions_disclosure_and_no_weaponization(workspace):
    crash = _crash(workspace)
    report = ReportGenerator(workspace).create(crash.id)
    md = render_markdown(report)
    assert "responsible disclosure" in md.lower()
    assert "No weaponized exploit code" in md
    assert crash.signature in md


def test_report_includes_minimized_when_available(workspace):
    crash = _crash(workspace)
    Triage(workspace).minimize(crash)
    report = ReportGenerator(workspace).create(crash.id)
    assert report.evidence["minimized_sha256"]


def test_report_completes_evidence_from_raw_crash(workspace):
    # A report on a raw (un-reproduced, un-minimized) crash auto-completes its
    # evidence: minimized artifact present and reproducibility confirmed.
    crash = _crash(workspace)
    assert crash.minimized_sha256 is None and crash.reproduced is None
    gen = ReportGenerator(workspace)
    report = gen.create(crash.id)
    assert report.evidence["minimized_sha256"]          # was auto-minimized
    updated = gen.crashes.get(crash.id)
    assert updated.reproduced is True                   # was auto-reproduced
    assert updated.minimized_sha256
    # Evidence completeness now meets goal 17's >= 0.95 bar (all core fields set).
    core = ("input_sha256", "minimized_sha256", "crash_signature", "analysis_id")
    assert all(report.evidence.get(f) for f in core)
    assert gen.validate(report)["valid"] is True


def test_report_create_is_idempotent(workspace):
    # Generating twice does not change the minimized evidence.
    crash = _crash(workspace)
    gen = ReportGenerator(workspace)
    r1 = gen.create(crash.id)
    r2 = gen.create(crash.id)
    assert r1.evidence["minimized_sha256"] == r2.evidence["minimized_sha256"]
