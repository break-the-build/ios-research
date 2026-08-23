"""Local-only Apple-bounty readiness and evidence-pack acceptance tests."""

from __future__ import annotations

import json

from ios_research.bounty import BountyReadiness, load_metadata
from ios_research.crashes import CrashStore
from ios_research.targets import create


def _report(workspace):
    data = b"MOCK\x01\x01\xff\xff" + b"A" * 20
    result = create("mock:parser").execute(data)
    crash = CrashStore(workspace).record(
        experiment_id="e1", target="mock:parser", fmt="mock-record",
        data=data, exec_result=result)
    readiness = BountyReadiness(workspace)
    report = readiness.reports.create(crash.id)
    # The controlled test crash has no persisted experiment; a researcher can
    # supply a concrete, non-placeholder platform version in the report.
    report.sections["affected_versions"]["os_version"] = "17.5"
    report.sections["affected_versions"]["device"] = "authorized test device"
    return readiness, report


def test_bounty_readiness_reports_complete_local_evidence(workspace):
    readiness, report = _report(workspace)
    metadata = {
        "contact": "researcher@example.test",
        "attestations": {"authorized_testing": True},
    }
    result = readiness.validate(report, metadata)
    assert result["ready"] is True
    assert all(check["passed"] for check in result["checks"])
    assert "Target Flags" in result["limitations"][1]


def test_bounty_readiness_identifies_insufficient_evidence(workspace):
    readiness, report = _report(workspace)
    report.evidence["minimized_sha256"] = None
    result = readiness.validate(report, {"attestations": {"authorized_testing": False}})
    assert result["ready"] is False
    assert {"minimized_input", "authorized_testing_attestation", "researcher_contact"} <= set(result["missing"])


def test_evidence_pack_is_deterministic_and_redacts_researcher_secrets(workspace, tmp_path):
    readiness, report = _report(workspace)
    metadata = {
        "contact": "researcher@example.test",
        "attestations": {"authorized_testing": True},
        "token": "do-not-export",
        "nested": [{"api_key": "also-secret"}],
    }
    first = readiness.pack(report, metadata)
    second = readiness.pack(report, metadata)
    assert first == second
    assert first["researcher_metadata"]["token"] == "***REDACTED***"
    assert first["researcher_metadata"]["nested"][0]["api_key"] == "***REDACTED***"
    out = readiness.write_pack(report, metadata)
    saved = json.loads(out.read_text())
    assert saved == first
    assert "do-not-export" not in out.read_text()
    archive_paths = [item["archive_path"] for item in saved["artifacts"]]
    assert "evidence/crashes/%s/original-input.bin" % report.crash_id in archive_paths
    assert "evidence/crashes/%s/diagnostics/diagnostics.json" % report.crash_id in archive_paths
    assert (out.parent / "evidence" / "crashes" / report.crash_id / "original-input.bin").is_file()


def test_evidence_pack_rejects_missing_or_escaped_workspace_artifacts(workspace):
    readiness, report = _report(workspace)
    diagnostic = workspace.path(report.evidence["diagnostic_reference"])
    diagnostic.unlink()
    from ios_research.errors import ValidationError
    import pytest
    with pytest.raises(ValidationError, match="required evidence artifact is missing"):
        readiness.write_pack(report)

    # A crafted report ID cannot turn the fixed evidence paths into a traversal.
    report.crash_id = "../outside"
    with pytest.raises(ValidationError, match="workspace"):
        readiness.pack(report)


def test_bounty_metadata_must_be_a_json_object(tmp_path):
    metadata = tmp_path / "metadata.json"
    metadata.write_text("[]", encoding="utf-8")
    from ios_research.errors import ValidationError
    import pytest
    with pytest.raises(ValidationError):
        load_metadata(str(metadata))
