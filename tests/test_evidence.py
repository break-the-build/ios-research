"""Researcher-recorded evidence import: sysdiagnose refs, videos, logs (#38)."""

from __future__ import annotations

import pytest

from ios_research.bounty import BountyReadiness
from ios_research.crashes import CrashStore
from ios_research.evidence import EvidenceStore
from ios_research.errors import NotFoundError, ValidationError
from ios_research.targets import create


def _crash(workspace):
    data = b"MOCK\x01\x01\xff\xff" + b"A" * 20
    result = create("mock:parser").execute(data)
    return CrashStore(workspace).record(
        experiment_id="e1", target="mock:parser", fmt="mock-record",
        data=data, exec_result=result)


def _report(workspace, crash):
    readiness = BountyReadiness(workspace)
    report = readiness.reports.create(crash.id)
    report.sections["affected_versions"]["os_version"] = "17.5"
    report.sections["affected_versions"]["device"] = "authorized test device"
    return readiness, report


@pytest.fixture()
def crash(workspace):
    return _crash(workspace)


def test_import_hashes_and_copies_artifact(workspace, tmp_path, crash):
    store = EvidenceStore(workspace)
    artifact = tmp_path / "sysdiagnose.tar.gz"
    artifact.write_bytes(b"SYSDIAGNOSE-BYTES")
    item = store.import_file(crash.id, artifact, "sysdiagnose",
                             device_id="mock:device", build="21A123",
                             process="MobileSafari",
                             captured_at="2026-08-01T12:00:00")
    assert item["sha256"]
    stored = workspace.path(item["file"])
    assert stored.is_file()
    assert store.verify_integrity(item["id"])
    again = store.get(item["id"])
    assert again["source"] == "researcher-supplied"
    assert again["linked_crash_id"] == crash.id


def test_video_requires_explicit_redaction_ack(workspace, tmp_path, crash):
    store = EvidenceStore(workspace)
    clip = tmp_path / "repro.mov"
    clip.write_bytes(b"VIDEO")
    with pytest.raises(ValidationError, match="redaction-ack"):
        store.import_file(crash.id, clip, "video")
    item = store.import_file(crash.id, clip, "video", redaction_ack=True,
                             captured_at="2026-08-01T11:59:00")
    assert item["redaction_ack"] is True
    assert any("personal data" in w for w in item["warnings"])


def test_correlation_uses_researcher_timestamp(workspace, tmp_path, crash):
    store = EvidenceStore(workspace)
    log = tmp_path / "crash.log"
    log.write_bytes(b"LOG")
    bad_time = store.import_file(crash.id, log, "crash-log",
                                 captured_at="not-a-date")
    assert "no delta" in bad_time["correlation"]["note"]

    from ios_research.clock import now_iso
    good = store.import_file(crash.id, log, "syslog",
                             captured_at=now_iso())
    assert isinstance(good["correlation"].get("delta_seconds"), float)


def test_unknown_kind_and_missing_file_rejected(workspace, tmp_path, crash):
    store = EvidenceStore(workspace)
    with pytest.raises(ValidationError):
        store.import_file(crash.id, tmp_path / "x.bin", "vhs")
    with pytest.raises(NotFoundError):
        store.import_file(crash.id, tmp_path / "missing.bin", "other")


def test_traversal_names_and_bad_crash_ids_rejected(workspace, tmp_path):
    store = EvidenceStore(workspace)
    source = tmp_path / "f.bin"
    source.write_bytes(b"x")
    with pytest.raises(ValidationError):
        store.import_file("../outside", source, "other")
    with pytest.raises((NotFoundError, ValidationError)):
        store.import_file("crash_does_not_exist_12345", source, "other")


def test_list_filters_by_crash(workspace, tmp_path, crash):
    store = EvidenceStore(workspace)
    a = tmp_path / "a.log"
    a.write_bytes(b"A")
    b = tmp_path / "b.log"
    b.write_bytes(b"B")
    item_a = store.import_file(crash.id, a, "syslog")
    other = store.import_file(crash.id, b, "crash-log")
    listed = store.list(crash.id)
    ids = {i["id"] for i in listed}
    assert {item_a["id"], other["id"]} <= ids
    assert all(i["linked_crash_id"] == crash.id for i in listed)


def test_integrity_detects_tampering(workspace, tmp_path, crash):
    store = EvidenceStore(workspace)
    f = tmp_path / "e.bin"
    f.write_bytes(b"original")
    item = store.import_file(crash.id, f, "other")
    workspace.path(item["file"]).write_bytes(b"tampered")
    assert store.verify_integrity(item["id"]) is False


def test_bounty_pack_lists_attached_evidence_separately(
        workspace, tmp_path, crash):
    store = EvidenceStore(workspace)
    art = tmp_path / "sysd.tar.gz"
    art.write_bytes(b"EVIDENCE")
    item = store.import_file(crash.id, art, "sysdiagnose")

    readiness, report = _report(workspace, crash)
    metadata = {"attestations": {"authorized_testing": True},
                "contact": "researcher@example.test"}
    pack = readiness.pack(report, metadata)
    entries = pack["attached_evidence"]
    assert [e["id"] for e in entries] == [item["id"]]
    assert entries[0]["integrity_ok"] is True
