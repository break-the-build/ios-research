"""External engine import adapters and deterministic artifact ingestion (#48)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from ios_research.crashes import CrashStore
from ios_research.hashing import sha256_bytes as sha
from ios_research.engines import (
    EngineImporter, write_libfuzzer_fixture)
from ios_research.errors import NotFoundError, ValidationError


def _workspace():
    from ios_research.workspace import Workspace
    from ios_research import __version__, clock
    ws = Workspace(Path(tempfile.mkdtemp()) / ".ios-research")
    ws.init(framework_version=__version__, created_at=clock.now_iso())
    return ws


def test_two_engines_import_deterministically_preserving_provenance(tmp_path):
    a_ws = _workspace()
    b_ws = _workspace()
    a = EngineImporter(a_ws).import_manifest(
        write_libfuzzer_fixture(tmp_path / "libfuzzer", engine="libfuzzer"))
    b = EngineImporter(b_ws).import_manifest(
        write_libfuzzer_fixture(tmp_path / "aflpp", engine="afl++"))

    assert a["engine"] == "libfuzzer"
    assert b["engine"] == "afl++"
    assert a["crashes_imported"] == b["crashes_imported"] == 1
    assert a["unverified"] == b["unverified"] == 1
    # Deterministic across runs of the same fixture.
    again = EngineImporter(_workspace()).import_manifest(
        write_libfuzzer_fixture(tmp_path / "libfuzzer2", engine="libfuzzer"))
    assert again["findings"][0]["id"] == a["findings"][0]["id"]
    # Provenance preserved on the unverified record.
    record = b_ws.path(f"findings/{b['findings'][0]['id']}/import.json")
    stored = json.loads(record.read_text())
    assert stored["provenance"]["engine"] == "afl++"
    assert stored["provenance"]["source"] == "external-import"
    # Raw sanitizer output is classified without any target.
    assert stored["violation_class"] == "BUFFER_OVERFLOW"
    assert stored["sanitizers"] == ["address"]


def test_hash_mismatch_is_rejected(tmp_path):
    directory = tmp_path / "bad"
    write_libfuzzer_fixture(directory, engine="libfuzzer")
    (directory / "crash-oobs").write_bytes(b"tampered")
    ws = _workspace()
    with pytest.raises(ValidationError, match="sha256 mismatch"):
        EngineImporter(ws).import_manifest(directory / "manifest.json")


def test_missing_hash_field_refuses_import(tmp_path):
    directory = tmp_path / "nohash"
    write_libfuzzer_fixture(directory, engine="libfuzzer")
    manifest = json.loads((directory / "manifest.json").read_text())
    del manifest["artifacts"][0]["sha256"]
    (directory / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValidationError, match="no sha256"):
        EngineImporter(_workspace()).import_manifest(
            directory / "manifest.json")


def test_bad_schema_fails_safely(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version": 99}')
    with pytest.raises(ValidationError):
        EngineImporter(_workspace()).import_manifest(bad)
    not_object = tmp_path / "arr.json"
    not_object.write_text("[]")
    with pytest.raises(ValidationError):
        EngineImporter(_workspace()).import_manifest(not_object)


def test_missing_artifact_cannot_escape_workspace(tmp_path):
    manifest = write_libfuzzer_fixture(tmp_path / "good", engine="x")
    m = json.loads(manifest.read_text())
    m["artifacts"][0]["path"] = "../../../outside/crash"
    escape = tmp_path / "escape.json"
    escape.write_text(json.dumps(m))
    with pytest.raises(NotFoundError):
        EngineImporter(_workspace()).import_manifest(escape)


def test_unknown_target_for_reproduction_rejected(tmp_path):
    manifest = write_libfuzzer_fixture(tmp_path / "eng", engine="libfuzzer")
    with pytest.raises(NotFoundError):
        EngineImporter(_workspace()).import_manifest(
            manifest, target_id="not:a-target", reproduce=True)


def test_reproduced_crash_lands_in_standard_pipeline(workspace, tmp_path):
    """When the declared target can reproduce, evidence flows into crashes/."""
    directory = tmp_path / "jsc-eng"
    payload = b'var x="CRASHMARKER";\n'
    log = ("==1==ERROR: AddressSanitizer: SEGV on unknown address "
           "0x000000000000\nSUMMARY: AddressSanitizer: SEGV s.c:3 in eval\n")
    directory.mkdir()
    (directory / "crash-jsc").write_bytes(payload)
    (directory / "jsc.log").write_text(log)
    manifest = {
        "schema_version": 1,
        "engine": "fuzzilli-bridge",
        "command": "fuzzilli --runs=10",
        "target": "jsc:semantic",
        "artifacts": [{"kind": "crash", "path": "crash-jsc",
                       "sha256": sha(payload), "stderr_log": "jsc.log",
                       "stderr_log_sha256": sha(log.encode())}],
    }
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    out = EngineImporter(workspace).import_manifest(manifest_path,
                                                    reproduce=True)
    assert out["reproduced"] == 1
    crash_store = CrashStore(workspace)
    crashes = crash_store.list(experiment_id=out["experiment_id"])
    assert len(crashes) == 1
    assert crashes[0].lineage["engine"] == "fuzzilli-bridge"
    assert crashes[0].lineage["source"] == "external-import"
