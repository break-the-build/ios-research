"""External fuzzer-engine adapters and artifact ingestion (#48)."""

from __future__ import annotations

import json

import pytest

from ios_research.engine_import import (
    EngineImporter, load_manifest,
)
from ios_research.errors import ValidationError
from ios_research.fuzz import FuzzEngine


ASAN_LOG = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
READ of size 4 at 0x602000000010 thread T0
    #0 0x102a4f1 in parse_record pdf/decode.c:120
    #1 0x102b882 in main driver/main.c:44
SUMMARY: AddressSanitizer: heap-buffer-overflow pdf/decode.c:120
"""


def _libfuzzer_fixture(tmp_path):
    """A libFuzzer-style campaign: crash artifact + ASan log + corpus."""
    (tmp_path / "crash-0xdeadbeef").write_bytes(b"LIBFUZZER-CRASH-INPUT")
    (tmp_path / "asan-crash.log").write_text(ASAN_LOG, encoding="utf-8")
    (tmp_path / "corpusdir").mkdir()
    (tmp_path / "corpusdir" / "seed000").write_bytes(b"\x89PNG\r\n\x1a\n")
    manifest = {
        "schema_version": 1,
        "kind": "engine-campaign",
        "engine": {"name": "libfuzzer", "version": "17.0",
                   "command": ["./fuzz", "-runs=1000", "./corpus"]},
        "target": {"id": "custom:pdf", "fmt": "pdf"},
        "stats": {"executions": 12000},
        "findings": [{"input": "crash-0xdeadbeef",
                      "sanitizer_output": "asan-crash.log"}],
        "corpus": ["corpusdir/seed000"],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _afl_fixture(tmp_path):
    """An AFL++-style campaign: id: naming, no sanitizer log."""
    (tmp_path / "id:000000,sig:06,src:000001").write_bytes(b"AFL-CRASH-INPUT")
    manifest = {
        "schema_version": 1,
        "kind": "engine-campaign",
        "engine": {"name": "aflpp", "version": "4.09"},
        "findings": [{"input": "id:000000,sig:06,src:000001",
                      "detail": "crashes target deterministically"}],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


# --- acceptance: two engines import deterministically --------------------------

def test_libfuzzer_import_preserves_provenance_and_triage(workspace, tmp_path):
    manifest = _libfuzzer_fixture(tmp_path)
    summary = EngineImporter(workspace).import_manifest(manifest)

    assert summary["engine"]["name"] == "libfuzzer"
    assert len(summary["crashes"]) == 1
    crash = workspace.path(
        "crashes", summary["crashes"][0], "crash.json")
    record = json.loads(crash.read_text())
    assert record["lineage"]["engine"] == "libfuzzer"
    assert record["lineage"]["artifact"] == "crash-0xdeadbeef"
    assert record["lineage"]["sanitizer_output"] == "asan-crash.log"
    assert record["lineage"]["origin"] == "engine-import"
    # Normalized multi-sanitizer triage from the attached ASan log.
    assert record["signature"].startswith("address_BUFFER_OVERFLOW_")
    assert record["classification"] == "OUT_OF_BOUNDS_READ"
    assert record["diagnostics"]["exception_type"] == "BUFFER_OVERFLOW"
    assert record["diagnostics"]["stack_trace"]


def test_aflpp_import_without_sanitizer_log_uses_filename_metadata(
        workspace, tmp_path):
    manifest = _afl_fixture(tmp_path)
    summary = EngineImporter(workspace).import_manifest(manifest)

    record = json.loads(workspace.path(
        "crashes", summary["crashes"][0], "crash.json").read_text())
    assert record["lineage"]["engine"] == "aflpp"
    assert record["diagnostics"]["signal"] == "SIGSEGV"
    assert record["classification"] == "SEGV_OR_NULL_DEREF"
    assert record["input_sha256"]


def _fresh_workspace(tmp_path):
    from ios_research import __version__
    from ios_research.clock import now_iso
    from ios_research.workspace import Workspace
    ws = Workspace(tmp_path / f"ws-{_fresh_workspace.counter}")
    _fresh_workspace.counter += 1
    ws.init(framework_version=__version__, created_at=now_iso())
    return ws


_fresh_workspace.counter = 0


def test_two_workspaces_produce_identical_summaries(tmp_path):
    manifest = _libfuzzer_fixture(tmp_path)
    first = EngineImporter(_fresh_workspace(tmp_path)).import_manifest(
        manifest)
    second = EngineImporter(_fresh_workspace(tmp_path)).import_manifest(
        manifest)
    assert first == second
    assert first["manifest_sha256"] == second["manifest_sha256"]


def test_reimport_dedupes_by_signature(workspace, tmp_path):
    manifest = _libfuzzer_fixture(tmp_path)
    importer = EngineImporter(workspace)
    first = importer.import_manifest(manifest)
    second = importer.import_manifest(manifest)
    assert len(first["crashes"]) == 1
    assert not any(c in first["crashes"] for c in second["crashes"])
    assert second["crash_deduped"] == first["crashes"]


def test_corpus_artifacts_are_content_addressed(workspace, tmp_path):
    manifest = _libfuzzer_fixture(tmp_path)
    summary = EngineImporter(workspace).import_manifest(manifest)
    assert summary["corpus_artifacts"] == 1
    listing = EngineImporter(workspace).list_imports()
    assert listing and listing[0]["import_id"] == summary["import_id"]


def test_existing_experiment_is_reused_when_requested(workspace, tmp_path):
    from ios_research.experiment import ExperimentStore
    exp = ExperimentStore(workspace).create(
        target="custom:pdf", device="external:libfuzzer",
        os_version="unknown", config_hash="fixed", seed=0)
    manifest = _libfuzzer_fixture(tmp_path)
    data = json.loads(manifest.read_text())
    data["experiment_id"] = exp.id
    manifest.write_text(json.dumps(data), encoding="utf-8")

    summary = EngineImporter(workspace).import_manifest(manifest)
    assert summary["experiment_id"] == exp.id


# --- malformed archives fail safely ---------------------------------------------

def _write(tmp_path, payload) -> str:
    path = tmp_path / "bad-manifest.json"
    path.write_text(payload if isinstance(payload, str)
                    else json.dumps(payload), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("payload", [
    "not json at all",
    [],
    {"kind": "engine-campaign"},
    {"schema_version": 99, "kind": "engine-campaign", "engine": {}},
    {"schema_version": 1, "kind": "other-campaign", "engine": {"name": "x"}},
    {"schema_version": 1, "kind": "engine-campaign"},
    {"schema_version": 1, "kind": "engine-campaign",
     "engine": {"name": "x"}, "findings": [{"detail": "no input path"}]},
])
def test_malformed_manifests_are_rejected(tmp_path, payload):
    with pytest.raises(ValidationError):
        load_manifest(_write(tmp_path, payload))


def test_finding_paths_cannot_escape_the_manifest_directory(
        workspace, tmp_path):
    outside = tmp_path.parent / "outside-secret.bin"
    outside.write_bytes(b"secret")
    manifest = {
        "schema_version": 1, "kind": "engine-campaign",
        "engine": {"name": "libfuzzer"},
        "findings": [{"input": "../outside-secret.bin", "detail": "x"}],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValidationError, match="escapes|relative"):
        EngineImporter(workspace).import_manifest(path)


def test_absolute_artifact_paths_are_rejected(workspace, tmp_path):
    manifest = {
        "schema_version": 1, "kind": "engine-campaign",
        "engine": {"name": "libfuzzer"},
        "findings": [{"input": "/etc/passwd", "detail": "x"}],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValidationError, match="relative"):
        EngineImporter(workspace).import_manifest(path)


def test_missing_or_oversized_artifacts_fail_closed(workspace, tmp_path):
    manifest = {
        "schema_version": 1, "kind": "engine-campaign",
        "engine": {"name": "libfuzzer"},
        "findings": [{"input": "does-not-exist", "detail": "x"}],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValidationError, match="missing"):
        EngineImporter(workspace).import_manifest(path)


# --- CLI envelope ----------------------------------------------------------------

def test_engine_cli_roundtrip(workspace, tmp_path, capsys):
    from ios_research.cli import main
    from ios_research.errors import ExitCode
    manifest = _libfuzzer_fixture(tmp_path)
    ws = ["--workspace", str(workspace.root)]
    code = main([*ws, "engine", "import", str(manifest), "--json"])
    captured = capsys.readouterr().out
    assert code == 0
    env = json.loads(captured)
    assert env["ok"] is True
    assert env["data"]["engine"]["name"] == "libfuzzer"

    code = main([*ws, "engine", "list", "--json"])
    env = json.loads(capsys.readouterr().out)
    assert code == 0
    assert env["data"]["count"] == 1
