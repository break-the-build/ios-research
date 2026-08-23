"""Tests for the opt-in SRD backend and its CI fake (#40).

The real ``srd:device`` target is exercised only through its gating/failure
paths (no hardware, no SRD access, ever). All execution behavior — provenance,
lifecycle, determinism, redaction — is covered by the deterministic
``FakeSRDBackend``.
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from ios_research.cli import main
from ios_research.errors import ExitCode, NotFoundError, ValidationError
from ios_research.targets import create, is_registered
from ios_research.targets.base import Outcome
from ios_research.targets.srd import (
    FakeSRDBackend, SRDTarget, SRD_ENV, missing_config_fields)

APPROVED_CONFIG = {
    "approved": True,
    "device_id": "SRD-1234",
    "model": "iPhoneResearch",
    "build": "22G50-fake",
    "authorized_user": "researcher@example.com",
}


# --- gating: unapproved / missing fields ------------------------------------

@pytest.mark.parametrize("config", [
    None,
    {},
    {"approved": False, **{k: "x" for k in APPROVED_CONFIG if k != "approved"}},
    {**APPROVED_CONFIG, "approved": False},
    {**APPROVED_CONFIG, "device_id": ""},
    {k: v for k, v in APPROVED_CONFIG.items() if k != "build"},
])
def test_unapproved_or_incomplete_config_is_blocked_not_fabricated(config):
    t = SRDTarget(config)
    assert t.available() is False
    assert t.missing_fields(), "blocker must name the missing fields"

    blocker = t.blocker()
    assert "IOS_RESEARCH_SRD_CONFIG" in blocker
    for field in t.missing_fields():
        assert field in blocker

    res = t.execute(b"data")
    assert res.outcome == Outcome.ABNORMAL
    assert res.diagnostics is None          # never fabricates a crash
    assert blocker in res.detail


def test_missing_config_fields_helper():
    assert missing_config_fields(None) == \
        ["<entire config>", "device_id", "model", "build", "authorized_user"]
    assert missing_config_fields({"approved": True}) == \
        ["device_id", "model", "build", "authorized_user"]
    assert missing_config_fields(APPROVED_CONFIG) == []


def test_env_var_config_is_loaded_lazily(monkeypatch, tmp_path):
    cfg_file = tmp_path / "srd.json"
    cfg_file.write_text(json.dumps(APPROVED_CONFIG), encoding="utf-8")
    monkeypatch.setenv(SRD_ENV, str(cfg_file))
    # No config passed to the constructor; the env file is read on demand.
    t = SRDTarget()
    assert t.available() is True
    assert t.missing_fields() == []
    prov = t.provenance()
    assert prov["device_id"] == "SRD-1234"


def test_unreadable_env_config_is_a_blocker_not_an_exception(monkeypatch,
                                                             tmp_path):
    monkeypatch.setenv(SRD_ENV, str(tmp_path / "does-not-exist.json"))
    t = SRDTarget()
    assert t.available() is False
    assert "unreadable" in t.blocker()
    res = t.execute(b"data")
    assert res.outcome == Outcome.ABNORMAL
    assert res.diagnostics is None


# --- approved real target: observation-only behavior -------------------------

def test_approved_target_records_observation_only():
    t = SRDTarget(APPROVED_CONFIG)
    assert t.available() is True
    res = t.execute(b"observed-input")
    assert res.outcome == Outcome.ACCEPTED
    assert "observation only" in res.detail
    assert res.diagnostics is None
    ops = [e["op"] for e in t.lifecycle_log]
    assert ops == ["prepare", "run", "cleanup"]


# --- fake backend: determinism, provenance, lifecycle, redaction -------------

def test_fake_backend_run_is_deterministic_on_input_bytes():
    a = FakeSRDBackend().execute(b"deterministic-input")
    b = FakeSRDBackend().execute(b"deterministic-input")
    assert a.to_dict() == b.to_dict()

    other = FakeSRDBackend().execute(b"other-input")
    assert other.outcome in Outcome.ALL


def test_fake_backend_provenance_captures_context_and_evidence_class(workspace):
    backend = FakeSRDBackend(workspace=workspace)
    backend.execute(b"x")
    prov = backend.provenance()
    assert prov["evidence_class"] == "srd"
    assert prov["model"] == FakeSRDBackend._DEFAULT_CONFIG["model"]
    assert prov["build"] == FakeSRDBackend._DEFAULT_CONFIG["build"]
    assert prov["authorized_user"] == "ci-researcher"
    assert prov["tool_versions"]["ios_research"]
    assert prov["mock"] is True
    assert "no exploit" in prov["note"]
    assert "bypass" in prov["note"]


def test_fake_backend_supplied_config_validated_like_real():
    bad = FakeSRDBackend({k: v for k, v in APPROVED_CONFIG.items()
                          if k != "approved"})
    assert bad.available() is False
    res = bad.execute(b"x")
    assert res.outcome == Outcome.ABNORMAL
    assert res.diagnostics is None


def test_secret_shaped_keys_are_redacted_in_exported_dicts():
    leaking = {**APPROVED_CONFIG,
               "api_key": "sk-secret-1", "token": "hunter2",
               "nested": {"password": "p4ss"}}
    backend = FakeSRDBackend(leaking)
    exported = backend.provenance()
    assert exported["config"]["api_key"] == "***REDACTED***"
    assert exported["config"]["token"] == "***REDACTED***"
    assert exported["config"]["nested"]["password"] == "***REDACTED***"
    assert "sk-secret-1" not in json.dumps(exported)
    assert "hunter2" not in json.dumps(backend.describe())


def test_lifecycle_log_is_ordered_prepare_run_cleanup(workspace):
    backend = FakeSRDBackend(workspace=workspace)
    backend.execute(b"input-bytes")
    ops = [e["op"] for e in backend.lifecycle_log]
    assert ops == ["prepare", "run", "cleanup"]
    run_event = backend.lifecycle_log[1]
    assert run_event["mode"] == "fake"


# --- command hooks -----------------------------------------------------------

def test_registered_hook_recorded_in_provenance_when_explicitly_run(workspace):
    backend = FakeSRDBackend(workspace=workspace)
    backend.register_command_hook("list-profiles", lambda: {"argv": ["ls", "-1"],
                                                           "stdout": "a\nb"})
    # Not auto-executed by execute().
    backend.execute(b"q")
    assert backend.provenance()["hooks_run"] == []

    out = backend.run_hook("list-profiles")
    assert out == {"argv": ["ls", "-1"], "stdout": "a\nb"}
    hooks = backend.provenance()["hooks_run"]
    assert len(hooks) == 1
    assert hooks[0]["hook"] == "list-profiles"
    assert len(hooks[0]["output_sha256"]) == 64


def test_unknown_hook_raises_not_found():
    with pytest.raises(NotFoundError):
        FakeSRDBackend().run_hook("ghost-hook")


def test_hook_registration_requires_callable():
    with pytest.raises(ValidationError):
        FakeSRDBackend().register_command_hook("", lambda: None)
    with pytest.raises(ValidationError):
        FakeSRDBackend().register_command_hook("name", "not-callable")


def test_same_hook_output_hashes_identically(workspace):
    a = FakeSRDBackend(workspace=workspace)
    b = FakeSRDBackend(workspace=workspace)
    for backend in (a, b):
        backend.register_command_hook("h", lambda: b"same-output")
        backend.run_hook("h")
    assert (a.provenance()["hooks_run"][0]["output_sha256"]
            == b.provenance()["hooks_run"][0]["output_sha256"])


# --- artifact collection -----------------------------------------------------

def test_artifact_collection_hashes_deterministically_into_store(workspace):
    backend = FakeSRDBackend(workspace=workspace)
    rec1 = backend.collect_artifact("sysdiagnose", b"artifact-bytes")
    rec2 = FakeSRDBackend(workspace=workspace).collect_artifact(
        "sysdiagnose", b"artifact-bytes")

    from ios_research.hashing import sha256_bytes
    expected = sha256_bytes(b"artifact-bytes")
    assert rec1["sha256"] == rec2["sha256"] == expected
    assert rec1["path"] == rec2["path"]
    assert workspace.path(rec1["path"]).is_file()

    different = backend.collect_artifact("sysdiagnose", b"other-bytes")
    assert different["sha256"] != rec1["sha256"]

    prov = backend.provenance()
    names = [a["name"] for a in prov["collected_artifacts"]]
    assert names == ["sysdiagnose", "sysdiagnose"]


def test_artifact_collection_requires_workspace():
    with pytest.raises(ValidationError):
        FakeSRDBackend().collect_artifact("x", b"y")


# --- retail / SRD evidence separation ---------------------------------------

def test_srd_evidence_is_always_tagged_separate_from_retail():
    for target in (SRDTarget(APPROVED_CONFIG), FakeSRDBackend()):
        assert target.provenance()["evidence_class"] == "srd"
        assert target.describe()["evidence_class"] == "srd"


def test_registration_and_kinds():
    assert is_registered("srd:device")
    assert is_registered("srd:fake")
    real = create("srd:device")
    fake = create("srd:fake")
    assert real.mock is False and real.kind == "srd"
    assert fake.mock is True and fake.kind == "srd-fake"
    assert real.target_id == "srd:device"


# --- CLI ----------------------------------------------------------------------

def _run_cli(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(argv)
    return code, json.loads(buf.getvalue())


def test_cli_status_reports_missing_fields(tmp_path):
    ws = tmp_path / ".ios-research"
    code, payload = _run_cli(["init", "--json", "--workspace", str(ws)])
    assert code == ExitCode.OK

    code, payload = _run_cli(["srd", "status", "--json",
                              "--workspace", str(ws)])
    assert code == ExitCode.OK
    assert payload["ok"] is True
    assert payload["data"]["available"] is False
    assert set(payload["data"]["missing_fields"]) >= {
        "approved", "device_id", "model", "build", "authorized_user"}
    assert payload["data"]["target"]["evidence_class"] == "srd"


def test_cli_fake_run_executes_and_returns_provenance(tmp_path):
    ws = tmp_path / ".ios-research"
    assert main(["init", "--json", "--workspace", str(ws)]) == ExitCode.OK
    input_file = tmp_path / "case.bin"
    input_file.write_bytes(b"\x00\x01cli-case")

    code, payload = _run_cli(["srd", "fake-run", "--input-file",
                              str(input_file), "--json",
                              "--workspace", str(ws)])
    assert code == ExitCode.OK
    data = payload["data"]
    assert data["result"]["outcome"] in Outcome.ALL
    prov = data["provenance"]
    assert prov["evidence_class"] == "srd"
    assert prov["build"] == FakeSRDBackend._DEFAULT_CONFIG["build"]

    # Deterministic across invocations.
    _, again = _run_cli(["srd", "fake-run", "--input-file", str(input_file),
                         "--json", "--workspace", str(ws)])
    assert again["data"]["result"] == data["result"]


def test_cli_fake_run_missing_input_file_is_not_found(tmp_path):
    ws = tmp_path / ".ios-research"
    assert main(["init", "--json", "--workspace", str(ws)]) == ExitCode.OK
    code, payload = _run_cli(["srd", "fake-run", "--input-file",
                              str(tmp_path / "missing.bin"), "--json",
                              "--workspace", str(ws)])
    assert code == ExitCode.NOT_FOUND
    assert payload["ok"] is False
