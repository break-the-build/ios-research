"""Opt-in Apple Security Research Device backend (#40).

All coverage runs against the deterministic :class:`FakeSRDBackend` plus
adapter templates pointing at ``{python}``; no SRD hardware, Apple service,
or exploit capability is exercised anywhere.
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from ios_research.cli import main
from ios_research.clock import now_iso
from ios_research.config import Config
from ios_research.errors import SafetyError, StateError, ValidationError
from ios_research.hashing import sha256_bytes
from ios_research.srd import (
    FakeSRDBackend,
    SRDDeviceBackend,
    split_by_channel,
)


def _approval_config(**adapters) -> Config:
    values: dict = {
        "srd": {
            "approved_user": "researcher@example.com",
            "device_model": "iPhoneSRD,42",
            "build": "23A5297f",
            "preview": "iOS 18.0 beta",
            "approval_reference": "SRD-AGREEMENT-2026-042",
        }
    }
    if adapters:
        values["srd"]["adapters"] = adapters
    return Config(values)


def _echo_adapter(script: str) -> dict:
    return {"argv": ["{python}", "-c", script]}


# --- approval gate ---------------------------------------------------------

class TestApprovalGate:
    def test_refuses_without_any_srd_config(self, workspace):
        with pytest.raises(SafetyError) as exc:
            SRDDeviceBackend(Config({}), workspace)
        assert exc.value.exit_code == 5
        assert "missing_keys" in exc.value.details

    def test_partial_config_lists_every_missing_key(self, workspace):
        config = Config({"srd": {"approved_user": "researcher@example.com"}})
        with pytest.raises(SafetyError) as exc:
            SRDDeviceBackend(config, workspace)
        missing = exc.value.details["missing_keys"]
        assert "srd.device_model" in missing
        assert any("build" in key for key in missing)
        assert any("approval" in key for key in missing)

    def test_accepts_preview_without_build(self, workspace):
        config = Config({
            "srd": {
                "approved_user": "u", "device_model": "m",
                "preview": "iOS 19 beta 1",
                "approval_artifact": "/local/path/agreement.pdf",
            }})
        backend = SRDDeviceBackend(config, workspace)
        assert backend.approval["preview"] == "iOS 19 beta 1"
        assert backend.approval["build"] == ""

    def test_non_string_values_are_validation_errors(self, workspace):
        config = Config({"srd": {
            "approved_user": "u", "device_model": "m",
            "build": 12345, "approval_reference": "r"}})
        with pytest.raises(ValidationError):
            SRDDeviceBackend(config, workspace)

    def test_gate_is_explicit_about_never_obtaining_access(self, workspace):
        with pytest.raises(SafetyError) as exc:
            SRDDeviceBackend(Config({}), workspace)
        assert "never obtains SRD access" in exc.value.message


# --- lifecycle with the fake backend ----------------------------------------

class TestFakeBackendLifecycle:
    def test_full_happy_path_idle_to_collected(self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace)
        assert backend.session is None
        session = backend.prepare()
        assert session["state"] == "prepared"
        session = backend.run("demo")
        assert session["state"] == "ran"
        session = backend.collect()
        assert session["state"] == "collected"
        assert session["evidence_channels"] == {"retail": 0, "srd": 1}

    def test_record_persisted_and_marked_fake(self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace)
        session = backend.run("demo")  # auto-prepares
        on_disk = workspace.read_json(f"devices/{session['id']}.json")
        assert on_disk["fake"] is True
        assert on_disk["kind"] == "srd-session"

    def test_prepare_is_idempotent_for_active_sessions(self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace)
        first = backend.prepare()
        second = backend.prepare()
        assert first["id"] == second["id"]

    def test_run_requires_known_adapter(self, workspace):
        # The real backend validates against the configured allowlist; the
        # fake backend deliberately accepts any name (nothing executes).
        backend = SRDDeviceBackend(_approval_config(), workspace)
        with pytest.raises(ValidationError) as exc:
            backend.run("nope")
        assert "(none)" in str(exc.value.message)

    def test_fake_backend_accepts_any_adapter_name(self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace)
        session = backend.run("whatever")
        assert session["state"] == "ran"

    def test_collect_before_run_is_state_error(self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace)
        backend.prepare()
        with pytest.raises(StateError):
            backend.collect()


# --- provenance --------------------------------------------------------------

class TestProvenance:
    def test_record_carries_all_required_fields(self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace)
        provenance = backend.provenance_summary()
        device = provenance["device"]
        user_ctx = provenance["approved_user_context"]
        assert device == {"model": "iPhoneSRD,42", "build": "23A5297f",
                          "preview": "iOS 18.0 beta"}
        assert user_ctx == {"approved_user": "researcher@example.com",
                            "approval_reference": "SRD-AGREEMENT-2026-042"}
        assert provenance["tools"] == FakeSRDBackend.FAKE_TOOLS
        assert provenance["captured_at"] == now_iso()

    def test_real_backend_reports_host_python(self, workspace):
        backend = SRDDeviceBackend(_approval_config(), workspace)
        assert backend.provenance_summary()["tools"]["python"]

    def test_provenance_log_stamps_lifecycle(self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace)
        backend.prepare()
        ops = [e["op"] for e in backend.session["provenance_log"]]
        assert ops == ["prepare"]
        backend.run("demo")
        ops = [e["op"] for e in backend.session["provenance_log"]]
        assert ops == ["prepare", "run"]


# --- redaction -----------------------------------------------------------------

class TestRedaction:
    def test_secret_shaped_output_lines_are_masked(self, workspace):
        script = ("import sys; print('password=hunter2'); "
                  "print('note=clean'); print('api_key=abc123')")
        config = _approval_config(leaky=_echo_adapter(script))
        backend = SRDDeviceBackend(config, workspace)
        entry = backend.run("leaky")["runs"][-1]
        assert "hunter2" not in entry["stdout_tail"]
        assert "abc123" not in entry["stdout_tail"]
        assert "***REDACTED***" in entry["stdout_tail"]
        assert "note=clean" in entry["stdout_tail"]

    def test_fake_backend_output_is_redacted(self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace)
        entry = backend.run("demo")["runs"][-1]
        assert "hunter2" not in entry["stdout_tail"]
        assert "***REDACTED***" in entry["stdout_tail"]

    def test_stderr_tail_redacted_too(self, workspace):
        script = "import sys; sys.stderr.write('session_token=t0psecret\\n')"
        config = _approval_config(noisy=_echo_adapter(script))
        backend = SRDDeviceBackend(config, workspace)
        entry = backend.run("noisy")["runs"][-1]
        assert "t0psecret" not in entry["stderr_tail"]
        assert "***REDACTED***" in entry["stderr_tail"]


# --- failure paths ---------------------------------------------------------------

class TestFailurePaths:
    def test_injected_run_failure_marks_session_failed(self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace,
                                 fail_step="run")
        backend.prepare()
        with pytest.raises(StateError) as exc:
            backend.run("demo")
        assert "injected fake failure" in str(exc.value.message)
        assert backend.session["state"] == "failed"
        ops = [e["op"] for e in backend.session["provenance_log"]]
        assert ops[-1] == "run-failed"
        with pytest.raises(StateError):
            backend.collect()

    def test_injected_prepare_failure(self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace,
                                 fail_step="prepare")
        with pytest.raises(StateError):
            backend.prepare()

    def test_failed_session_then_fresh_prepare_starts_new_session(
            self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace,
                                 fail_step="run")
        backend.prepare()
        failed_id = backend.session["id"]
        with pytest.raises(StateError):
            backend.run("demo")
        fresh = FakeSRDBackend(_approval_config(), workspace).prepare()
        assert fresh["state"] == "prepared"
        assert fresh["id"] != failed_id

    def test_real_adapter_nonzero_exit_is_stable_error(self, workspace):
        script = "import sys; sys.exit(3)"
        config = _approval_config(broken=_echo_adapter(script))
        backend = SRDDeviceBackend(config, workspace)
        with pytest.raises(StateError) as exc:
            backend.run("broken")
        assert exc.value.details["exit_code"] == 3
        assert backend.session["state"] == "failed"

    def test_missing_binary_is_actionable_error(self, workspace):
        config = _approval_config(missing={"argv": ["definitely-not-a-bin"]})
        backend = SRDDeviceBackend(config, workspace)
        with pytest.raises(StateError) as exc:
            backend.run("missing")
        assert "failed to start" in str(exc.value.message)


# --- adapter hooks -----------------------------------------------------------------

class TestAdapterHooks:
    def test_artifact_collected_into_workspace_with_hash(self, workspace):
        config = _approval_config(demo={
            "argv": ["{python}", "-c",
                     "import sys; open(sys.argv[1], 'w').write('body')",
                     "{out}"]})
        backend = SRDDeviceBackend(config, workspace)
        session = backend.run("demo")
        artifact = session["runs"][-1]["artifact"]
        assert artifact["sha256"] == sha256_bytes(b"body")
        blob = workspace.read_bytes(artifact["path"])
        assert blob == b"body"

    def test_adapter_without_out_placeholder_has_no_artifact(self, workspace):
        config = _approval_config(demo=_echo_adapter("print('hi')"))
        backend = SRDDeviceBackend(
            config, workspace,
            tools_fn=lambda: dict(FakeSRDBackend.FAKE_TOOLS))
        session = backend.run("demo")
        assert session["runs"][-1]["artifact"] == {}

    def test_unknown_placeholder_rejected_upfront(self, workspace):
        config = _approval_config(bad={"argv": ["rm", "{home_dir}"]})
        with pytest.raises(ValidationError) as exc:
            SRDDeviceBackend(config, workspace)
        assert "unknown placeholder" in str(exc.value.message)

    def test_shell_style_string_argv_rejected(self, workspace):
        config = _approval_config(shell={"argv": "echo hi > file"})
        with pytest.raises(ValidationError):
            SRDDeviceBackend(config, workspace)

    def test_empty_argv_rejected(self, workspace):
        config = _approval_config(empty={"argv": []})
        with pytest.raises(ValidationError):
            SRDDeviceBackend(config, workspace)

    def test_timeout_bounds_enforced(self, workspace):
        config = _approval_config(slow={"argv": ["x"], "timeout_s": 10_000})
        with pytest.raises(ValidationError):
            SRDDeviceBackend(config, workspace)

    def test_executed_via_argv_list_never_a_shell(self, workspace):
        # Shell metacharacters must arrive as literal argv elements. A shell
        # would interpret '|'/';' as operators; argv execution prints them.
        config = _approval_config(inject={"argv": [
            "{python}", "-c", "import sys; print('|'.join(sys.argv[1:]))",
            "a;b", "|", "/tmp/srd-pwned-marker"]})
        backend = SRDDeviceBackend(
            config, workspace,
            tools_fn=lambda: dict(FakeSRDBackend.FAKE_TOOLS))
        session = backend.run("inject")
        assert session["runs"][-1]["stdout_tail"].strip() == \
            "a;b|||/tmp/srd-pwned-marker"


# --- retail / SRD evidence separation ----------------------------------------------

class TestChannelSeparation:
    def test_entries_partition_disjointly_by_channel(self):
        entries = [
            {"channel": "retail", "tag": "retail:mock-device"},
            {"channel": "srd", "tag": "srd:sysdiagnose-note"},
            {"channel": "srd", "tag": "srd:snapshot"},
        ]
        split = split_by_channel(entries)
        assert len(split["retail"]) == 1
        assert len(split["srd"]) == 2
        ids = [(e["tag"], e["channel"]) for group in split.values()
               for e in group]
        assert len(ids) == len(entries)

    def test_entries_default_to_retail_channel(self):
        split = split_by_channel([{"tag": "retail:x"}])
        assert len(split["retail"]) == 1
        assert split["srd"] == []

    def test_unknown_channel_is_validation_error(self):
        with pytest.raises(ValidationError):
            split_by_channel([{"channel": "carrier"}])

    def test_session_runs_carry_srd_tags_only(self, workspace):
        backend = FakeSRDBackend(_approval_config(), workspace)
        session = backend.run("demo")
        tags = [run["tag"] for run in session["runs"]]
        assert all(tag.startswith("srd:") for tag in tags)


# --- CLI envelope contract -----------------------------------------------------------

def _run_main(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


class TestCli:
    def test_status_unconfigured_is_clean_safety_error(self, tmp_path,
                                                       monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert main(["init", "--json"]) == 0
        code, out = _run_main(["srd", "status", "--json"])
        assert code == 5
        envelope = json.loads(out)
        assert envelope["ok"] is False
        assert envelope["exit_code"] == 5
        assert "opt-in" in envelope["error"]
        assert envelope["error"].startswith("SRD backend")

    def test_status_shows_provenance_when_configured(self, tmp_path,
                                                     monkeypatch, workspace):
        monkeypatch.chdir(str(workspace.root.parent))
        workspace.write_json("config/config.json", {
            "srd": _approval_config().values["srd"]})
        code, out = _run_main(["srd", "status", "--json"])
        assert code == 0
        envelope = json.loads(out)
        assert envelope["ok"] is True
        gate = envelope["data"]["gate"]
        assert gate["approved_user"] == "researcher@example.com"
        provenance = envelope["data"]["provenance"]
        assert provenance["device"]["model"] == "iPhoneSRD,42"
        assert provenance["approved_user_context"]["approval_reference"] == \
            "SRD-AGREEMENT-2026-042"

    def test_run_and_collect_happy_path(self, tmp_path, monkeypatch,
                                        workspace):
        monkeypatch.chdir(str(workspace.root.parent))
        srd = _approval_config(demo=_echo_adapter("print('hello')"))
        workspace.write_json("config/config.json", srd.values)
        code, out = _run_main(["srd", "run", "demo", "--json"])
        assert code == 0
        envelope = json.loads(out)
        assert envelope["data"]["session"]["state"] == "ran"
        code, out = _run_main(["srd", "collect", "--json"])
        assert code == 0
        envelope = json.loads(out)
        assert envelope["data"]["session"]["evidence_channels"]["srd"] == 1
        _, status = _run_main(["srd", "status", "--json"])
        data = json.loads(status)["data"]
        assert data["state"] == "collected"
        assert data["latest_session_id"] == \
            envelope["data"]["session"]["id"]

    def test_run_unknown_adapter_is_validation_error(self, tmp_path,
                                                     monkeypatch, workspace):
        monkeypatch.chdir(str(workspace.root.parent))
        workspace.write_json("config/config.json",
                             _approval_config().values)
        code, out = _run_main(["srd", "run", "ghost", "--json"])
        assert code == 4
        envelope = json.loads(out)
        assert envelope["ok"] is False

    def test_run_failure_propagates_state_error(self, tmp_path, monkeypatch,
                                                workspace):
        monkeypatch.chdir(str(workspace.root.parent))
        srd = _approval_config(
            broken=_echo_adapter("import sys; sys.exit(9)"))
        workspace.write_json("config/config.json", srd.values)
        code, out = _run_main(["srd", "run", "broken", "--json"])
        assert code == 7
        envelope = json.loads(out)
        assert envelope["exit_code"] == 7
        assert envelope["error"].endswith("exited 9")


# The fake backend is intentionally exported for CI reuse; guard against it
# silently drifting from the real interface.

def test_fake_backend_mirrors_real_interface():
    real_methods = {name for name in dir(SRDDeviceBackend)
                    if not name.startswith("_")}
    fake_methods = {name for name in dir(FakeSRDBackend)
                    if not name.startswith("_")}
    assert real_methods <= fake_methods
