"""Phase 01 tests: init/doctor/config/device/target/experiment."""

from __future__ import annotations

import json

import pytest

from ios_research.cli import main
from ios_research.errors import ExitCode
from ios_research.artifacts import ArtifactStore
from ios_research.experiment import ExperimentStore


def run_json(argv, workspace):
    """Run the CLI against ``workspace`` and return (exit_code, envelope)."""
    import io
    import contextlib
    buf = io.StringIO()
    argv = [*argv, "--json", "--workspace", str(workspace.root)]
    with contextlib.redirect_stdout(buf):
        code = main(argv)
    return code, json.loads(buf.getvalue())


# --- init -----------------------------------------------------------------
def test_init_creates_workspace(tmp_path):
    ws_path = tmp_path / ".ios-research"
    code = main(["init", "--json", "--workspace", str(ws_path)])
    assert code == ExitCode.OK
    assert (ws_path / "workspace.json").exists()
    assert (ws_path / "config" / "config.json").exists()


def test_init_twice_fails_without_force(tmp_path):
    ws_path = tmp_path / ".ios-research"
    main(["init", "--json", "--workspace", str(ws_path)])
    code = main(["init", "--json", "--workspace", str(ws_path)])
    assert code == ExitCode.VALIDATION


def test_global_flags_before_subcommand_are_not_clobbered(tmp_path, capsys):
    """Regression: subparser defaults reset globals parsed before the verb."""
    ws_path = tmp_path / ".ios-research"
    assert main(["--workspace", str(ws_path), "init"]) == ExitCode.OK
    capsys.readouterr()  # drain the human-readable init output
    assert (ws_path / "workspace.json").exists()

    code = main(["--workspace", str(ws_path), "--json", "doctor"])
    captured = capsys.readouterr().out
    assert code == ExitCode.OK
    payload = json.loads(captured)
    assert payload["ok"] is True
    assert payload["data"]["workspace_initialized"] is True


# --- doctor ---------------------------------------------------------------
def test_doctor_reports_workspace(workspace):
    code, env = run_json(["doctor"], workspace)
    assert env["data"]["workspace_initialized"] is True


# --- config ---------------------------------------------------------------
def test_config_set_and_get(workspace):
    _, env = run_json(["config", "set", "fuzz.workers", "8"], workspace)
    assert env["data"]["value"] == 8
    _, env2 = run_json(["config", "get", "fuzz.workers"], workspace)
    assert env2["data"]["value"] == 8


def test_config_hash_changes_with_values(workspace):
    _, before = run_json(["config", "hash"], workspace)
    run_json(["config", "set", "fuzz.workers", "8"], workspace)
    _, after = run_json(["config", "hash"], workspace)
    assert before["data"]["config_hash"] != after["data"]["config_hash"]


# --- device / target ------------------------------------------------------
def test_device_list(workspace):
    _, env = run_json(["device", "list"], workspace)
    ids = [d["id"] for d in env["data"]["devices"]]
    assert "mock:device" in ids


def test_device_show_unknown_is_not_found(workspace):
    code, env = run_json(["device", "show", "nope"], workspace)
    assert code == ExitCode.NOT_FOUND


def test_target_list_and_show(workspace):
    _, env = run_json(["target", "list"], workspace)
    assert env["data"]["count"] >= 1
    _, env2 = run_json(["target", "show", "mock:parser"], workspace)
    assert env2["data"]["target"]["id"] == "mock:parser"


# --- experiment -----------------------------------------------------------
def test_experiment_create_is_reproducible_fields(workspace):
    _, env = run_json(["experiment", "create"], workspace)
    exp = env["data"]["experiment"]
    for key in ("id", "created_at", "target", "device", "os_version",
                "framework_version", "config_hash"):
        assert exp[key]


def test_experiment_create_list_show(workspace):
    _, env = run_json(["experiment", "create"], workspace)
    exp_id = env["data"]["experiment"]["id"]
    _, listed = run_json(["experiment", "list"], workspace)
    assert any(e["id"] == exp_id for e in listed["data"]["experiments"])
    _, shown = run_json(["experiment", "show", exp_id], workspace)
    assert shown["data"]["experiment"]["id"] == exp_id


def test_experiment_unknown_target_is_usage_error(workspace):
    code, env = run_json(["experiment", "create", "--target", "bogus:x"], workspace)
    assert code == ExitCode.USAGE


# --- artifact store -------------------------------------------------------
def test_artifact_store_is_content_addressed(workspace):
    store = ArtifactStore(workspace)
    a = store.put(b"hello", kind="testcase")
    b = store.put(b"hello", kind="testcase")
    assert a.sha256 == b.sha256
    assert store.get_bytes(a.sha256) == b"hello"
    assert store.exists(a.sha256)


def test_global_flags_before_subcommand_are_kept():
    """Regression: subparser defaults must not clobber pre-subcommand flags."""
    from ios_research.cli import build_parser
    args = build_parser().parse_args(
        ["--workspace", "/tmp/ws-a", "--json", "target", "list"])
    assert getattr(args, "workspace_path", None) == "/tmp/ws-a"
    assert getattr(args, "as_json", False) is True


def test_global_flags_absent_leave_namespace_clean():
    from ios_research.cli import build_parser
    args = build_parser().parse_args(["target", "list"])
    assert getattr(args, "workspace_path", None) is None
    assert getattr(args, "as_json", False) is False
