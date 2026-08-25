"""Tests for issue #268: agent ergonomics.

Covers workspace pinning via the ``IOS_RESEARCH_WORKSPACE`` environment
variable (precedence: explicit ``--workspace`` flag > env var > cwd fallback)
and the operational schema hints (``examples``, ``time_bounds``, ``next``)
added to the pipeline command groups.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ios_research import __version__
from ios_research.cli import build_parser
from ios_research.clock import now_iso
from ios_research.context import Context
from ios_research.errors import NotFoundError
from ios_research.schema import build_cli_schema
from ios_research.workspace import Workspace

# Pipeline command groups that must carry operational hints (#268).
PIPELINE_GROUPS = ("fuzz", "campaign", "research", "agent")


def _init_workspace(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name / ".ios-research"
    Workspace(root).init(framework_version=__version__, created_at=now_iso())
    return root


# --- workspace pinning ------------------------------------------------------
def test_workspace_pinning_precedence(tmp_path, monkeypatch):
    flag_root = _init_workspace(tmp_path, "flag")
    env_root = _init_workspace(tmp_path, "env")

    # The env var pins the workspace when no --workspace flag is given.
    monkeypatch.setenv("IOS_RESEARCH_WORKSPACE", str(env_root))
    assert Context().workspace().root == env_root.resolve()

    # An explicit --workspace flag outranks the environment variable.
    flagged = Context(workspace_path=str(flag_root))
    assert flagged.workspace().root == flag_root.resolve()


def test_workspace_cwd_fallback_when_unpinned(tmp_path, monkeypatch):
    env_root = _init_workspace(tmp_path, "env")
    monkeypatch.delenv("IOS_RESEARCH_WORKSPACE", raising=False)
    # With neither flag nor env var, resolution stays cwd-relative.
    monkeypatch.chdir(tmp_path / "env")  # parent of .ios-research
    assert Context().workspace().root == env_root.resolve()


def test_workspace_env_var_requires_initialized_marker(tmp_path, monkeypatch):
    missing = tmp_path / "missing" / ".ios-research"
    monkeypatch.setenv("IOS_RESEARCH_WORKSPACE", str(missing))
    with pytest.raises(NotFoundError):
        Context().workspace()
    # Non-required lookups tolerate an uninitialized pinned path (same
    # behaviour as an explicit --workspace pointing at a fresh directory).
    ws = Context().workspace(required=False)
    assert ws is not None and ws.root == missing.resolve()


def test_workspace_env_var_empty_string_is_ignored(tmp_path, monkeypatch):
    env_root = _init_workspace(tmp_path, "env")
    monkeypatch.setenv("IOS_RESEARCH_WORKSPACE", "")
    monkeypatch.chdir(tmp_path / "env")
    # "" must fall through to the cwd fallback, not resolve to the empty path.
    assert Context().workspace().root == env_root.resolve()


# --- operational schema hints -------------------------------------------------
def test_pipeline_groups_carry_time_bounds():
    schema = build_cli_schema()
    for group in PIPELINE_GROUPS:
        subs = schema["commands"][group].get("subcommands", {})
        assert subs, f"expected subcommands under '{group}'"
        for name, entry in subs.items():
            time_bounds = entry.get("time_bounds")
            assert isinstance(time_bounds, dict), f"{group} {name}"
            assert isinstance(time_bounds.get("blocking"), bool), \
                f"{group} {name}"


def test_examples_are_valid_argv_with_envelope_shape():
    schema = build_cli_schema()
    parser = build_parser()
    contract_keys = set(schema["json_output_contract"]["envelope"])
    checked = 0
    for group in PIPELINE_GROUPS:
        for name, entry in schema["commands"][group]["subcommands"].items():
            for example in entry.get("examples", []):
                argv = example["argv"]
                assert argv[0] == "ios-research"
                parser.parse_args(argv[1:])  # examples must parse
                assert set(example["envelope"]) == contract_keys
                assert example["envelope"]["command"] == f"{group} {name}"
                checked += 1
    assert checked >= 4  # every key pipeline command carries at least one


def test_key_pipeline_commands_have_examples_and_next_steps():
    commands = build_cli_schema()["commands"]
    for path in ("fuzz start", "fuzz resume", "campaign export",
                 "research create", "agent run"):
        group, _, name = path.partition(" ")
        entry = commands[group]["subcommands"][name]
        assert entry["examples"], path
        assert entry["next"], path


def test_time_bounds_flag_hints_for_long_runners():
    commands = build_cli_schema()["commands"]
    # fuzz start blocks and names its budget flags (#268).
    fuzz_bounds = commands["fuzz"]["subcommands"]["start"]["time_bounds"]
    assert fuzz_bounds["blocking"] is True
    for flag in ("--max-cases", "--duration", "--chunk"):
        assert flag in fuzz_bounds["bounds"]
    # research run blocks until sliced via --max-stages.
    research_bounds = commands["research"]["subcommands"]["run"]["time_bounds"]
    assert research_bounds["blocking"] is True
    assert "--max-stages" in research_bounds["bounds"]
    assert "--yes" in research_bounds["note"]  # destructive gate surfaced
    # agent run is bounded end-to-end by --max-cases.
    agent_bounds = commands["agent"]["subcommands"]["run"]["time_bounds"]
    assert agent_bounds["blocking"] is True
    assert "--max-cases" in agent_bounds["bounds"]
    # status-style commands report non-blocking.
    assert commands["research"]["subcommands"]["status"][
        "time_bounds"]["blocking"] is False


def test_committed_cli_schema_matches_generator():
    schema_path = (Path(__file__).resolve().parents[1]
                   / "docs" / "cli-schema.json")
    committed = json.loads(schema_path.read_text(encoding="utf-8"))
    assert committed == build_cli_schema()
