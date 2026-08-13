"""Phase 07 tests: LLM-agent interface and CLI schema."""

from __future__ import annotations

import json

from ios_research.agent import Agent
from ios_research.context import Context
from ios_research.schema import build_cli_schema, EXIT_CODES
from ios_research.cli import main


def _ctx(workspace) -> Context:
    return Context(workspace_path=str(workspace.root), assume_yes=True)


def test_schema_lists_all_commands_and_contract():
    schema = build_cli_schema()
    for cmd in ("init", "fuzz", "crash", "analyze", "diff", "agent"):
        assert cmd in schema["commands"]
    assert schema["json_output_contract"]["envelope"][0] == "ok"
    assert schema["exit_codes"] == EXIT_CODES
    assert schema["safety_boundary"]["authorized_research_only"] is True
    assert "CODE_EXECUTION_INDICATOR" in schema["exploitability_indicators"]


def test_agent_status_reports_counts(workspace):
    status = Agent(_ctx(workspace)).status()
    assert status["ready"] is True
    assert "crashes" in status["counts"]


def test_agent_run_pipeline(workspace):
    result = Agent(_ctx(workspace)).run(target="mock:parser", seed=1,
                                        max_cases=200)
    assert result["unique_crashes"] > 0
    # every reported crash has an evidence-gated indicator + confidence
    for c in result["crashes"]:
        assert c["indicator"]
        assert c["confidence"]


def test_agent_run_is_deterministic(tmp_path):
    from ios_research.workspace import Workspace
    from ios_research import __version__
    runs = []
    for name in ("a", "b"):
        ws = Workspace(tmp_path / name / ".ios-research")
        ws.init(framework_version=__version__, created_at="t")
        res = Agent(Context(workspace_path=str(ws.root))).run(
            target="mock:parser", seed=7, max_cases=150, minimize=False)
        runs.append(sorted(c["crash_id"] for c in res["crashes"]))
    assert runs[0] == runs[1]


def test_agent_inspect_cli_json_is_valid(workspace, capsys):
    main(["agent", "inspect", "--json", "--workspace", str(workspace.root)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert "commands" in payload["data"]


def test_every_command_supports_json(workspace, capsys):
    # A representative sweep: each returns a parseable envelope with exit_code.
    for argv in (["version"], ["info"], ["doctor"], ["target", "list"],
                 ["device", "list"], ["corpus", "list"], ["crash", "list"]):
        main([*argv, "--json", "--workspace", str(workspace.root)])
        payload = json.loads(capsys.readouterr().out)
        assert "exit_code" in payload and "ok" in payload
