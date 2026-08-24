"""Machine-readable description of the CLI, for LLM agents.

Builds a deterministic schema of commands, arguments, exit codes, artifact
locations, the experiment lifecycle, crash classifications and the safety
boundary. This is the contract agents can rely on.
"""

from __future__ import annotations

import argparse
from typing import Any

from .errors import ExitCode
from .safety import boundary_summary
from .triage import CLASSIFICATIONS
from .analysis import (
    CRASH_ONLY, CONTROLLED_MEMORY_ACCESS_INDICATOR, CONTROLLED_REGISTER_INDICATOR,
    ARBITRARY_READ_INDICATOR, ARBITRARY_WRITE_INDICATOR, CODE_EXECUTION_INDICATOR,
)

EXIT_CODES = {
    "OK": ExitCode.OK,
    "ERROR": ExitCode.ERROR,
    "USAGE": ExitCode.USAGE,
    "NOT_FOUND": ExitCode.NOT_FOUND,
    "VALIDATION": ExitCode.VALIDATION,
    "SAFETY": ExitCode.SAFETY,
    "INTERRUPTED": ExitCode.INTERRUPTED,
    "STATE": ExitCode.STATE,
}

ARTIFACT_LOCATIONS = {
    "workspace_marker": ".ios-research/workspace.json",
    "config": ".ios-research/config/config.json",
    "experiments": ".ios-research/experiments/<experiment_id>.json",
    "corpus": ".ios-research/corpus/<corpus_id>/",
    "fuzz_sessions": ".ios-research/fuzz/<session_id>.json",
    "crashes": ".ios-research/crashes/<crash_id>/",
    "analysis": ".ios-research/analysis/<analysis_id>.json",
    "diffs": ".ios-research/diffs/<diff_id>/",
    "reports": ".ios-research/reports/<report_id>/",
    "research": ".ios-research/research/<research_id>.json",
    "harnesses": ".ios-research/harnesses/<candidate_id>.json",
    "spoints": ".ios-research/spoints/<report_id>.json",
    "findings": ".ios-research/findings/<finding_id>.json",
    "ndays": ".ios-research/ndays/<diff_id>.json",
    "artifacts": ".ios-research/artifacts/<sha2>/<sha256>.bin",
    "supply": ".ios-research/supply/<record_id>.json",
}

EXPERIMENT_LIFECYCLE = [
    "inspect environment", "select target", "inspect corpus", "create experiment",
    "fuzz", "detect crashes", "deduplicate", "minimize", "reproduce", "analyze",
    "differential test", "generate report",
]

EXPLOITABILITY_INDICATORS = [
    CRASH_ONLY, CONTROLLED_MEMORY_ACCESS_INDICATOR, CONTROLLED_REGISTER_INDICATOR,
    ARBITRARY_READ_INDICATOR, ARBITRARY_WRITE_INDICATOR, CODE_EXECUTION_INDICATOR,
]

# Commands that mutate/consume significant resources and require --yes.
DESTRUCTIVE_COMMANDS = ["research run"]


def _describe_arguments(parser: argparse.ArgumentParser) -> dict[str, Any]:
    positionals, options = [], []
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction):
            continue
        if action.option_strings:
            if action.dest in ("as_json", "verbose", "quiet", "workspace_path",
                               "config_path", "assume_yes"):
                continue  # global flags documented once
            options.append({"flags": list(action.option_strings),
                            "dest": action.dest, "required": action.required,
                            "help": action.help or ""})
        elif action.dest != "help":
            positionals.append({"name": action.dest,
                                "required": action.nargs != "?",
                                "help": action.help or ""})
    return {"positionals": positionals, "options": options}


def _walk(parser: argparse.ArgumentParser) -> dict[str, Any]:
    commands: dict[str, Any] = {}
    subparsers_action = next(
        (a for a in parser._actions if isinstance(a, argparse._SubParsersAction)),
        None)
    if subparsers_action is None:
        return commands
    for name, sub in subparsers_action.choices.items():
        entry: dict[str, Any] = {"arguments": _describe_arguments(sub)}
        nested = _walk(sub)
        if nested:
            entry["subcommands"] = nested
        commands[name] = entry
    return commands


def build_cli_schema() -> dict[str, Any]:
    from .cli import build_parser  # local import to avoid a cycle
    from . import __version__

    parser = build_parser()
    return {
        "framework": "ios-research",
        "version": __version__,
        "global_flags": ["--json", "--verbose", "--quiet", "--workspace",
                         "--config", "--yes"],
        "json_output_contract": {
            "envelope": ["ok", "command", "data", "messages", "error",
                         "exit_code"],
            "note": "every command supports --json and returns this envelope",
        },
        "exit_codes": EXIT_CODES,
        "artifact_locations": ARTIFACT_LOCATIONS,
        "experiment_lifecycle": EXPERIMENT_LIFECYCLE,
        "crash_classifications": list(CLASSIFICATIONS),
        "exploitability_indicators": EXPLOITABILITY_INDICATORS,
        "destructive_commands": DESTRUCTIVE_COMMANDS,
        "safety_boundary": boundary_summary(),
        "commands": _walk(parser),
    }
