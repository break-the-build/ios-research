"""Machine-readable description of the CLI, for LLM agents.

Builds a deterministic schema of commands, arguments, exit codes, artifact
locations, the experiment lifecycle, crash classifications and the safety
boundary. This is the contract agents can rely on.

Pipeline command groups additionally carry operational hints (#268):
per-command ``examples`` (argv + expected envelope), ``time_bounds``
(blocking behaviour and which flags cap runtime) and ``next`` (common
follow-up commands).
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
    "races": ".ios-research/races/<race_id>.json",
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

# Operational hints per command path ("group subcommand"), added for #268.
# The base schema is structural (arguments, exit codes); these entries make it
# *operational* for autonomous agents:
#   - ``examples``: realistic argv arrays plus the expected Result envelope
#     shape, so agents can copy an invocation and know what comes back;
#   - ``time_bounds``: whether the invocation blocks until finished and which
#     flags cap its runtime (--max-cases/--duration/--chunk time-slicing is the
#     key pattern: bound every long runner instead of letting defaults run);
#   - ``next``: common follow-up commands per outcome.
# Keys are optional per command; absent means "no hint" — purely additive, so
# existing schema consumers keep working unchanged.
OPERATIONAL_HINTS: dict[str, dict[str, Any]] = {
    # --- fuzz ---------------------------------------------------------------
    "fuzz start": {
        "examples": [
            {
                "argv": ["ios-research", "fuzz", "start", "--target",
                         "mock:parser", "--max-cases", "200", "--json"],
                "envelope": {
                    "ok": True,
                    "command": "fuzz start",
                    "data": {"session": {"<session-fields>": "..."},
                             "stats": {"<stats-fields>": "..."},
                             "experiment_id": "<experiment-id>"},
                    "messages": [],
                    "error": None,
                    "exit_code": 0,
                },
            },
            {
                "argv": ["ios-research", "fuzz", "start", "--duration", "30",
                         "--chunk", "50", "--json"],
                "envelope": {
                    "ok": True,
                    "command": "fuzz start",
                    "data": {},
                    "messages": [],
                    "error": None,
                    "exit_code": 0,
                },
            },
        ],
        "time_bounds": {
            "blocking": True,
            "bounds": ["--max-cases", "--duration", "--chunk"],
            "note": "executes cases synchronously up to the given budget; "
                    "always pass an explicit --max-cases/--duration/--chunk "
                    "(defaults can run long); sessions are resumable via "
                    "'fuzz resume'",
        },
        "next": [
            "ios-research fuzz status [session_id] --json",
            "ios-research fuzz stats [session_id] --json",
            "ios-research crash list --json",
        ],
    },
    "fuzz status": {
        "time_bounds": {
            "blocking": False,
            "note": "reads session state from disk and returns immediately",
        },
        "next": ["ios-research fuzz stats [session_id] --json"],
    },
    "fuzz stats": {
        "time_bounds": {
            "blocking": False,
            "note": "reads session state from disk and returns immediately",
        },
    },
    "fuzz stop": {
        "time_bounds": {
            "blocking": False,
            "note": "marks a session stopped; returns immediately",
        },
    },
    "fuzz pause": {
        "time_bounds": {
            "blocking": False,
            "note": "marks a session paused; returns immediately",
        },
        "next": ["ios-research fuzz resume [session_id] --json"],
    },
    "fuzz resume": {
        "examples": [
            {
                "argv": ["ios-research", "fuzz", "resume", "--chunk", "50",
                         "--json"],
                "envelope": {
                    "ok": True,
                    "command": "fuzz resume",
                    "data": {"session": {"<session-fields>": "..."},
                             "stats": {"<stats-fields>": "..."}},
                    "messages": [],
                    "error": None,
                    "exit_code": 0,
                },
            },
        ],
        "time_bounds": {
            "blocking": True,
            "bounds": ["--chunk", "--duration"],
            "note": "resumes execution for at most --chunk cases or "
                    "--duration seconds; without bounds it runs to the "
                    "session's remaining budget",
        },
        "next": [
            "ios-research fuzz status [session_id] --json",
            "ios-research crash list --json",
        ],
    },
    # --- campaign -------------------------------------------------------------
    "campaign export": {
        "examples": [
            {
                "argv": ["ios-research", "campaign", "export", "--corpus",
                         "<corpus-id>", "--out", "/tmp/bundle.tar.zst",
                         "--worker", "w1", "--json"],
                "envelope": {
                    "ok": True,
                    "command": "campaign export",
                    "data": {"manifest": {"<manifest-fields>": "..."},
                             "out": "<bundle-path>"},
                    "messages": [],
                    "error": None,
                    "exit_code": 0,
                },
            },
        ],
        "time_bounds": {
            "blocking": False,
            "note": "writes one exchange bundle; bounded by corpus size but "
                    "no scheduling flags apply",
        },
        "next": [
            "ios-research campaign import --from <bundle> --corpus <id> --json",
            "ios-research campaign status --json",
        ],
    },
    "campaign import": {
        "time_bounds": {
            "blocking": False,
            "note": "imports one bundle; use --dry-run to preview accept/"
                    "reject decisions without writing",
        },
        "next": [
            "ios-research campaign status --json",
            "ios-research fuzz start --corpus <corpus-id> --max-cases N --json",
        ],
    },
    "campaign status": {
        "time_bounds": {
            "blocking": False,
            "note": "aggregates sync records from disk; returns immediately",
        },
    },
    # --- research ---------------------------------------------------------------
    "research create": {
        "examples": [
            {
                "argv": ["ios-research", "research", "create", "--name",
                         "my-run", "--target", "mock:parser",
                         "--max-cases", "300", "--json"],
                "envelope": {
                    "ok": True,
                    "command": "research create",
                    "data": {"research": {"<research-run-fields>": "..."}},
                    "messages": [],
                    "error": None,
                    "exit_code": 0,
                },
            },
        ],
        "time_bounds": {
            "blocking": False,
            "note": "creates the run record only; no stages execute here",
        },
        "next": [
            "ios-research research run <research_id> --yes --json",
            "ios-research research status --json",
        ],
    },
    "research run": {
        "time_bounds": {
            "blocking": True,
            "bounds": ["--max-stages"],
            "note": "destructive/resource-consuming: requires --yes; runs "
                    "pipeline stages until complete unless sliced with "
                    "--max-stages N (resumable); per-stage budgets come from "
                    "the run's --max-cases/--max-runtime/--max-testcases set "
                    "at 'research create'",
        },
        "next": [
            "ios-research research status <research_id> --json",
            "ios-research research summarize <research_id> --json",
            "ios-research research pause <research_id> --json",
        ],
    },
    "research status": {
        "time_bounds": {
            "blocking": False,
            "note": "reads run state from disk and returns immediately",
        },
        "next": ["ios-research research summarize <research_id> --json"],
    },
    "research resume": {
        "time_bounds": {
            "blocking": True,
            "bounds": ["--max-stages"],
            "note": "continues a paused/partial run; slice with --max-stages "
                    "to keep each invocation short",
        },
        "next": [
            "ios-research research status <research_id> --json",
            "ios-research research summarize <research_id> --json",
        ],
    },
    "research pause": {
        "time_bounds": {
            "blocking": False,
            "note": "marks a run paused; returns immediately",
        },
        "next": ["ios-research research resume <research_id> --json"],
    },
    "research summarize": {
        "time_bounds": {
            "blocking": False,
            "note": "aggregates recorded stage results; returns immediately",
        },
    },
    # --- agent ---------------------------------------------------------------
    "agent status": {
        "time_bounds": {
            "blocking": False,
            "note": "environment + workspace counts; returns immediately",
        },
        "next": ["ios-research target list --json"],
    },
    "agent inspect": {
        "time_bounds": {
            "blocking": False,
            "note": "prints this schema; returns immediately",
        },
    },
    "agent schema": {
        "time_bounds": {
            "blocking": False,
            "note": "writes docs/cli-schema.json (or --out P); fast, but "
                    "re-run after any CLI change so the committed schema "
                    "stays current",
        },
    },
    "agent experiment": {
        "time_bounds": {
            "blocking": False,
            "note": "creates a stamped experiment record only; returns "
                    "immediately",
        },
        "next": ["ios-research fuzz start --experiment <id> --json"],
    },
    "agent run": {
        "examples": [
            {
                "argv": ["ios-research", "agent", "run", "--target",
                         "mock:parser", "--max-cases", "200", "--seed", "0",
                         "--json"],
                "envelope": {
                    "ok": True,
                    "command": "agent run",
                    "data": {"experiment_id": "<experiment-id>",
                             "unique_crashes": 0,
                             "<other-pipeline-fields>": "..."},
                    "messages": [],
                    "error": None,
                    "exit_code": 0,
                },
            },
        ],
        "time_bounds": {
            "blocking": True,
            "bounds": ["--max-cases"],
            "note": "bounded end-to-end pipeline (fuzz -> reproduce -> "
                    "minimize -> analyze) in one call; blocks until done but "
                    "is capped by --max-cases (default 200)",
        },
        "next": [
            "ios-research crash list --json",
            "ios-research report create <crash_id> --json",
            "ios-research agent analyze --json",
        ],
    },
    "agent analyze": {
        "time_bounds": {
            "blocking": True,
            "bounds": [],
            "note": "analyzes all recorded crashes; bounded by crash count, "
                    "no slicing flag exists yet",
        },
    },
}


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


def _walk(parser: argparse.ArgumentParser, prefix: tuple[str, ...] = ()) \
        -> dict[str, Any]:
    commands: dict[str, Any] = {}
    subparsers_action = next(
        (a for a in parser._actions if isinstance(a, argparse._SubParsersAction)),
        None)
    if subparsers_action is None:
        return commands
    for name, sub in subparsers_action.choices.items():
        entry: dict[str, Any] = {"arguments": _describe_arguments(sub)}
        nested = _walk(sub, (*prefix, name))
        if nested:
            entry["subcommands"] = nested
        # Operational hints (#268): attach examples/time_bounds/next by full
        # command path (e.g. "fuzz start"). Optional and additive — commands
        # without an entry keep the structural shape consumers already rely on.
        hint = OPERATIONAL_HINTS.get(" ".join((*prefix, name)))
        if hint:
            entry.update(hint)
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
