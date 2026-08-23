"""Command-line entry point and dispatch framework.

The CLI is a thin, deterministic shell around command handlers. Each command
group registers a subparser and a handler ``func(ctx, args) -> Result``. Global
flags (``--json``, ``--verbose``, ``--quiet``, ``--workspace``, ``--config``,
``--yes``) are accepted both before and after the subcommand.
"""

from __future__ import annotations

import argparse
import sys
from typing import Callable

from . import __version__, FRAMEWORK_NAME
from .context import Context
from .errors import IosResearchError, ExitCode, UsageError
from .output import Result, render

# Command group registrars. Each is ``register(subparsers, parent)``.
# Groups are added phase by phase; later phases extend this list.
from .commands import (
    core, config_cmd, device_cmd, target_cmd, experiment_cmd,
    corpus_cmd, fuzz_cmd, audio_cmd, bluetooth_cmd, wifi_cmd, crash_cmd,
    analyze_cmd, diff_cmd, harness_cmd, spoints_cmd, agent_cmd, report_cmd,
    research_cmd,
    targetflags_cmd, advisory_cmd,
)

_REGISTRARS: list[Callable] = [
    core.register,
    config_cmd.register,
    device_cmd.register,
    audio_cmd.register,       # must precede target_cmd (installs 'target audio')
    bluetooth_cmd.register,   # must precede target_cmd (installs 'target bluetooth')
    wifi_cmd.register,        # must precede target_cmd (installs 'target wifi')
    target_cmd.register,
    experiment_cmd.register,
    corpus_cmd.register,
    fuzz_cmd.register,
    crash_cmd.register,
    analyze_cmd.register,
    diff_cmd.register,
    harness_cmd.register,
    spoints_cmd.register,
    report_cmd.register,
    research_cmd.register,
    agent_cmd.register,
    targetflags_cmd.register,
    advisory_cmd.register,
]


def _global_parent() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--json", action="store_true", dest="as_json",
                        help="emit stable machine-readable JSON")
    parent.add_argument("--verbose", action="store_true",
                        help="verbose logging")
    parent.add_argument("--quiet", action="store_true",
                        help="suppress non-error human output")
    parent.add_argument("--workspace", dest="workspace_path", default=None,
                        help="path to the .ios-research workspace")
    parent.add_argument("--config", dest="config_path", default=None,
                        help="path to a config file override")
    parent.add_argument("--yes", action="store_true", dest="assume_yes",
                        help="assume yes; confirm destructive operations")
    return parent


def build_parser() -> argparse.ArgumentParser:
    parent = _global_parent()
    parser = argparse.ArgumentParser(
        prog=FRAMEWORK_NAME,
        parents=[parent],
        description="Authorized iOS security research framework.")
    parser.add_argument("--version", action="version",
                        version=f"{FRAMEWORK_NAME} {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    for registrar in _REGISTRARS:
        registrar(subparsers, parent)
    return parser


def _context_from_args(args: argparse.Namespace) -> Context:
    return Context(
        as_json=getattr(args, "as_json", False),
        verbose=getattr(args, "verbose", False),
        quiet=getattr(args, "quiet", False),
        workspace_path=getattr(args, "workspace_path", None),
        config_path=getattr(args, "config_path", None),
        assume_yes=getattr(args, "assume_yes", False),
    )


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "func", None):
        parser.print_help()
        return ExitCode.USAGE

    ctx = _context_from_args(args)
    try:
        result: Result = args.func(ctx, args)
    except IosResearchError as exc:
        result = Result(ok=False, command=getattr(args, "command", "") or "",
                        error=exc.message, exit_code=exc.exit_code,
                        data=exc.details)
    except BrokenPipeError:  # pragma: no cover
        return ExitCode.OK
    except KeyboardInterrupt:  # pragma: no cover
        result = Result(ok=False, error="interrupted",
                        exit_code=ExitCode.INTERRUPTED)

    render(result, as_json=ctx.as_json, quiet=ctx.quiet)
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
