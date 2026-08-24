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
    corpus_cmd, fuzz_cmd, audio_cmd, bluetooth_cmd, wifi_cmd, nfc_cmd,
    messaging_cmd, lockeddevice_cmd,
    crash_cmd, analyze_cmd, diff_cmd, report_cmd, research_cmd, matrix_cmd,
    harness_cmd, spoints_cmd, findings_cmd, surface_cmd, targetflags_cmd,
    advisory_cmd, engine_cmd, beta_cmd, agent_cmd,
    net_cmd, kernel_cmd, oracle_cmd, detect_cmd, cve_cmd, lockdown_cmd,
    proximity_cmd,
    netip_cmd, wifiaware_cmd, pq3_cmd, continuity_cmd, ipc_cmd, xpc_cmd,
    docimp_cmd, signeddoc_cmd, proxapp_cmd, fsclient_cmd, geo_cmd,
    voiceassist_cmd, supply_cmd, nday_cmd, races_cmd,
    evidence_cmd,
    sequence_cmd,
    xcode_cmd,
    campaign_cmd,
    suite_cmd,
    srd_cmd,
)

_REGISTRARS: list[Callable] = [
    core.register,
    config_cmd.register,
    device_cmd.register,
    audio_cmd.register,       # must precede target_cmd (installs 'target audio')
    bluetooth_cmd.register,   # must precede target_cmd (installs 'target bluetooth')
    wifi_cmd.register,        # must precede target_cmd (installs 'target wifi')
    nfc_cmd.register,         # must precede target_cmd (installs 'target nfc')
    messaging_cmd.register,   # must precede target_cmd (installs 'target messaging')
    lockeddevice_cmd.register,  # must precede target_cmd (installs 'target lockeddevice')
    netip_cmd.register,   # must precede target_cmd (installs 'target netip')
    wifiaware_cmd.register,   # must precede target_cmd (installs 'target wifiaware')
    pq3_cmd.register,   # must precede target_cmd (installs 'target pq3')
    continuity_cmd.register,   # must precede target_cmd (installs 'target continuity')
    ipc_cmd.register,   # must precede target_cmd (installs 'target ipc')
    xpc_cmd.register,   # must precede target_cmd (installs 'target xpc')
    docimp_cmd.register,   # must precede target_cmd (installs 'target docimp')
    signeddoc_cmd.register,   # must precede target_cmd (installs 'target signeddoc')
    proxapp_cmd.register,   # must precede target_cmd (installs 'target proxapp')
    fsclient_cmd.register,   # must precede target_cmd (installs 'target fsclient')
    geo_cmd.register,   # must precede target_cmd (installs 'target geo')
    voiceassist_cmd.register,   # must precede target_cmd (installs 'target voiceassist')
    target_cmd.register,
    experiment_cmd.register,
    corpus_cmd.register,
    fuzz_cmd.register,
    crash_cmd.register,
    analyze_cmd.register,
    races_cmd.register,
    diff_cmd.register,
    harness_cmd.register,
    spoints_cmd.register,
    kernel_cmd.register,
    findings_cmd.register,
    report_cmd.register,
    research_cmd.register,
    matrix_cmd.register,
    evidence_cmd.register,
    sequence_cmd.register,
    suite_cmd.register,
    detect_cmd.register,
    cve_cmd.register,
    engine_cmd.register,
    agent_cmd.register,
    targetflags_cmd.register,
    advisory_cmd.register,
    surface_cmd.register,
    beta_cmd.register,
    net_cmd.register,
    lockdown_cmd.register,
    oracle_cmd.register,
    proximity_cmd.register,
    supply_cmd.register,
    nday_cmd.register,
    xcode_cmd.register,
    srd_cmd.register,
    campaign_cmd.register,
]


def _global_parent() -> argparse.ArgumentParser:
    # SUPPRESS defaults: every subparser re-inherits this parent, and plain
    # defaults would clobber values parsed *before* the subcommand (argparse
    # applies subparser defaults over the existing namespace).
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--json", action="store_true", dest="as_json",
                        default=argparse.SUPPRESS,
                        help="emit stable machine-readable JSON")
    parent.add_argument("--verbose", action="store_true",
                        default=argparse.SUPPRESS,
                        help="verbose logging")
    parent.add_argument("--quiet", action="store_true",
                        default=argparse.SUPPRESS,
                        help="suppress non-error human output")
    parent.add_argument("--workspace", dest="workspace_path",
                        default=argparse.SUPPRESS,
                        help="path to the .ios-research workspace")
    parent.add_argument("--config", dest="config_path",
                        default=argparse.SUPPRESS,
                        help="path to a config file override")
    parent.add_argument("--yes", action="store_true", dest="assume_yes",
                        default=argparse.SUPPRESS,
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
    _suppress_subparser_global_defaults(parser)
    return parser


# Global-flag dests shared by the root parser and every subparser. Subparsers
# parse into a fresh namespace whose results are copied unconditionally over
# the root namespace, so a subparser *default* (e.g. ``as_json=False``) would
# silently discard a global flag given before the subcommand. Marking these
# actions ``SUPPRESS`` keeps absent flags from being copied; handlers already
# read them via :func:`getattr` fallbacks.
_GLOBAL_DESTS = ("as_json", "verbose", "quiet",
                 "workspace_path", "config_path", "assume_yes")


def _suppress_subparser_global_defaults(parser: argparse.ArgumentParser) -> None:
    subparsers_action = next(
        (a for a in parser._actions
         if isinstance(a, argparse._SubParsersAction)), None)
    if subparsers_action is None:
        return
    for sub in subparsers_action.choices.values():
        for action in sub._actions:
            if getattr(action, "dest", None) in _GLOBAL_DESTS:
                action.default = argparse.SUPPRESS
        _suppress_subparser_global_defaults(sub)


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
