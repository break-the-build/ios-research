"""Global flags must work before AND after the subcommand (cli.py contract).

Regression tests for the argparse subparser-namespace clobber: subparsers
parse into a fresh namespace and copy results over the root namespace, so a
subparser default used to discard ``--json``/``--workspace`` etc. when they
appeared before the subcommand.
"""

from __future__ import annotations

import json

import pytest

from ios_research.cli import build_parser, main


@pytest.mark.parametrize("argv_tail", [
    ["target", "list"],
])
def test_json_flag_position_independent(ctx, capsys, argv_tail):
    ws = str(ctx.workspace().root)
    for argv in ([*argv_tail, "--json", "--workspace", ws],
                 ["--json", "--workspace", ws, *argv_tail]):
        rc = main([*argv])
        assert rc == 0, argv
        envelope = json.loads(capsys.readouterr().out.strip())
        assert envelope["ok"] is True
        assert envelope["command"] == " ".join(argv_tail[:2])


def test_workspace_flag_before_subcommand(ctx, capsys):
    # --workspace before the subcommand previously fell back to cwd discovery
    # and failed with NOT_FOUND outside a workspace.
    rc = main(["--workspace", str(ctx.workspace().root),
               "harness", "list", "--json"])
    assert rc == 0
    envelope = json.loads(capsys.readouterr().out.strip())
    assert envelope["data"]["count"] == 0


def test_defaults_when_flags_absent():
    args = build_parser().parse_args(["target", "list"])
    assert getattr(args, "as_json") is False if hasattr(args, "as_json") \
        else True  # suppressed default => attribute may be absent


def test_advisory_and_surface_cli_preposition_style(ctx, capsys):
    """The style used by tests/test_advisories.py and tests/test_surface.py."""
    pre = ["--workspace", str(ctx.workspace().root)]
    rc = main([*pre, "harness", "generate", "--target", "mock:parser",
               "--max-candidates", "1", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["ok"] is True
