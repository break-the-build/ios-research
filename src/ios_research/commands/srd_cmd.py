"""`ios-research srd` — status and CI-safe runs for the SRD backend (#40).

The real ``srd:device`` target is strictly opt-in: this command group only
*reports* its availability and blocker. Executions in CI go through the
deterministic ``srd:fake`` backend, which never touches hardware.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..errors import NotFoundError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("srd", parents=[parent],
                              help="Apple Security Research Device backend")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_status = sub.add_parser(
        "status", parents=[parent],
        help="show srd:device availability, missing config fields, and blocker")
    p_status.set_defaults(func=cmd_status)

    p_fake = sub.add_parser(
        "fake-run", parents=[parent],
        help="run one input through the deterministic srd:fake backend")
    p_fake.add_argument("--input-file", required=True,
                        help="path to the input file to execute")
    p_fake.set_defaults(func=cmd_fake_run)

    p.set_defaults(func=cmd_status)


def cmd_status(ctx, args) -> Result:
    from .. import targets
    target = targets.create("srd:device")
    info = target.describe()
    return Result(command="srd status",
                  data={"target": info,
                        "available": target.available(),
                        "missing_fields": info["missing_fields"],
                        "blocker": target.blocker() or None,
                        "evidence_class": info["evidence_class"]},
                  human=lambda d: "\n".join([
                      f"target:         {d['target']['id']} ({d['target']['kind']})",
                      f"available:      {d['available']}",
                      f"missing_fields: {', '.join(d['missing_fields']) or '(none)'}",
                      f"blocker:        {d['blocker'] or '(none)'}",
                      f"evidence_class: {d['evidence_class']}",
                  ]))


def cmd_fake_run(ctx, args) -> Result:
    from ..targets.srd import FakeSRDBackend
    path = Path(args.input_file)
    if not path.is_file():
        raise NotFoundError(f"input file not found: {path}")
    data = path.read_bytes()
    backend = FakeSRDBackend(workspace=ctx.workspace(required=False))
    result = backend.execute(data)
    return Result(command="srd fake-run",
                  data={"result": result.to_dict(),
                        "provenance": backend.provenance()},
                  human=lambda d: (
                      f"outcome: {d['result']['outcome']} "
                      f"({d['result']['detail']})\n"
                      f"evidence_class: {d['provenance']['evidence_class']}"))
