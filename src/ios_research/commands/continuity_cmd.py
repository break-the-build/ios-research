"""`ios-research target continuity` — list and inspect Continuity targets.

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_ct = sub.add_parser("continuity", parents=[parent],
                          help="Continuity beacon-record research targets")
    csub = p_ct.add_subparsers(dest="continuity_action", metavar="<action>")

    p_list = csub.add_parser("list", parents=[parent],
                             help="list Continuity targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = csub.add_parser("inspect", parents=[parent],
                                help="inspect a Continuity target")
    p_inspect.add_argument("format",
                           help="handoff|findmy-adv|hotspot-tlv or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_ct.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.continuity import CONTINUITY_TARGETS
    if fmt in CONTINUITY_TARGETS:
        return fmt
    candidate = f"continuity:{fmt}"
    if candidate in CONTINUITY_TARGETS:
        return candidate
    raise NotFoundError(f"unknown Continuity format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.continuity import CONTINUITY_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(CONTINUITY_TARGETS)]
    return Result(command="target continuity list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:24} {', '.join(t['formats'])}" for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target continuity inspect", data={"target": d})
