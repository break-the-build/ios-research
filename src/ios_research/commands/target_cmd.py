"""`ios-research target` — list and inspect research targets.

Format-specific target subcommands (e.g. ``target audio``) are attached by the
respective module (see phase 03).
"""

from __future__ import annotations

from ..output import Result

# Extra subparser installers contributed by other modules (e.g. audio).
_EXTRA_SUBCOMMANDS = []


def add_subcommand(installer) -> None:
    """Register an installer ``installer(sub, parent)`` for a target subcommand.

    Idempotent: the same installer is only registered once even if the CLI
    parser is rebuilt (e.g. across tests).
    """
    if installer not in _EXTRA_SUBCOMMANDS:
        _EXTRA_SUBCOMMANDS.append(installer)


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("target", parents=[parent],
                              help="manage research targets")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_list = sub.add_parser("list", parents=[parent], help="list known targets")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent], help="inspect one target")
    p_show.add_argument("target_id")
    p_show.set_defaults(func=cmd_show)

    for installer in _EXTRA_SUBCOMMANDS:
        installer(sub, parent)

    p.set_defaults(func=cmd_list)


def cmd_list(ctx, args) -> Result:
    from .. import targets
    items = targets.list_targets()
    return Result(command="target list", data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{x['id']:16} {x['kind']:8} {x['description']}"
                      for x in d["targets"]))


def cmd_show(ctx, args) -> Result:
    from .. import targets
    target = targets.create(args.target_id)
    return Result(command="target show", data={"target": target.describe()})
