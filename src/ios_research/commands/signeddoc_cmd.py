"""`ios-research target signeddoc` — list and inspect signed-document targets.

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_sd = sub.add_parser("signeddoc", parents=[parent],
                          help="signed-document research targets")
    ssub = p_sd.add_subparsers(dest="signeddoc_action", metavar="<action>")

    p_list = ssub.add_parser("list", parents=[parent],
                             help="list signed-document targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = ssub.add_parser("inspect", parents=[parent],
                                help="inspect a signed-document target")
    p_inspect.add_argument("format",
                           help="profile|provision|receipt|pkpass or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_sd.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.signeddoc import SIGNEDDOC_TARGETS
    if fmt in SIGNEDDOC_TARGETS:
        return fmt
    candidate = f"signeddoc:{fmt}"
    if candidate in SIGNEDDOC_TARGETS:
        return candidate
    raise NotFoundError(f"unknown signed-document format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.signeddoc import SIGNEDDOC_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(SIGNEDDOC_TARGETS)]
    return Result(command="target signeddoc list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:22} {', '.join(t['formats'])}" for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target signeddoc inspect", data={"target": d})
