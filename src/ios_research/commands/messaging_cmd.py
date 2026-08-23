"""`ios-research target messaging` — list and inspect messaging targets (#85).

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_msg = sub.add_parser("messaging", parents=[parent],
                           help="communication-message research targets "
                                "(network zero-click profiles)")
    msub = p_msg.add_subparsers(dest="messaging_action", metavar="<action>")

    p_list = msub.add_parser("list", parents=[parent],
                             help="list messaging targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = msub.add_parser("inspect", parents=[parent],
                                help="inspect a messaging target")
    p_inspect.add_argument("format",
                           help="sms|mime|link-preview or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_msg.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.messaging import MESSAGING_TARGETS
    if fmt in MESSAGING_TARGETS:
        return fmt
    candidate = f"messaging:{fmt}"
    if candidate in MESSAGING_TARGETS:
        return candidate
    raise NotFoundError(f"unknown messaging format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.messaging import MESSAGING_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(MESSAGING_TARGETS)]
    return Result(command="target messaging list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:26} {', '.join(t['formats'])}"
                      for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target messaging inspect", data={"target": d})
