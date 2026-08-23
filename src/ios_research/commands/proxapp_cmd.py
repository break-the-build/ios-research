"""`ios-research target proxapp` — list and inspect proximity-protocol targets.

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_px = sub.add_parser("proxapp", parents=[parent],
                          help="Proximity application-protocol research targets")
    psub = p_px.add_subparsers(dest="proxapp_action", metavar="<action>")

    p_list = psub.add_parser("list", parents=[parent],
                             help="list proximity-protocol targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = psub.add_parser("inspect", parents=[parent],
                                help="inspect a proximity-protocol target")
    p_inspect.add_argument(
        "format", help="hap-tlv|airplay-nego|mpc-frame|pbap-vcard or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_px.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.proxapp import PROXAPP_TARGETS
    if fmt in PROXAPP_TARGETS:
        return fmt
    candidate = f"proxapp:{fmt}"
    if candidate in PROXAPP_TARGETS:
        return candidate
    raise NotFoundError(f"unknown proximity-protocol format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.proxapp import PROXAPP_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(PROXAPP_TARGETS)]
    return Result(command="target proxapp list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:22} {', '.join(t['formats'])}" for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target proxapp inspect", data={"target": d})
