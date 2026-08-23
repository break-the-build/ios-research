"""`ios-research target bluetooth` — list and inspect Bluetooth targets.

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_bt = sub.add_parser("bluetooth", parents=[parent],
                          help="Bluetooth frame research targets")
    bsub = p_bt.add_subparsers(dest="bluetooth_action", metavar="<action>")

    p_list = bsub.add_parser("list", parents=[parent],
                             help="list Bluetooth targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = bsub.add_parser("inspect", parents=[parent],
                                help="inspect a Bluetooth target")
    p_inspect.add_argument("format", help="btle-adv|l2cap|gatt or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_bt.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.bluetooth import BLUETOOTH_TARGETS
    if fmt in BLUETOOTH_TARGETS:
        return fmt
    candidate = f"bluetooth:{fmt}"
    if candidate in BLUETOOTH_TARGETS:
        return candidate
    raise NotFoundError(f"unknown Bluetooth format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.bluetooth import BLUETOOTH_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(BLUETOOTH_TARGETS)]
    return Result(command="target bluetooth list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:20} {', '.join(t['formats'])}" for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target bluetooth inspect", data={"target": d})
