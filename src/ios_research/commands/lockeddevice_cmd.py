"""`ios-research target lockeddevice` — list and inspect locked-device
surface targets (#86).

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_ld = sub.add_parser("lockeddevice", parents=[parent],
                          help="locked-device surface research targets "
                               "(physical-access profiles)")
    lsub = p_ld.add_subparsers(dest="lockeddevice_action", metavar="<action>")

    p_list = lsub.add_parser("list", parents=[parent],
                             help="list locked-device targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = lsub.add_parser("inspect", parents=[parent],
                                help="inspect a locked-device target")
    p_inspect.add_argument("format",
                           help="lockdownd|mfi-auth|notification or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_ld.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.lockeddevice import LOCKED_DEVICE_TARGETS
    if fmt in LOCKED_DEVICE_TARGETS:
        return fmt
    candidate = f"lockeddevice:{fmt}"
    if candidate in LOCKED_DEVICE_TARGETS:
        return candidate
    raise NotFoundError(f"unknown locked-device format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.lockeddevice import LOCKED_DEVICE_TARGETS
    items = [targets.create(tid).describe()
             for tid in sorted(LOCKED_DEVICE_TARGETS)]
    return Result(command="target lockeddevice list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:28} {', '.join(t['formats'])}"
                      for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target lockeddevice inspect", data={"target": d})
