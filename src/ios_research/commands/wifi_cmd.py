"""`ios-research target wifi` — list and inspect Wi-Fi targets.

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_wifi = sub.add_parser("wifi", parents=[parent],
                            help="Wi-Fi frame research targets")
    wsub = p_wifi.add_subparsers(dest="wifi_action", metavar="<action>")

    p_list = wsub.add_parser("list", parents=[parent],
                             help="list Wi-Fi targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = wsub.add_parser("inspect", parents=[parent],
                                help="inspect a Wi-Fi target")
    p_inspect.add_argument("format",
                           help="beacon|probe-resp|action or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_wifi.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.wifi import WIFI_TARGETS
    if fmt in WIFI_TARGETS:
        return fmt
    candidate = f"wifi:{fmt}"
    if candidate in WIFI_TARGETS:
        return candidate
    raise NotFoundError(f"unknown Wi-Fi format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.wifi import WIFI_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(WIFI_TARGETS)]
    return Result(command="target wifi list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:18} {', '.join(t['formats'])}" for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target wifi inspect", data={"target": d})
