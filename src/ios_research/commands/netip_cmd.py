"""`ios-research target netip` — list and inspect IP-stack targets.

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_net = sub.add_parser("netip", parents=[parent],
                           help="IP-stack input-path research targets")
    nsub = p_net.add_subparsers(dest="netip_action", metavar="<action>")

    p_list = nsub.add_parser("list", parents=[parent],
                             help="list IP-stack targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = nsub.add_parser("inspect", parents=[parent],
                                help="inspect an IP-stack target")
    p_inspect.add_argument("format", help="mdns-record|dhcpv6-opt|icmp6-info|edns or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_net.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.netip import NETIP_TARGETS
    if fmt in NETIP_TARGETS:
        return fmt
    candidate = f"netip:{fmt}"
    if candidate in NETIP_TARGETS:
        return candidate
    raise NotFoundError(f"unknown IP-stack format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.netip import NETIP_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(NETIP_TARGETS)]
    return Result(command="target netip list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:20} {', '.join(t['formats'])}" for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target netip inspect", data={"target": d})
