"""`ios-research device` — list and inspect devices."""

from __future__ import annotations

from .. import devices
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("device", parents=[parent],
                              help="manage research devices")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_list = sub.add_parser("list", parents=[parent], help="list known devices")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent], help="show one device")
    p_show.add_argument("device_id")
    p_show.set_defaults(func=cmd_show)

    p.set_defaults(func=cmd_list)


def cmd_list(ctx, args) -> Result:
    items = devices.list_devices()
    return Result(command="device list", data={"devices": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{x['id']:16} {x['os_name']} {x['os_version']} "
                      f"({'mock' if x['mock'] else 'real'})" for x in d["devices"]))


def cmd_show(ctx, args) -> Result:
    device = devices.get(args.device_id)
    return Result(command="device show", data={"device": device.to_dict()})
