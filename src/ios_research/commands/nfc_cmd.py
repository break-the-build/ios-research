"""`ios-research target nfc` — list and inspect NFC targets.

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_nfc = sub.add_parser("nfc", parents=[parent],
                           help="NFC record research targets")
    nsub = p_nfc.add_subparsers(dest="nfc_action", metavar="<action>")

    p_list = nsub.add_parser("list", parents=[parent],
                             help="list NFC targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = nsub.add_parser("inspect", parents=[parent],
                                help="inspect an NFC target")
    p_inspect.add_argument("format", help="ndef|isodep|tagcmd or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_nfc.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.nfc import NFC_TARGETS
    if fmt in NFC_TARGETS:
        return fmt
    candidate = f"nfc:{fmt}"
    if candidate in NFC_TARGETS:
        return candidate
    raise NotFoundError(f"unknown NFC format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.nfc import NFC_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(NFC_TARGETS)]
    return Result(command="target nfc list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:14} {', '.join(t['formats'])}" for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target nfc inspect", data={"target": d})
