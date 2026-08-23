"""`ios-research target pq3` — list and inspect PQ3 ratchet targets.

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_pq3 = sub.add_parser("pq3", parents=[parent],
                           help="PQ3 ratchet transcript research targets")
    psub = p_pq3.add_subparsers(dest="pq3_action", metavar="<action>")

    p_list = psub.add_parser("list", parents=[parent],
                             help="list PQ3 targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = psub.add_parser("inspect", parents=[parent],
                                help="inspect a PQ3 target")
    p_inspect.add_argument("format", help="handshake|rekey or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_pq3.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.pq3 import PQ3_TARGETS
    if fmt in PQ3_TARGETS:
        return fmt
    candidate = f"pq3:{fmt}"
    if candidate in PQ3_TARGETS:
        return candidate
    raise NotFoundError(f"unknown PQ3 format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.pq3 import PQ3_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(PQ3_TARGETS)]
    return Result(command="target pq3 list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:16} {', '.join(t['formats'])}" for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target pq3 inspect", data={"target": d})
