"""`ios-research target ipc` — list and inspect IPC targets (#107).

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_ipc = sub.add_parser("ipc", parents=[parent],
                           help="trust-boundary payload-envelope "
                                "research targets (decode modeling)")
    isub = p_ipc.add_subparsers(dest="ipc_action", metavar="<action>")

    p_list = isub.add_parser("list", parents=[parent],
                             help="list IPC targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = isub.add_parser("inspect", parents=[parent],
                                help="inspect an IPC target")
    p_inspect.add_argument("format",
                           help="share-payload|docprovider-item|intent-donation "
                                "or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_ipc.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.ipc import IPC_TARGETS
    if fmt in IPC_TARGETS:
        return fmt
    candidate = f"ipc:{fmt}"
    if candidate in IPC_TARGETS:
        return candidate
    raise NotFoundError(f"unknown IPC format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.ipc import IPC_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(IPC_TARGETS)]
    return Result(command="target ipc list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:24} {', '.join(t['formats'])}"
                      for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target ipc inspect", data={"target": d})
