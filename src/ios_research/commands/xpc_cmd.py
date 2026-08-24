"""`ios-research target xpc` — list/inspect XPC targets + offline schema harvest.

Installs itself as a subcommand of ``target`` via the target command's
extension hook. The ``harvest`` subcommand reads a researcher-exported JSON
schema file (a list of ``{"key", "type"}`` entries) and emits deterministic
corpus seed bytes. It performs **no live enumeration of system daemons** and
sends no messages anywhere (#108).
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_xpc = sub.add_parser("xpc", parents=[parent],
                           help="XPC/Mach message-schema research targets")
    xsub = p_xpc.add_subparsers(dest="xpc_action", metavar="<action>")

    p_list = xsub.add_parser("list", parents=[parent],
                             help="list XPC targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = xsub.add_parser("inspect", parents=[parent],
                                help="inspect an XPC target")
    p_inspect.add_argument("format", help="dict|array|endpoint or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_harvest = xsub.add_parser("harvest", parents=[parent],
                                help="import a researcher-exported service schema JSON file as deterministic corpus seeds")
    p_harvest.add_argument("schema_file")
    p_harvest.set_defaults(func=cmd_harvest)

    p_xpc.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.xpc import XPC_TARGETS
    if fmt in XPC_TARGETS:
        return fmt
    candidate = f"xpc:{fmt}"
    if candidate in XPC_TARGETS:
        return candidate
    raise NotFoundError(f"unknown XPC format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.xpc import XPC_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(XPC_TARGETS)]
    return Result(command="target xpc list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:14} {', '.join(t['formats'])}" for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target xpc inspect", data={"target": d})


def cmd_harvest(ctx, args) -> Result:
    import json
    import os

    from ..targets.xpc import XPC_TARGETS
    if not os.path.exists(args.schema_file):
        raise NotFoundError(f"schema file not found: {args.schema_file}")
    with open(args.schema_file) as fh:
        entries = json.load(fh)

    # Deterministic seed bytes: every registered target's base seed, extended
    # with one "&key=type" suffix per schema entry. Purely local byte
    # construction — nothing is sent or resolved.
    unique: set[bytes] = set()
    for tid in sorted(XPC_TARGETS):
        base = XPC_TARGETS[tid]().seeds()[0]
        for entry in entries:
            etype = entry.get("type", "string")
            unique.add(base + b"&" + entry["key"].encode() + b"=" + etype.encode())

    return Result(command="target xpc harvest",
                  data={"seeds": len(unique), "targets": len(XPC_TARGETS)},
                  human=lambda d: f"imported {d['seeds']} deterministic seeds "
                                  f"across {d['targets']} XPC targets")
