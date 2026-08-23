"""`ios-research target docimp` — list and inspect document-importer targets.

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_doc = sub.add_parser("docimp", parents=[parent],
                           help="document-importer research targets")
    dsub = p_doc.add_subparsers(dest="docimp_action", metavar="<action>")

    p_list = dsub.add_parser("list", parents=[parent],
                             help="list document-importer targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = dsub.add_parser("inspect", parents=[parent],
                                help="inspect a document-importer target")
    p_inspect.add_argument("format",
                           help="zip-archive|ooxml-part|font|pdfform or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_doc.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.docimp import DOCIMP_TARGETS
    if fmt in DOCIMP_TARGETS:
        return fmt
    candidate = f"docimp:{fmt}"
    if candidate in DOCIMP_TARGETS:
        return candidate
    raise NotFoundError(f"unknown document-importer format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.docimp import DOCIMP_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(DOCIMP_TARGETS)]
    return Result(command="target docimp list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:22} {', '.join(t['formats'])}" for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target docimp inspect", data={"target": d})
