"""`ios-research target voiceassist` — list and inspect voice-assistant targets.

Installs itself as a subcommand of ``target`` via the target command's
extension hook.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result
from . import target_cmd


def _install(sub, parent) -> None:
    p_va = sub.add_parser("voiceassist", parents=[parent],
                          help="voice-assistant record research targets")
    vsub = p_va.add_subparsers(dest="voiceassist_action", metavar="<action>")

    p_list = vsub.add_parser("list", parents=[parent],
                             help="list voice-assistant targets")
    p_list.set_defaults(func=cmd_list)

    p_inspect = vsub.add_parser("inspect", parents=[parent],
                                help="inspect a voice-assistant target")
    p_inspect.add_argument("format",
                           help="siri-suggestion|callkit-intent or a full id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_va.set_defaults(func=cmd_list)


def register(subparsers, parent) -> None:
    # Register the installer with the target command group.
    target_cmd.add_subcommand(_install)


def _resolve(fmt: str) -> str:
    from ..targets.voiceassist import VOICEASSIST_TARGETS
    if fmt in VOICEASSIST_TARGETS:
        return fmt
    candidate = f"voiceassist:{fmt}"
    if candidate in VOICEASSIST_TARGETS:
        return candidate
    raise NotFoundError(f"unknown voice-assistant format '{fmt}'")


def cmd_list(ctx, args) -> Result:
    from .. import targets
    from ..targets.voiceassist import VOICEASSIST_TARGETS
    items = [targets.create(tid).describe() for tid in sorted(VOICEASSIST_TARGETS)]
    return Result(command="target voiceassist list",
                  data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{t['id']:28} {', '.join(t['formats'])}" for t in d["targets"]))


def cmd_inspect(ctx, args) -> Result:
    from .. import targets
    target_id = _resolve(args.format)
    target = targets.create(target_id)
    d = target.describe()
    d["seed_count"] = len(target.seeds())
    return Result(command="target voiceassist inspect", data={"target": d})
