"""`ios-research proximity` — host-side proximity parser harness profiles (#63)."""

from __future__ import annotations

from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("proximity", parents=[parent],
                              help="host-side proximity parser harness "
                                   "profiles (opt-in; no RF transmission)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_list = sub.add_parser("list", parents=[parent],
                            help="list profiles and their gating state")
    p_list.set_defaults(func=cmd_list)

    p_smoke = sub.add_parser("smoke", parents=[parent],
                             help="bounded smoke run over a profile's "
                                  "harness surfaces")
    p_smoke.add_argument("profile_id")
    p_smoke.add_argument("--enable", action="store_true",
                         dest="enable",
                         help="explicitly opt in to this profile for this "
                              "invocation")
    p_smoke.add_argument("--max-cases", type=int, default=50)
    p_smoke.set_defaults(func=cmd_smoke)

    p.set_defaults(func=cmd_list)


def _enabled(ctx, args) -> set[str]:
    from ..proximity import enabled_from_config
    enabled = enabled_from_config(ctx.config())
    if getattr(args, "enable", False):
        enabled = set(enabled)
        enabled.add(args.profile_id)
    return enabled


def cmd_list(ctx, args) -> Result:
    from ..proximity import catalog, enabled_from_config
    entries = catalog(enabled=enabled_from_config(ctx.config()))
    return Result(command="proximity list",
                  data={"profiles": entries, "count": len(entries)},
                  human=lambda d: "\n".join(
                      f"{p['id']:28} enabled={str(p['enabled']).lower():5} "
                      f"runnable={str(p['runnable']).lower():5} "
                      f"{p['label']}" for p in d["profiles"]) or "(none)")


def cmd_smoke(ctx, args) -> Result:
    from ..proximity import ProximityEngine
    record = ProximityEngine(ctx.workspace()).smoke(
        profile_id=args.profile_id, enabled=_enabled(ctx, args),
        max_cases=args.max_cases)
    totals = record["totals"]
    return Result(command="proximity smoke",
                  data=record,
                  messages=[f"{record['profile']}: {totals['executed']} "
                            f"execution(s) across "
                            f"{len(record['surfaces'])} surface(s) "
                            f"(crash={totals['crash']})"])
