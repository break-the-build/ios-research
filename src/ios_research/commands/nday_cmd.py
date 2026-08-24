"""`ios-research nday` — IPSW build-to-build symbol patch-diffing."""

from __future__ import annotations

from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("nday", parents=[parent],
                              help="IPSW symbol patch-diffing across builds")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_diff = sub.add_parser("diff", parents=[parent],
                            help="diff nm symbol tables from two builds")
    p_diff.add_argument("--name", required=True)
    p_diff.add_argument("--symbols-a", required=True)
    p_diff.add_argument("--symbols-b", required=True)
    p_diff.set_defaults(func=cmd_diff)

    p_list = sub.add_parser("list", parents=[parent],
                            help="list recorded nday diffs")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent],
                            help="show one nday diff")
    p_show.add_argument("nday_id")
    p_show.set_defaults(func=cmd_show)

    p_pri = sub.add_parser("prioritize", parents=[parent],
                           help="rank changed symbols by reachability")
    p_pri.add_argument("nday_id")
    p_pri.add_argument("--reachable", required=True)
    p_pri.set_defaults(func=cmd_prioritize)

    p_camp = sub.add_parser("campaign", parents=[parent],
                            help="build a reproduction campaign plan")
    p_camp.add_argument("nday_id")
    p_camp.add_argument("--reachable", required=True)
    p_camp.set_defaults(func=cmd_campaign)

    p.set_defaults(func=cmd_list)


def _summary(rec) -> dict:
    return {"id": rec.id, "name": rec.name, "stats": rec.stats,
            "planned": bool(rec.plan)}


def cmd_diff(ctx, args) -> Result:
    from ..ipswdiff import NdayEngine
    engine = NdayEngine(ctx.workspace())
    rec = engine.create_diff(args.name, args.symbols_a, args.symbols_b)
    return Result(command="nday diff", data={"nday": rec.to_dict()},
                  messages=[f"created nday diff {rec.id} "
                            f"(+{rec.stats['added']} -{rec.stats['removed']} "
                            f"~{rec.stats['modified']})"])


def cmd_list(ctx, args) -> Result:
    from ..ipswdiff import NdayStore
    items = [_summary(r) for r in NdayStore(ctx.workspace()).list()]
    return Result(command="nday list",
                  data={"ndays": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{x['id']:20} {x['name']:24} "
                      f"[+{x['stats']['added']} -{x['stats']['removed']} "
                      f"~{x['stats']['modified']}]"
                      for x in d["ndays"]) or "(none)")


def cmd_show(ctx, args) -> Result:
    from ..ipswdiff import NdayStore
    rec = NdayStore(ctx.workspace()).get(args.nday_id)
    return Result(command="nday show", data=rec.to_dict())


def cmd_prioritize(ctx, args) -> Result:
    from ..ipswdiff import NdayEngine
    rec = NdayEngine(ctx.workspace()).prioritize(args.nday_id,
                                                 args.reachable)
    return Result(command="nday prioritize",
                  data={"nday_id": rec.id, "plan": rec.plan},
                  messages=[f"ranked {len(rec.plan['ranked'])} changed "
                            f"symbol(s); {rec.plan['reachable_count']} "
                            f"reachable"])


def cmd_campaign(ctx, args) -> Result:
    from ..ipswdiff import NdayEngine
    rec = NdayEngine(ctx.workspace()).campaign(args.nday_id, args.reachable)
    recommended = rec.plan.get("recommended", [])
    return Result(command="nday campaign",
                  data={"nday_id": rec.id, "plan": rec.plan},
                  messages=["recommended for reproduction: "
                            + (", ".join(recommended) if recommended else "(none)")])
