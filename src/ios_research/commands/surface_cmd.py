"""`ios-research surface` — attack-surface inventory and prioritization (#61)."""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("surface", parents=[parent],
                              help="attack-surface inventory + bounty-EV "
                                   "campaign prioritization (snapshot-driven)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_ingest = sub.add_parser("ingest", parents=[parent],
                              help="validate and store a system snapshot JSON")
    p_ingest.add_argument("path")
    p_ingest.set_defaults(func=cmd_ingest)

    p_plan = sub.add_parser("plan", parents=[parent],
                            help="rank surfaces by bounty expected value")
    p_plan.add_argument("--inventory", required=True,
                        help="surface-inventory id from 'surface ingest'")
    p_plan.add_argument("--previous-plan", default=None,
                        help="down-rank surfaces covered by an earlier plan")
    p_plan.add_argument("--novelty-yield", type=float, default=None,
                        help="explicit novel ratio override [0..1] "
                             "(default: latest advisory scan or 0.5)")
    p_plan.add_argument("--saturation-penalty", type=float, default=0.5)
    p_plan.set_defaults(func=cmd_plan)

    p_list = sub.add_parser("list", parents=[parent],
                            help="list inventories and plans")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent], help="show a plan")
    p_show.add_argument("plan_id")
    p_show.set_defaults(func=cmd_show)

    p.set_defaults(func=cmd_list)


def cmd_ingest(ctx, args) -> Result:
    from ..surface import SurfaceEngine
    record = SurfaceEngine(ctx.workspace()).ingest(args.path)
    return Result(command="surface ingest",
                  data={"inventory_id": record["id"],
                        "surfaces": len(record["surfaces"])},
                  messages=[f"stored inventory {record['id']} "
                            f"({len(record['surfaces'])} surfaces)"])


def cmd_plan(ctx, args) -> Result:
    from ..surface import SurfaceEngine
    plan = SurfaceEngine(ctx.workspace()).plan(
        inventory_id=args.inventory, previous_plan_id=args.previous_plan,
        novelty_yield=args.novelty_yield,
        saturation_penalty=args.saturation_penalty)
    summary = plan["summary"]
    top = plan["ranked_surfaces"][0] if plan["ranked_surfaces"] else None
    return Result(command="surface plan",
                  data={"plan_id": plan["id"], **plan},
                  messages=[
                      f"planned {summary['surfaces']} surfaces "
                      f"(unclassified: {summary['unclassified']})",
                      f"top: {summary['top_surface']}"
                      + (f" tier={top['reward_tier']}" if top else ""),
                  ])


def cmd_list(ctx, args) -> Result:
    from ..surface import SurfaceEngine
    items = [{"id": r["id"], "kind": r["kind"], "created_at": r["created_at"]}
             for r in SurfaceEngine(ctx.workspace()).list()]
    return Result(command="surface list",
                  data={"records": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{r['id']} {r['kind']}" for r in d["records"])
                  or "(none)")


def cmd_show(ctx, args) -> Result:
    from ..surface import SurfaceEngine
    try:
        plan = SurfaceEngine(ctx.workspace()).get(args.plan_id)
    except Exception as exc:
        raise NotFoundError(f"surface plan '{args.plan_id}' not found") from exc
    rows = "\n".join(
        f"{r['surface_id']:28} tier={str(r['reward_tier']):>9} "
        f"ev={r['ev_score']:.4f}{' SAT' if r['saturated'] else ''}"
        for r in plan["ranked_surfaces"])
    return Result(command="surface show", data={"plan": plan},
                  human=lambda _d: rows or "(empty plan)")
