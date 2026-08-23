"""`ios-research spoints` — multi-agent suspicious-point triage pipeline."""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("spoints", parents=[parent],
                              help="suspicious-point triage agents "
                                   "(verify, cluster, poc)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_run = sub.add_parser("run", parents=[parent],
                           help="run the full triage agent pipeline")
    p_run.add_argument("--experiment", default=None,
                       help="restrict to one experiment")
    p_run.add_argument("--limit", type=int, default=None)
    p_run.set_defaults(func=cmd_run)

    p_list = sub.add_parser("list", parents=[parent], help="list reports")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent], help="show a report")
    p_show.add_argument("report_id")
    p_show.set_defaults(func=cmd_show)

    p_points = sub.add_parser("points", parents=[parent],
                              help="show extracted points for one crash")
    p_points.add_argument("report_id")
    p_points.add_argument("crash_id")
    p_points.set_defaults(func=cmd_points)

    p.set_defaults(func=cmd_list)


def cmd_run(ctx, args) -> Result:
    from ..spoints import SpointsEngine
    engine = SpointsEngine(ctx.workspace())
    report = engine.run(experiment_id=args.experiment, limit=args.limit)
    return Result(command="spoints run",
                  data={"report_id": report.id, "stats": report.stats},
                  messages=[
                      f"{report.stats['verified']}/{report.stats['crashes']} "
                      f"verified, {report.stats['clusters']} cluster(s), "
                      f"{report.stats['poc_triggered']} PoC-confirmed"])


def cmd_list(ctx, args) -> Result:
    from ..spoints import SpointsEngine
    reports = SpointsEngine(ctx.workspace()).list()
    data = {"reports": [{"id": r.id, "created_at": r.created_at,
                         "scope": r.scope_experiment_id, **r.stats}
                        for r in reports],
            "count": len(reports)}
    return Result(command="spoints list", data=data,
                  human=lambda d: "\n".join(
                      f"{x['id']:24} crashes={x['crashes']} "
                      f"verified={x['verified']} clusters={x['clusters']}"
                      for x in d["reports"]) or "(none)")


def cmd_show(ctx, args) -> Result:
    from ..spoints import SpointsEngine
    report = SpointsEngine(ctx.workspace()).get(args.report_id)
    return Result(command="spoints show", data=report.to_dict())


def cmd_points(ctx, args) -> Result:
    from ..errors import NotFoundError
    from ..spoints import SpointsEngine
    report = SpointsEngine(ctx.workspace()).get(args.report_id)
    if args.crash_id not in report.points:
        raise NotFoundError(
            f"crash '{args.crash_id}' has no points in report "
            f"'{args.report_id}' (unverified or out of scope)")
    return Result(command="spoints points",
                  data={"report_id": report.id,
                        "crash_id": args.crash_id,
                        "points": report.points[args.crash_id]})
