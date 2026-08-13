"""`ios-research analyze` and `ios-research analysis` commands."""

from __future__ import annotations

from ..analysis import Analyzer
from ..crashes import CrashStore
from ..errors import UsageError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("analyze", parents=[parent],
                              help="root-cause and exploitability analysis")
    p.add_argument("crash_id", nargs="?", default=None)
    p.add_argument("--batch", action="store_true",
                   help="analyze all crashes (default when no id is given)")
    p.set_defaults(func=cmd_analyze)

    p_analysis = subparsers.add_parser("analysis", parents=[parent],
                                       help="inspect stored analyses")
    sub = p_analysis.add_subparsers(dest="subcommand", metavar="<action>")
    p_show = sub.add_parser("show", parents=[parent], help="show an analysis")
    p_show.add_argument("analysis_id")
    p_show.set_defaults(func=cmd_show)
    p_list = sub.add_parser("list", parents=[parent], help="list analyses")
    p_list.set_defaults(func=cmd_list)
    p_analysis.set_defaults(func=cmd_list)


def cmd_analyze(ctx, args) -> Result:
    analyzer = Analyzer(ctx.workspace())
    if args.crash_id and not args.batch:
        crash = CrashStore(ctx.workspace()).get(args.crash_id)
        analysis = analyzer.analyze(crash)
        return Result(command="analyze",
                      data={"analysis": analysis.to_dict()},
                      messages=[f"{analysis.id}: "
                                f"{analysis.exploitability_classification} "
                                f"({analysis.confidence})"])
    # Batch (explicit or when no id supplied).
    analyses = analyzer.analyze_batch()
    summary: dict[str, int] = {}
    for a in analyses:
        summary[a.exploitability_classification] = \
            summary.get(a.exploitability_classification, 0) + 1
    return Result(command="analyze",
                  data={"count": len(analyses), "by_indicator": summary,
                        "analysis_ids": [a.id for a in analyses]},
                  messages=[f"analyzed {len(analyses)} crash(es)"])


def cmd_show(ctx, args) -> Result:
    analysis = Analyzer(ctx.workspace()).get(args.analysis_id)
    return Result(command="analysis show", data={"analysis": analysis.to_dict()})


def cmd_list(ctx, args) -> Result:
    analyses = Analyzer(ctx.workspace()).list()
    items = [{"id": a.id, "crash_id": a.crash_id,
              "indicator": a.exploitability_classification,
              "confidence": a.confidence} for a in analyses]
    return Result(command="analysis list",
                  data={"analyses": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{a['id']:20} {a['indicator']:34} {a['confidence']}"
                      for a in d["analyses"]) or "(none)")
