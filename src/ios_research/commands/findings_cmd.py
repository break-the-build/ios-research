"""`ios-research findings` — SARIF import + adjudication of static results."""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("findings", parents=[parent],
                              help="static-analysis findings triage")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_imp = sub.add_parser("import", parents=[parent],
                           help="import a SARIF report")
    p_imp.add_argument("--sarif", required=True,
                       help="path to the SARIF JSON file")
    p_imp.add_argument("--tool", default=None,
                       help="override tool name for all imported findings")
    p_imp.set_defaults(func=cmd_import)

    p_list = sub.add_parser("list", parents=[parent], help="list findings")
    p_list.add_argument("--status", default=None)
    p_list.add_argument("--cwe", default=None)
    p_list.set_defaults(func=cmd_list)

    p_adj = sub.add_parser("adjudicate", parents=[parent],
                           help="adjudicate pending findings")
    p_adj.add_argument("finding_id", nargs="?", default=None)
    p_adj.set_defaults(func=cmd_adjudicate)

    p_show = sub.add_parser("show", parents=[parent], help="show a finding")
    p_show.add_argument("finding_id")
    p_show.set_defaults(func=cmd_show)

    p_dis = sub.add_parser("dismiss", parents=[parent],
                           help="manually dismiss a finding")
    p_dis.add_argument("finding_id")
    p_dis.add_argument("--reason", default="")
    p_dis.set_defaults(func=cmd_dismiss)

    p_con = sub.add_parser("confirm", parents=[parent],
                           help="manually confirm a finding")
    p_con.add_argument("finding_id")
    p_con.add_argument("--reason", default="")
    p_con.set_defaults(func=cmd_confirm)

    p_obj = sub.add_parser("objectives", parents=[parent],
                           help="confirmed findings as fuzz objectives")
    p_obj.set_defaults(func=cmd_objectives)

    p.set_defaults(func=cmd_list)


def cmd_import(ctx, args) -> Result:
    from ..findings import FindingsPipeline
    try:
        text = open(args.sarif, encoding="utf-8").read()
    except OSError as exc:
        raise NotFoundError(f"cannot read SARIF file: {exc}") from exc
    pipeline = FindingsPipeline(ctx.workspace())
    summary = pipeline.import_sarif(text, default_tool=args.tool)
    return Result(command="findings import",
                  data={"sarif": args.sarif, **summary},
                  messages=[f"imported {summary['imported']} finding(s), "
                            f"{summary['duplicates']} duplicate(s)"])


def _rows(records):
    return [{"id": f.id, "tool": f.tool, "rule": f.rule_id, "cwe": f.cwe,
             "severity": f.severity, "file": f.file_path,
             "line": f.start_line, "status": f.status} for f in records]


def cmd_list(ctx, args) -> Result:
    from ..findings import FindingsStore
    records = FindingsStore(ctx.workspace()).list(status=args.status)
    if args.cwe:
        records = [r for r in records if r.cwe == args.cwe]
    data = {"findings": _rows(records), "count": len(records)}
    return Result(command="findings list", data=data,
                  human=lambda d: "\n".join(
                      f"{x['id']:24} {x['rule']:20.20} {x['cwe'] or '-':8}"
                      f" {x['status']:9} {x['file']}:{x['line']}"
                      for x in d["findings"]) or "(none)")


def cmd_adjudicate(ctx, args) -> Result:
    from ..findings import FindingsPipeline, HeuristicAdjudicator
    pipeline = FindingsPipeline(ctx.workspace())
    if args.finding_id:
        rec = pipeline.store.get(args.finding_id)
        verdict = HeuristicAdjudicator().adjudicate(
            rec, root=ctx.workspace().root.parent)
        rec.verdict = verdict
        rec.status = verdict["verdict"]
        pipeline.store.save(rec)
        touched = [rec]
    else:
        touched = pipeline.adjudicate_all(root=ctx.workspace().root.parent)
    counts = {"confirmed": 0, "dismissed": 0, "pending": 0}
    for rec in touched:
        counts[rec.status] = counts.get(rec.status, 0) + 1
    return Result(command="findings adjudicate",
                  data={"adjudicated": len(touched), **counts},
                  messages=[f"adjudicated {len(touched)} finding(s): "
                            f"{counts['confirmed']} confirmed, "
                            f"{counts['dismissed']} dismissed"])


def cmd_show(ctx, args) -> Result:
    from ..findings import FindingsStore
    rec = FindingsStore(ctx.workspace()).get(args.finding_id)
    return Result(command="findings show", data=rec.to_dict())


def cmd_dismiss(ctx, args) -> Result:
    from ..findings import FindingsPipeline
    rec = FindingsPipeline(ctx.workspace()).override(
        args.finding_id, "dismissed", args.reason)
    return Result(command="findings dismiss",
                  data={"id": rec.id, "status": rec.status})


def cmd_confirm(ctx, args) -> Result:
    from ..findings import FindingsPipeline
    rec = FindingsPipeline(ctx.workspace()).override(
        args.finding_id, "confirmed", args.reason)
    return Result(command="findings confirm",
                  data={"id": rec.id, "status": rec.status})


def cmd_objectives(ctx, args) -> Result:
    from ..findings import FindingsPipeline
    objs = FindingsPipeline(ctx.workspace()).objectives()
    return Result(command="findings objectives",
                  data={"objectives": objs, "count": len(objs)},
                  human=lambda d: "\n".join(
                      f"{o['finding_id']} {o['file']}:{o['line']} ({o['cwe']})"
                      for o in d["objectives"]) or "(none)")
