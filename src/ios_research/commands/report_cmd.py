"""`ios-research report` — create/show/validate/export vulnerability reports."""

from __future__ import annotations

from pathlib import Path

from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("report", parents=[parent],
                              help="generate responsible-disclosure reports")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_create = sub.add_parser("create", parents=[parent],
                              help="create a report from a crash")
    p_create.add_argument("crash_id")
    p_create.set_defaults(func=cmd_create)

    p_show = sub.add_parser("show", parents=[parent], help="show a report")
    p_show.add_argument("report_id")
    p_show.set_defaults(func=cmd_show)

    p_val = sub.add_parser("validate", parents=[parent],
                           help="validate a report for missing evidence")
    p_val.add_argument("report_id")
    p_val.set_defaults(func=cmd_validate)

    p_exp = sub.add_parser("export", parents=[parent],
                           help="export a report as markdown or json")
    p_exp.add_argument("report_id")
    p_exp.add_argument("--format", default="markdown",
                       choices=["markdown", "md", "json"])
    p_exp.add_argument("--out", default=None)
    p_exp.set_defaults(func=cmd_export)

    p_list = sub.add_parser("list", parents=[parent], help="list reports")
    p_list.set_defaults(func=cmd_list)

    p.set_defaults(func=cmd_list)


def cmd_create(ctx, args) -> Result:
    from ..report import ReportGenerator
    gen = ReportGenerator(ctx.workspace())
    report = gen.create(args.crash_id)
    validation = gen.validate(report)
    return Result(command="report create",
                  data={"report_id": report.id, "valid": validation["valid"],
                        "issues": validation["issues"]},
                  messages=[f"created report {report.id} "
                            f"({'valid' if validation['valid'] else 'has issues'})"])


def cmd_show(ctx, args) -> Result:
    from ..report import ReportGenerator
    report = ReportGenerator(ctx.workspace()).get(args.report_id)
    return Result(command="report show", data={"report": report.to_dict()})


def cmd_validate(ctx, args) -> Result:
    from ..report import ReportGenerator
    gen = ReportGenerator(ctx.workspace())
    report = gen.get(args.report_id)
    validation = gen.validate(report)
    return Result(command="report validate", ok=validation["valid"],
                  data=validation,
                  messages=["valid" if validation["valid"]
                            else f"{len(validation['issues'])} issue(s)"])


def cmd_export(ctx, args) -> Result:
    from ..report import ReportGenerator
    gen = ReportGenerator(ctx.workspace())
    report = gen.get(args.report_id)
    content = gen.export(report, args.format)
    if args.out:
        Path(args.out).write_text(content, encoding="utf-8")
        return Result(command="report export",
                      data={"path": args.out, "format": args.format},
                      messages=[f"wrote {args.out}"])
    return Result(command="report export",
                  data={"format": args.format, "content": content},
                  human=lambda d: d["content"])


def cmd_list(ctx, args) -> Result:
    from ..report import ReportGenerator
    reports = ReportGenerator(ctx.workspace()).list()
    items = [{"id": r.id, "crash_id": r.crash_id} for r in reports]
    return Result(command="report list", data={"reports": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{r['id']:20} {r['crash_id']}" for r in d["reports"]) or "(none)")
