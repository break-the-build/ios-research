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

    p_bounty_validate = sub.add_parser("bounty-validate", parents=[parent],
                                       help="check local Apple-bounty evidence readiness")
    p_bounty_validate.add_argument("report_id")
    p_bounty_validate.add_argument("--metadata", default=None,
                                  help="optional local JSON metadata/attestations")
    p_bounty_validate.add_argument("--tccutil-output", dest="tccutil_output",
                                  default=None,
                                  help="captured 'tccutil flag check' text "
                                       "file (#84); makes the TCC flag "
                                       "check binding")
    p_bounty_validate.set_defaults(func=cmd_bounty_validate)

    p_bounty_export = sub.add_parser("bounty-export", parents=[parent],
                                     help="export a redacted local Apple-bounty evidence pack")
    p_bounty_export.add_argument("report_id")
    p_bounty_export.add_argument("--metadata", default=None,
                                 help="optional local JSON metadata/attestations")
    p_bounty_export.add_argument("--out", default=None,
                                 help="output directory (default: report evidence directory)")
    p_bounty_export.set_defaults(func=cmd_bounty_export)

    p_cov = sub.add_parser("coverage", parents=[parent],
                           help="coverage/corpus-quality report for a fuzz session (#34)")
    p_cov.add_argument("session_id", nargs="?", default=None)
    p_cov.add_argument("--markdown", action="store_true", dest="as_markdown")
    p_cov.set_defaults(func=cmd_coverage)

    p_cov_cmp = sub.add_parser("coverage-compare", parents=[parent],
                               help="compare two coverage reports for growth/regression (#34)")
    p_cov_cmp.add_argument("base_session_id")
    p_cov_cmp.add_argument("head_session_id")
    p_cov_cmp.set_defaults(func=cmd_coverage_compare)

    p_reach = sub.add_parser("reachability", parents=[parent],
                             help="compare declared static inventory with dynamic coverage (#34)")
    p_reach.add_argument("session_id", nargs="?", default=None)
    p_reach.add_argument("--inventory", required=True,
                         help="JSON file with a list of statically reachable feature/function IDs")
    p_reach.set_defaults(func=cmd_reachability)

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


def cmd_bounty_validate(ctx, args) -> Result:
    from pathlib import Path
    from ..bounty import BountyReadiness, load_metadata
    from ..errors import ValidationError
    readiness = BountyReadiness(ctx.workspace())
    report = readiness.reports.get(args.report_id)
    tccutil_output = None
    if args.tccutil_output:
        try:
            tccutil_output = Path(args.tccutil_output).read_text(
                encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ValidationError(
                f"cannot read tccutil output file: {exc}") from exc
    result = readiness.validate(report, load_metadata(args.metadata),
                                tccutil_output=tccutil_output)
    return Result(command="report bounty-validate", ok=result["ready"], data=result,
                  messages=["evidence complete" if result["ready"]
                            else f"missing: {', '.join(result['missing'])}"])


def cmd_bounty_export(ctx, args) -> Result:
    from ..bounty import BountyReadiness, load_metadata
    readiness = BountyReadiness(ctx.workspace())
    report = readiness.reports.get(args.report_id)
    metadata = load_metadata(args.metadata)
    path = readiness.write_pack(report, metadata, args.out)
    result = readiness.validate(report, metadata)
    return Result(command="report bounty-export",
                  data={"manifest": str(path), "directory": str(path.parent),
                        "ready": result["ready"],
                        "safety": "local validated evidence copies only; no data transmitted"})


def cmd_coverage(ctx, args) -> Result:
    from ..coverage_report import CoverageReporter
    report = CoverageReporter(ctx.workspace()).from_session_id(
        args.session_id)
    if getattr(args, "as_markdown", False):
        return Result(command="report coverage",
                      data={"markdown": CoverageReporter.markdown(report)},
                      human=lambda d: d["markdown"])
    return Result(command="report coverage", data=report)


def cmd_coverage_compare(ctx, args) -> Result:
    from ..coverage_report import CoverageReporter
    reporter = CoverageReporter(ctx.workspace())
    base = reporter.from_session_id(args.base_session_id)
    head = reporter.from_session_id(args.head_session_id)
    comparison = CoverageReporter.compare(base, head)
    verdict = ("growth" if comparison["delta"] > 0 else
               "regression" if comparison["delta"] < 0 else "flat")
    return Result(command="report coverage-compare",
                  data=comparison,
                  messages=[f"coverage {verdict}: "
                            f"{comparison['base_unique']} -> "
                            f"{comparison['head_unique']} features"])


def cmd_reachability(ctx, args) -> Result:
    import json as _json
    from ..coverage_report import CoverageReporter
    from ..errors import ValidationError
    try:
        inventory = _json.loads(Path(args.inventory).read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"cannot read inventory: {exc}") from exc
    if not isinstance(inventory, list) or \
            not all(isinstance(item, str) for item in inventory):
        raise ValidationError("inventory must be a JSON array of strings")
    report = CoverageReporter(ctx.workspace()).from_session_id(args.session_id)
    analysis = CoverageReporter.reachability(report, inventory)
    return Result(command="report reachability", data=analysis)
