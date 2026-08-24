"""`ios-research xcode` — test-plan adapter and XCResult ingestion (#36)."""

from __future__ import annotations

import json
import os

from ..errors import InterruptedError_, NotFoundError, StateError, UsageError
from ..output import Result


def _add_test_args(p) -> None:
    p.add_argument("plan_id")
    p.add_argument("--project", default=None)
    p.add_argument("--xcode-workspace", dest="workspace_swift",
                    default=None)
    p.add_argument("--destination", default=None)
    p.add_argument("--only-testing", action="append", default=None)
    p.add_argument("--sanitizer", action="append", default=None,
                    help="address|thread|undefined-behavior|"
                         "main-thread-checker|guard-malloc|zombies|"
                         "code-coverage (repeatable)")
    p.add_argument("--result-bundle-path", default=None)
    p.add_argument("--dry-run", action="store_true",
                    help="print the command without executing "
                         "(construction-only is the default)")
    p.add_argument("--execute", action="store_true",
                   help="actually run xcodebuild (opt-in; requires --yes)")
    p.add_argument("--timeout", type=float, default=600.0)


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("xcode", parents=[parent],
                              help="Xcode test-plan adapter and XCResult "
                                   "diagnostic ingestion")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_plan = sub.add_parser("plan", parents=[parent],
                            help="import and inspect Xcode test plans")
    plan_sub = p_plan.add_subparsers(dest="plan_subcommand",
                                     metavar="<action>")

    p_import = plan_sub.add_parser("import", parents=[parent],
                                   help="import a .xctestplan JSON file")
    p_import.add_argument("path")
    p_import.set_defaults(func=cmd_plan_import)

    p_plist = plan_sub.add_parser("list", parents=[parent],
                                  help="list imported test plans")
    p_plist.set_defaults(func=cmd_plan_list)

    p_pshow = plan_sub.add_parser("show", parents=[parent],
                                  help="show one imported test plan")
    p_pshow.add_argument("plan_id")
    p_pshow.set_defaults(func=cmd_plan_show)

    p_test = sub.add_parser("test", parents=[parent],
                            help="construct (or opt-in run) an xcodebuild "
                                 "test command")
    _add_test_args(p_test)
    p_test.set_defaults(func=cmd_test)

    # Canonical alias names from the issue's CLI contract.
    p_import_plan = sub.add_parser("import-plan", parents=[parent],
                                   help="alias of 'plan import': import a "
                                        ".xctestplan JSON file")
    p_import_plan.add_argument("path")
    p_import_plan.set_defaults(func=cmd_plan_import)

    p_run_tests = sub.add_parser("run-tests", parents=[parent],
                                 help="alias of 'test': construct (or "
                                      "opt-in run) an xcodebuild test command")
    _add_test_args(p_run_tests)
    p_run_tests.set_defaults(func=cmd_test)

    p_parse_xcr = sub.add_parser("parse-xcresult", parents=[parent],
                                 help="alias of 'xcresult parse': parse an "
                                      ".xcresult bundle or exported JSON")
    p_parse_xcr.add_argument("path")
    p_parse_xcr.set_defaults(func=cmd_xcresult_parse)

    p_repro_cmd = sub.add_parser("repro-cmd", parents=[parent],
                                 help="focused xcodebuild reproduction "
                                      "command from a parsed xcresult record "
                                      "or a minimized fuzz input")
    p_repro_cmd.add_argument("record_id", nargs="?", default=None)
    p_repro_cmd.add_argument("--plan", required=True)
    p_repro_cmd.add_argument("--failure-index", type=int, default=0)
    p_repro_cmd.add_argument("--project", default=None)
    p_repro_cmd.add_argument("--xcode-workspace", dest="workspace_swift",
                             default=None)
    p_repro_cmd.add_argument("--input", default=None,
                             help="minimized fuzz input path to map instead "
                                  "of a recorded failure")
    p_repro_cmd.add_argument("--action", action="append", default=None,
                             help="action sequence step (repeatable, with "
                                  "--input)")
    p_repro_cmd.add_argument("--test", default=None,
                             help="explicit -only-testing identifier override")
    p_repro_cmd.add_argument("--sanitizer", action="append", default=None)
    p_repro_cmd.set_defaults(func=cmd_repro_cmd)

    p_xcr = sub.add_parser("xcresult", parents=[parent],
                           help="parse .xcresult bundles or exported JSON")
    xcr_sub = p_xcr.add_subparsers(dest="xcr_subcommand", metavar="<action>")

    p_parse = xcr_sub.add_parser("parse", parents=[parent],
                                 help="parse an .xcresult bundle or a "
                                      "xcresulttool JSON export")
    p_parse.add_argument("path")
    p_parse.set_defaults(func=cmd_xcresult_parse)

    p_xlist = xcr_sub.add_parser("list", parents=[parent],
                                 help="list parsed xcresult records")
    p_xlist.set_defaults(func=cmd_xcresult_list)

    p_xshow = xcr_sub.add_parser("show", parents=[parent],
                                 help="show one parsed xcresult record")
    p_xshow.add_argument("record_id")
    p_xshow.set_defaults(func=cmd_xcresult_show)

    p_repro = sub.add_parser("repro", parents=[parent],
                             help="focused xcodebuild reproduction command "
                                  "for one recorded failure")
    p_repro.add_argument("record_id")
    p_repro.add_argument("--plan", required=True)
    p_repro.add_argument("--failure-index", type=int, default=0)
    p_repro.add_argument("--project", default=None)
    p_repro.add_argument("--xcode-workspace", dest="workspace_swift",
                     default=None)
    p_repro.set_defaults(func=cmd_repro)

    p.set_defaults(func=cmd_plan_list)


def _store(ctx):
    from ..xcode import PlanStore
    return PlanStore(ctx.workspace())


def cmd_plan_import(ctx, args) -> Result:
    from ..xcode import parse_test_plan
    plan = parse_test_plan(args.path)
    saved = _store(ctx).save(plan)
    return Result(command="xcode plan import",
                  data={"plan": saved},
                  messages=[f"imported plan '{saved['name']}' with "
                            f"{len(saved['targets'])} target(s)"])


def cmd_plan_list(ctx, args) -> Result:
    plans = _store(ctx).list()
    return Result(command="xcode plan list",
                  data={"plans": plans, "count": len(plans)},
                  human=lambda d: "\n".join(
                      f"{p['id']}  {p['name']} "
                      f"({len(p['targets'])} targets)" for p in d["plans"])
                  or "(none)")


def cmd_plan_show(ctx, args) -> Result:
    return Result(command="xcode plan show",
                  data={"plan": _store(ctx).get(args.plan_id)})


def cmd_test(ctx, args) -> Result:
    from ..xcode import XcodebuildBackend, build_test_command
    plan = _store(ctx).get(args.plan_id)
    cmd = build_test_command(
        plan, project=args.project, workspace_swift=args.workspace_swift,
        only_testing=args.only_testing, sanitizers=args.sanitizer,
        destination=args.destination,
        result_bundle_path=args.result_bundle_path)
    # Construction-only by default; execution is an explicit, confirmed
    # opt-in honoring the framework's --yes safety convention.
    execute = bool(getattr(args, "execute", False)) \
        and not getattr(args, "dry_run", False)
    backend = XcodebuildBackend()
    run_result = None
    if execute:
        if not ctx.confirm("run xcodebuild test"):
            raise InterruptedError_(
                "xcode test --execute requires confirmation; "
                "re-run with --yes")
        if not backend.available():
            # Actionable JSON error, per the issue's acceptance criteria.
            raise StateError(
                f"xcodebuild unavailable: {backend.blocker()} "
                f"(omit --execute to construct the command only)",
                details={"command": cmd})
        run_result = backend.run(cmd, timeout_s=args.timeout)
    return Result(command="xcode test",
                  ok=run_result["exit_code"] == 0 if run_result else True,
                  data={"command": cmd, "executed": execute,
                        "plan_id": plan["id"], "run": run_result},
                  messages=["constructed: " + " ".join(cmd)]
                  if run_result is None else
                  [f"xcodebuild exited {run_result['exit_code']}"])


def cmd_xcresult_parse(ctx, args) -> Result:
    from ..xcode import XCResultStore, parse_xcresult_path, tool_provenance
    normalized, raw = parse_xcresult_path(args.path)
    provenance = normalized.setdefault("provenance", {})
    if "environment" in normalized and isinstance(
            normalized["environment"], dict) \
            and "environment" not in provenance:
        provenance["environment"] = normalized.pop("environment")
    provenance["ingest"] = tool_provenance()
    saved = XCResultStore(ctx.workspace()).save(normalized, raw)
    crashes = saved.get("crashes") or saved.get("failures") or []
    return Result(command="xcode xcresult parse",
                  data={"record": saved},
                  messages=[f"parsed {saved['source']}: "
                            f"{len(crashes)} crash/failure(s), "
                            f"{len(saved.get('logs', []))} log file(s), "
                            f"{len(saved.get('unrecognized', []))} "
                            f"unrecognized issue type(s)"])


def cmd_xcresult_list(ctx, args) -> Result:
    from ..xcode import XCResultStore
    records = XCResultStore(ctx.workspace()).list()
    return Result(command="xcode xcresult list",
                  data={"records": records, "count": len(records)},
                  human=lambda d: "\n".join(
                      f"{r['id']}  {r['source']} "
                      f"({len(r['failures'])} failures)" for r in d["records"])
                  or "(none)")


def cmd_xcresult_show(ctx, args) -> Result:
    from ..xcode import XCResultStore
    return Result(command="xcode xcresult show",
                  data={"record": XCResultStore(ctx.workspace())
                        .get(args.record_id)})


def _repro_from_record(ctx, args) -> Result:
    from ..xcode import XCResultStore, PlanStore, map_repro_command
    record = XCResultStore(ctx.workspace()).get(args.record_id)
    plan = PlanStore(ctx.workspace()).get(args.plan)
    failures = record.get("failures") or record.get("crashes") or []
    if not failures:
        raise StateError(
            f"xcresult record '{args.record_id}' has no failures to map")
    if not 0 <= args.failure_index < len(failures):
        raise UsageError(
            f"--failure-index must be 0..{len(failures) - 1}")
    failure = failures[args.failure_index]
    test_id = failure.get("test") or ""
    if not test_id:
        raise StateError(
            "the recorded failure has no test identifier; cannot map to a "
            "focused -only-testing target",
            details={"failure": failure})
    sanitizers = [failure["sanitizer"]] if failure.get("sanitizer") else []
    cmd = map_repro_command(plan, failing_test=test_id,
                            project=args.project,
                            workspace_swift=args.workspace_swift,
                            sanitizers=sanitizers)
    return Result(command="xcode repro",
                  data={"command": cmd, "failure": failure,
                        "plan_id": plan["id"]},
                  messages=["focused repro: " + " ".join(cmd)])


def cmd_repro(ctx, args) -> Result:
    return _repro_from_record(ctx, args)


def cmd_repro_cmd(ctx, args) -> Result:
    from ..xcode import PlanStore, map_repro_from_input
    input_path = getattr(args, "input", None)
    record_id = getattr(args, "record_id", None)
    if input_path and record_id:
        raise UsageError("pass either a record id or --input, not both")
    if not input_path and not record_id:
        raise UsageError("provide an xcresult record id or --input PATH")
    if input_path:
        plan = PlanStore(ctx.workspace()).get(args.plan)
        mapped = map_repro_from_input(
            plan, input_path=input_path,
            actions=getattr(args, "action", None),
            project=args.project, workspace_swift=args.workspace_swift,
            sanitizers=getattr(args, "sanitizer", None),
            test=getattr(args, "test", None))
        return Result(command="xcode repro-cmd",
                      data={**mapped, "plan_id": plan["id"]},
                      messages=["focused repro: "
                                + " ".join(mapped["command"])])
    return _repro_from_record(ctx, args)
