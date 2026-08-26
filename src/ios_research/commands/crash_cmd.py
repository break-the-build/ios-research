"""`ios-research crash` — list/show/reproduce/minimize/classify/compare."""

from __future__ import annotations

from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("crash", parents=[parent],
                              help="triage discovered crashes")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_list = sub.add_parser("list", parents=[parent], help="list crashes")
    p_list.add_argument("--new-only", action="store_true",
                        help="only records not yet worked (status == 'new'). "
                             "No pipeline stage transitions status today, so "
                             "this currently matches every record; the flag "
                             "exists so agents can rely on the contract "
                             "once status transitions land (#264)")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent], help="show a crash")
    p_show.add_argument("crash_id")
    p_show.set_defaults(func=cmd_show)

    p_repro = sub.add_parser("reproduce", parents=[parent],
                             help="deterministically reproduce a crash")
    p_repro.add_argument("crash_id")
    p_repro.set_defaults(func=cmd_reproduce)

    p_min = sub.add_parser("minimize", parents=[parent],
                           help="minimize a crash input (delta debugging)")
    p_min.add_argument("crash_id")
    p_min.add_argument("--max-executions", type=int, default=None,
                       help="bound total target executions during minimization")
    p_min.set_defaults(func=cmd_minimize)

    p_cls = sub.add_parser("classify", parents=[parent],
                           help="classify a crash from diagnostics")
    p_cls.add_argument("crash_id")
    p_cls.set_defaults(func=cmd_classify)

    p_cmp = sub.add_parser("compare", parents=[parent],
                           help="compare two crashes")
    p_cmp.add_argument("crash_id_a")
    p_cmp.add_argument("crash_id_b")
    p_cmp.set_defaults(func=cmd_compare)

    p.set_defaults(func=cmd_list)


def cmd_list(ctx, args) -> Result:
    from ..crashes import CrashStore
    crashes = CrashStore(ctx.workspace()).list()
    # --new-only (#264): the agent-facing "not yet worked" view. Crash status
    # is only ever 'new' today (reproduce/minimize/analyze update
    # reproduced/minimized_sha256/analysis_id but never transition status), so
    # the filter currently equals the full listing — it is in place so agents
    # can adopt it before status transitions exist.
    if getattr(args, "new_only", False):
        crashes = [c for c in crashes if c.status == "new"]
    items = [{"id": c.id, "classification": c.classification,
              "signature": c.signature, "count": c.count, "target": c.target,
              "reproduced": c.reproduced, "status": c.status} for c in crashes]
    return Result(command="crash list",
                  data={"crashes": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{c['id']:20} {c['classification']:20} x{c['count']:<3} "
                      f"{c['target']}" for c in d["crashes"]) or "(none)")


def cmd_show(ctx, args) -> Result:
    from ..crashes import CrashStore
    crash = CrashStore(ctx.workspace()).get(args.crash_id)
    return Result(command="crash show", data={"crash": crash.to_dict()})


def cmd_reproduce(ctx, args) -> Result:
    from ..triage import Triage
    triage = Triage(ctx.workspace())
    crash = triage.crashes.get(args.crash_id)
    outcome = triage.reproduce(crash)
    return Result(command="crash reproduce", ok=outcome["reproduced"],
                  data=outcome,
                  messages=["reproduced" if outcome["reproduced"]
                            else "did not reproduce"])


def cmd_minimize(ctx, args) -> Result:
    from ..triage import Triage
    triage = Triage(ctx.workspace())
    crash = triage.crashes.get(args.crash_id)
    result = triage.minimize(
        crash, max_executions=getattr(args, "max_executions", None))
    msg = (f"minimized {result['original_size']} -> {result['minimized_size']} bytes"
           if result["minimized"] else f"not minimized: {result.get('reason')}")
    return Result(command="crash minimize", ok=result["minimized"],
                  data=result, messages=[msg])


def cmd_classify(ctx, args) -> Result:
    from ..triage import Triage
    triage = Triage(ctx.workspace())
    crash = triage.crashes.get(args.crash_id)
    return Result(command="crash classify", data=triage.classify(crash))


def cmd_compare(ctx, args) -> Result:
    from ..triage import Triage
    triage = Triage(ctx.workspace())
    a = triage.crashes.get(args.crash_id_a)
    b = triage.crashes.get(args.crash_id_b)
    return Result(command="crash compare", data=triage.compare(a, b))
