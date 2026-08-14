"""`ios-research diff` — create/run/compare/report differential experiments."""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("diff", parents=[parent],
                              help="differential testing across targets/versions")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_create = sub.add_parser("create", parents=[parent],
                              help="create a differential experiment")
    p_create.add_argument("--name", default="diff")
    p_create.add_argument("--target-a", required=True)
    p_create.add_argument("--target-b", required=True)
    p_create.add_argument("--corpus", default=None)
    p_create.add_argument("--seed", type=int, default=0)
    p_create.set_defaults(func=cmd_create)

    p_run = sub.add_parser("run", parents=[parent], help="run a diff experiment")
    p_run.add_argument("diff_id", nargs="?", default=None)
    p_run.set_defaults(func=cmd_run)

    p_cmp = sub.add_parser("compare", parents=[parent],
                           help="show per-testcase differences")
    p_cmp.add_argument("diff_id", nargs="?", default=None)
    p_cmp.set_defaults(func=cmd_compare)

    p_rep = sub.add_parser("report", parents=[parent],
                           help="summarize differential findings")
    p_rep.add_argument("diff_id", nargs="?", default=None)
    p_rep.set_defaults(func=cmd_report)

    p_list = sub.add_parser("list", parents=[parent], help="list diff experiments")
    p_list.set_defaults(func=cmd_list)

    p.set_defaults(func=cmd_list)


def _resolve(engine, diff_id):
    if diff_id:
        return engine.get(diff_id)
    items = engine.list()
    if not items:
        raise NotFoundError("no diff experiments found")
    return sorted(items, key=lambda d: d.created_at)[-1]


def cmd_create(ctx, args) -> Result:
    from ..differential import DifferentialEngine
    engine = DifferentialEngine(ctx.workspace())
    diff = engine.create(name=args.name, target_a=args.target_a,
                         target_b=args.target_b, config_hash=ctx.config().hash,
                         seed=args.seed, corpus_id=args.corpus)
    return Result(command="diff create", data={"diff": diff.to_dict()},
                  messages=[f"created diff {diff.id}"])


def cmd_run(ctx, args) -> Result:
    from ..differential import DifferentialEngine
    engine = DifferentialEngine(ctx.workspace())
    diff = _resolve(engine, args.diff_id)
    summary = engine.run(diff)
    return Result(command="diff run",
                  data={"diff_id": diff.id, "summary": summary},
                  messages=[f"{summary['differing']} differing, "
                            f"{summary['regressions']} regression(s)"])


def cmd_compare(ctx, args) -> Result:
    from ..differential import DifferentialEngine
    engine = DifferentialEngine(ctx.workspace())
    diff = _resolve(engine, args.diff_id)
    return Result(command="diff compare", data=engine.compare(diff))


def cmd_report(ctx, args) -> Result:
    from ..differential import DifferentialEngine
    engine = DifferentialEngine(ctx.workspace())
    diff = _resolve(engine, args.diff_id)
    return Result(command="diff report", data=engine.report(diff))


def cmd_list(ctx, args) -> Result:
    from ..differential import DifferentialEngine
    engine = DifferentialEngine(ctx.workspace())
    items = [{"id": d.id, "name": d.name, "a": d.target_a, "b": d.target_b,
              "status": d.status} for d in engine.list()]
    return Result(command="diff list", data={"diffs": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{x['id']:20} {x['a']} vs {x['b']} [{x['status']}]"
                      for x in d["diffs"]) or "(none)")
