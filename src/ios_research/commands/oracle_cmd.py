"""`ios-research oracle` — metamorphic/property oracles for non-crash findings."""

from __future__ import annotations

from ..errors import NotFoundError, ValidationError, UsageError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("oracle", parents=[parent],
                              help="metamorphic oracles for non-crash "
                                   "invariant violations (#42)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_run = sub.add_parser("run", parents=[parent],
                           help="evaluate relations over transformed inputs")
    p_run.add_argument("--target", required=True)
    p_run.add_argument("--corpus", default=None,
                       help="corpus id (default: target's seed inputs)")
    p_run.add_argument("--relations", nargs="*", dest="relations",
                       help="relation IDs to evaluate")
    p_run.add_argument("--transforms", nargs="*", dest="transforms",
                       help="transform IDs to apply")
    p_run.add_argument("--trials", type=int, default=2,
                       help="re-checks before a violation is confirmed")
    p_run.set_defaults(func=cmd_run)

    p_show = sub.add_parser("show", parents=[parent], help="show an oracle run")
    p_show.add_argument("run_id")
    p_show.set_defaults(func=cmd_show)

    p_list = sub.add_parser("list", parents=[parent], help="list oracle runs")
    p_list.set_defaults(func=cmd_list)

    p_rel = sub.add_parser("relations", parents=[parent],
                           help="list built-in relations and transforms")
    p_rel.set_defaults(func=cmd_relations)

    p.set_defaults(func=cmd_list)


def cmd_run(ctx, args) -> Result:
    from ..corpus import CorpusStore
    from ..oracles import OracleEngine, RELATIONS, TRANSFORMS
    from .. import targets as target_registry
    ws = ctx.workspace()
    engine = OracleEngine(ws)
    if args.corpus:
        store = CorpusStore(ws)
        corpus = store.get(args.corpus)
        inputs = [store.read_bytes(corpus, tc["sha256"])
                  for tc in corpus.testcases]
    else:
        seeds = target_registry.create(args.target).seeds()
        if not seeds:
            raise UsageError(
                "no inputs available; pass --corpus or use a target with seeds")
        inputs = list(seeds)
    summary = engine.run(
        target_id=args.target, inputs=inputs[:64],
        relations=args.relations, transforms=args.transforms,
        trials=max(2, args.trials))
    return Result(command="oracle run",
                  data=summary,
                  messages=[f"{summary['violations_confirmed']} confirmed / "
                            f"{summary['nondeterministic']} nondeterministic "
                            f"of {summary['pairs_evaluated']} pairs"])


def cmd_show(ctx, args) -> Result:
    from ..oracles import OracleEngine
    record = OracleEngine(ctx.workspace()).get(args.run_id)
    return Result(command="oracle show",
                  data={"run": record.to_dict()})


def cmd_list(ctx, args) -> Result:
    from ..oracles import OracleEngine
    runs = OracleEngine(ctx.workspace()).list()
    items = [{"id": r.id, "target": r.target, "status": r.status}
             for r in runs]
    return Result(command="oracle list", data={"runs": items,
                                               "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{r['id']} {r['target']} {r['status']}"
                      for r in d["runs"]) or "(none)")


def cmd_relations(ctx, args) -> Result:
    from ..oracles import RELATIONS, SEVERITY_RATIONALE, TRANSFORMS
    return Result(command="oracle relations",
                  data={
                      "relations": sorted(RELATIONS),
                      "transforms": sorted(TRANSFORMS),
                      "severity_rationale": SEVERITY_RATIONALE,
                  })
