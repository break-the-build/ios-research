"""`ios-research research` — orchestrate end-to-end research runs."""

from __future__ import annotations

from ..errors import InterruptedError_, NotFoundError, UsageError
from ..output import Result
from ..research import ResearchOrchestrator
from .. import targets


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("research", parents=[parent],
                              help="end-to-end research orchestration")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_create = sub.add_parser("create", parents=[parent],
                              help="create a research run")
    p_create.add_argument("--name", default="research")
    p_create.add_argument("--target", default=None)
    p_create.add_argument("--seed", type=int, default=0)
    p_create.add_argument("--max-cases", type=int, default=300)
    p_create.add_argument("--max-runtime", type=int, default=None)
    p_create.add_argument("--max-testcases", type=int, default=None)
    p_create.set_defaults(func=cmd_create)

    p_run = sub.add_parser("run", parents=[parent],
                           help="run a research pipeline (destructive; needs --yes)")
    p_run.add_argument("research_id", nargs="?", default=None)
    p_run.add_argument("--max-stages", type=int, default=None,
                       help="run only N stages (resumable)")
    p_run.set_defaults(func=cmd_run)

    for action in ("status", "resume", "pause", "summarize"):
        pa = sub.add_parser(action, parents=[parent],
                            help=f"{action} a research run")
        pa.add_argument("research_id", nargs="?", default=None)
        if action == "resume":
            pa.add_argument("--max-stages", type=int, default=None)
        pa.set_defaults(func=globals()[f"cmd_{action}"])

    p.set_defaults(func=cmd_status)


def _resolve(orch, research_id):
    if research_id:
        return orch.get(research_id)
    run = orch.latest()
    if run is None:
        raise NotFoundError("no research runs found")
    return run


def cmd_create(ctx, args) -> Result:
    orch = ResearchOrchestrator(ctx.workspace())
    target = args.target or ctx.config().get("default_target")
    if not targets.is_registered(target):
        raise UsageError(f"unknown target '{target}'")
    limits = {}
    if args.max_runtime is not None:
        limits["max_runtime_seconds"] = args.max_runtime
    if args.max_testcases is not None:
        limits["max_testcases"] = args.max_testcases
    run = orch.create(name=args.name, target=target, seed=args.seed,
                      max_cases=args.max_cases, limits=limits)
    return Result(command="research create", data={"research": run.to_dict()},
                  messages=[f"created research run {run.id}"])


def cmd_run(ctx, args) -> Result:
    # Destructive/resource-consuming: require explicit confirmation.
    if not ctx.confirm("run full research pipeline"):
        raise InterruptedError_(
            "research run requires confirmation; re-run with --yes")
    orch = ResearchOrchestrator(ctx.workspace())
    run = _resolve(orch, args.research_id)
    run = orch.run(run, max_stages=args.max_stages)
    return Result(command="research run",
                  data={"research_id": run.id, "status": run.status,
                        "cursor": run.cursor, "stats": run.stats},
                  messages=[f"run {run.id}: {run.status} "
                            f"(stage {run.cursor}/{len(run.stages)})"])


def cmd_resume(ctx, args) -> Result:
    if not ctx.confirm("resume research pipeline"):
        raise InterruptedError_(
            "research resume requires confirmation; re-run with --yes")
    orch = ResearchOrchestrator(ctx.workspace())
    run = orch.run(_resolve(orch, args.research_id),
                   max_stages=getattr(args, "max_stages", None), resume=True)
    return Result(command="research resume",
                  data={"research_id": run.id, "status": run.status,
                        "cursor": run.cursor},
                  messages=[f"run {run.id}: {run.status}"])


def cmd_pause(ctx, args) -> Result:
    orch = ResearchOrchestrator(ctx.workspace())
    run = orch.pause(_resolve(orch, args.research_id))
    return Result(command="research pause",
                  data={"research_id": run.id, "status": run.status})


def cmd_status(ctx, args) -> Result:
    orch = ResearchOrchestrator(ctx.workspace())
    if getattr(args, "research_id", None) is None and not orch.list():
        return Result(command="research status",
                      data={"runs": [], "count": 0}, messages=["(none)"])
    run = _resolve(orch, getattr(args, "research_id", None))
    return Result(command="research status",
                  data={"research_id": run.id, "status": run.status,
                        "cursor": run.cursor,
                        "stages": run.stages, "stats": run.stats})


def cmd_summarize(ctx, args) -> Result:
    orch = ResearchOrchestrator(ctx.workspace())
    run = _resolve(orch, args.research_id)
    return Result(command="research summarize",
                  data={"summary": orch.summarize(run)})
