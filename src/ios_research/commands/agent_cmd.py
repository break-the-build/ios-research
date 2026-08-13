"""`ios-research agent` — machine-first operations for LLM agents."""

from __future__ import annotations

import json
from pathlib import Path

from ..agent import Agent
from ..errors import UsageError
from ..output import Result
from ..schema import build_cli_schema
from .. import targets


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("agent", parents=[parent],
                              help="LLM-agent operations")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_status = sub.add_parser("status", parents=[parent],
                              help="report agent-readable status")
    p_status.set_defaults(func=cmd_status)

    p_inspect = sub.add_parser("inspect", parents=[parent],
                               help="emit the machine-readable CLI schema")
    p_inspect.set_defaults(func=cmd_inspect)

    p_schema = sub.add_parser("schema", parents=[parent],
                              help="write docs/cli-schema.json")
    p_schema.add_argument("--out", default="docs/cli-schema.json")
    p_schema.set_defaults(func=cmd_schema)

    p_run = sub.add_parser("run", parents=[parent],
                           help="run a bounded end-to-end pipeline")
    p_run.add_argument("--target", default=None)
    p_run.add_argument("--seed", type=int, default=0)
    p_run.add_argument("--max-cases", type=int, default=200)
    p_run.add_argument("--no-minimize", action="store_true")
    p_run.set_defaults(func=cmd_run)

    p_exp = sub.add_parser("experiment", parents=[parent],
                           help="create an experiment (machine-readable)")
    p_exp.add_argument("--target", default=None)
    p_exp.add_argument("--seed", type=int, default=0)
    p_exp.set_defaults(func=cmd_experiment)

    p_an = sub.add_parser("analyze", parents=[parent],
                          help="analyze all crashes (machine-readable)")
    p_an.set_defaults(func=cmd_analyze)

    p.set_defaults(func=cmd_status)


def cmd_status(ctx, args) -> Result:
    return Result(command="agent status", data=Agent(ctx).status())


def cmd_inspect(ctx, args) -> Result:
    return Result(command="agent inspect", data=Agent(ctx).inspect())


def cmd_schema(ctx, args) -> Result:
    schema = build_cli_schema()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    return Result(command="agent schema", data={"path": str(out),
                                                 "commands": len(schema["commands"])},
                  messages=[f"wrote schema to {out}"])


def _resolve_target(ctx, target):
    target = target or ctx.config().get("default_target")
    if not targets.is_registered(target):
        raise UsageError(f"unknown target '{target}'")
    return target


def cmd_run(ctx, args) -> Result:
    target = _resolve_target(ctx, args.target)
    data = Agent(ctx).run(target=target, seed=args.seed,
                          max_cases=args.max_cases, minimize=not args.no_minimize)
    return Result(command="agent run", data=data,
                  messages=[f"experiment {data['experiment_id']}: "
                            f"{data['unique_crashes']} unique crashes"])


def cmd_experiment(ctx, args) -> Result:
    target = _resolve_target(ctx, args.target)
    return Result(command="agent experiment",
                  data=Agent(ctx).experiment(target=target, seed=args.seed))


def cmd_analyze(ctx, args) -> Result:
    return Result(command="agent analyze", data=Agent(ctx).analyze())
