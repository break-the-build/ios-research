"""`ios-research oracle` — declarative metamorphic/property oracles (#42).

Oracles are local, behavioral checks over authorized targets. They never make
exploitability claims; timeouts and nondeterministic observations stay
explicitly inconclusive.
"""

from __future__ import annotations

import json

from ..errors import ValidationError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("oracle", parents=[parent],
                              help="metamorphic and property-based oracles "
                                   "for non-crash findings")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_run = sub.add_parser("run", parents=[parent],
                           help="evaluate an oracle spec (JSON file)")
    p_run.add_argument("spec", help="path to the oracle spec JSON")
    p_run.add_argument("--corpus", default=None,
                       help="corpus id providing the base inputs")
    p_run.set_defaults(func=cmd_run)

    p_show = sub.add_parser("show", parents=[parent],
                            help="show one oracle run")
    p_show.add_argument("run_id")
    p_show.set_defaults(func=cmd_show)

    p_list = sub.add_parser("list", parents=[parent],
                            help="list oracle runs")
    p_list.set_defaults(func=cmd_list)

    p.set_defaults(func=cmd_list)


def cmd_run(ctx, args) -> Result:
    from pathlib import Path

    from ..oracles import OracleEngine
    try:
        spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValidationError(f"cannot read oracle spec: {exc}") from exc
    except ValueError as exc:
        raise ValidationError(f"oracle spec is not valid JSON: {exc}") from exc
    run = OracleEngine(ctx.workspace()).run(spec, corpus_id=args.corpus)
    data = run.to_dict()
    return Result(command="oracle run", data=data,
                  messages=[f"{data['violation_count']} violation(s), "
                            f"{data['inconclusive']['timeouts']} timeout(s), "
                            f"{data['inconclusive']['nondeterministic']} "
                            "nondeterministic (inconclusive)"])


def cmd_show(ctx, args) -> Result:
    from ..oracles import OracleEngine
    return Result(command="oracle show",
                  data=OracleEngine(ctx.workspace()).get(args.run_id))


def cmd_list(ctx, args) -> Result:
    from ..oracles import OracleEngine
    runs = OracleEngine(ctx.workspace()).list_runs()
    if not runs:
        return Result(command="oracle list", data={"runs": []},
                      messages=["no oracle runs recorded"])
    return Result(command="oracle list",
                  data={"runs": runs, "count": len(runs)})
