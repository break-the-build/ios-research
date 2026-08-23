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

    # macOS reward-category verification oracles (#62): pure classifiers over
    # researcher-supplied evidence records; verdicts never assert a bypass.
    p_mac = sub.add_parser("mac", parents=[parent],
                           help="macOS reward-category verification oracles "
                                "(evidence classifiers)")
    mac_sub = p_mac.add_subparsers(dest="mac_subcommand", metavar="<action>")

    p_mac_run = mac_sub.add_parser("run", parents=[parent],
                                   help="classify one researcher-supplied "
                                        "evidence record")
    p_mac_run.add_argument("name", help="oracle name (see 'oracle mac oracles')")
    p_mac_run.add_argument("evidence", help="path to the evidence JSON record")
    p_mac_run.set_defaults(func=cmd_mac_run)

    p_mac_oracles = mac_sub.add_parser("oracles", parents=[parent],
                                       help="list available macOS oracles")
    p_mac_oracles.set_defaults(func=cmd_mac_oracles)

    p_mac.set_defaults(func=cmd_mac_oracles)

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


def cmd_mac_run(ctx, args) -> Result:
    from ..macoracles import MacOracleEngine
    record = MacOracleEngine(ctx.workspace()).run(
        name=args.name, evidence_path=args.evidence)
    return Result(command="oracle mac run", data=record,
                  messages=[f"classification: {record['classification']} "
                            "(observation only; not a bypass claim)"])


def cmd_mac_oracles(ctx, args) -> Result:
    from ..macoracles import MAC_ORACLES
    return Result(command="oracle mac oracles",
                  data={"oracles": sorted(MAC_ORACLES)})
