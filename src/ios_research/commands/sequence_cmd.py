"""`ios-research sequence` — stateful workflow fuzzing (#39)."""

from __future__ import annotations

from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("sequence", parents=[parent],
                              help="fuzz authorized app/API action sequences")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_fuzz = sub.add_parser("fuzz", parents=[parent],
                            help="run a bounded sequence-fuzzing campaign")
    p_fuzz.add_argument("--adapter", required=True,
                        help="path to a user-declared workflow adapter module")
    p_fuzz.add_argument("--cases", type=int, default=100)
    p_fuzz.add_argument("--seed", type=int, default=0)
    p_fuzz.add_argument("--max-length", type=int, default=8,
                        dest="max_length")
    p_fuzz.set_defaults(func=cmd_fuzz)

    p.set_defaults(func=lambda ctx, args: Result(
        command="sequence", messages=["use 'sequence fuzz'"]))


def cmd_fuzz(ctx, args) -> Result:
    from ..stateful import StatefulFuzzer
    out = StatefulFuzzer(ctx.workspace()).fuzz(
        adapter_path=args.adapter, cases=args.cases, seed=args.seed,
        max_length=args.max_length)
    return Result(command="sequence fuzz",
                  data=out,
                  messages=[f"{out['unique_failures']} unique failure(s) "
                            f"over {out['executed']} sequences"])
