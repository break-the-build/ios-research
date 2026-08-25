"""`ios-research benchmark` — bounded local performance baselines."""

from __future__ import annotations

from ..errors import UsageError
from ..output import Result


def register(subparsers, parent) -> None:
    parser = subparsers.add_parser(
        "benchmark", parents=[parent],
        help="run bounded, reproducible local performance measurements")
    sub = parser.add_subparsers(dest="subcommand", metavar="<action>")
    profile = sub.add_parser(
        "profile", parents=[parent],
        help="profile a deterministic mock-target fuzz campaign")
    profile.add_argument("--target", default="mock:parser",
                         help="mock target to profile (default: mock:parser)")
    profile.add_argument("--max-cases", type=int, default=1000,
                         help="bounded fuzz cases (default: 1000)")
    profile.add_argument("--seed", type=int, default=0,
                         help="deterministic mutation seed (default: 0)")
    profile.set_defaults(func=cmd_profile)
    parser.set_defaults(func=cmd_profile)


def cmd_profile(ctx, args) -> Result:
    if not args.target.startswith("mock:"):
        raise UsageError("benchmark profile accepts mock targets only")
    if args.max_cases <= 0:
        raise UsageError("--max-cases must be positive")
    from ..profiling import profile_campaign
    data = profile_campaign(target_id=args.target, max_cases=args.max_cases,
                            seed=args.seed)
    return Result(command="benchmark profile", data=data,
                  messages=[f"profiled {data['executed_cases']} cases in "
                            f"{data['wall_seconds']:.3f}s"])
