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
    native = sub.add_parser("native-profile", parents=[parent],
                            help="profile an explicitly authorized native macOS harness")
    native.add_argument("--target", required=True,
                        help="built mac:<framework> target to profile")
    native.add_argument("--max-cases", type=int, default=10,
                        help="bounded seed executions (default: 10)")
    native.add_argument("--acknowledge-authorized-use", action="store_true",
                        help="confirm authorization to execute the local native harness")
    native.set_defaults(func=cmd_native_profile)
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


def cmd_native_profile(ctx, args) -> Result:
    from ..profiling import profile_native_campaign
    try:
        data = profile_native_campaign(
            target_id=args.target, max_cases=args.max_cases,
            acknowledged=args.acknowledge_authorized_use)
    except ValueError as exc:
        raise UsageError(str(exc)) from None
    return Result(command="benchmark native-profile", data=data,
                  messages=[f"profiled {data['executed_cases']} authorized native cases"])
