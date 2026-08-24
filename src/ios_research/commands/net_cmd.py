"""`ios-research net` — loopback network transport deliver/replay (#57)."""

from __future__ import annotations

import json
from pathlib import Path

from ..errors import ValidationError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("net", parents=[parent],
                              help="loopback TCP transport for network-"
                                   "delivered inputs (capture + replay)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_deliver = sub.add_parser("deliver", parents=[parent],
                               help="deliver one input over the transport")
    p_deliver.add_argument("--target", required=True,
                           help="transport target id (net:<inner-target>)")
    p_deliver.add_argument("--input", required=True)
    p_deliver.add_argument("--schedule", default="single",
                           choices=["single", "split2", "byte-by-byte",
                                    "fragmented-4"])
    p_deliver.set_defaults(func=cmd_deliver)

    p_replay = sub.add_parser("replay", parents=[parent],
                              help="replay a saved capture against a target")
    p_replay.add_argument("--target", required=True)
    p_replay.add_argument("--input", required=True)
    p_replay.add_argument("--schedule", default=None)
    p_replay.add_argument("--capture", required=True,
                          help="JSON file with a saved capture")
    p_replay.set_defaults(func=cmd_replay)

    p.set_defaults(func=lambda ctx, args: cmd_help(ctx, args))


def cmd_help(ctx, args) -> Result:  # pragma: no cover - trivial
    return Result(command="net",
                  data={"actions": ["deliver", "replay"]})


def _read_input(path: str) -> bytes:
    path_ = Path(path)
    if not path_.is_file():
        raise ValidationError(f"input file not found: {path}")
    return path_.read_bytes()


def _load_capture(path: str) -> dict:
    try:
        capture = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"cannot read capture: {exc}") from exc
    if not isinstance(capture, dict) or "schedule" not in capture:
        raise ValidationError("capture must be a JSON object with 'schedule'")
    return capture


def cmd_deliver(ctx, args) -> Result:
    from .. import targets as targets_mod
    from ..nettransport import capture_from_result
    if not targets_mod.is_registered(args.target):
        raise ValidationError(f"unknown target '{args.target}'")
    target = targets_mod.create(args.target)
    if getattr(target, "schedule", None) != args.schedule:
        # Rebuild with the requested schedule.
        from ..nettransport import LoopbackTcpTarget
        inner = targets_mod.create(args.target[len("net:"):])
        target = LoopbackTcpTarget(inner, schedule=args.schedule)

    data = _read_input(args.input)
    result = target.execute(data)
    capture = capture_from_result(result)
    return Result(command="net deliver",
                  ok=result.outcome not in ("crash", "abnormal"),
                  data={"outcome": result.outcome, "detail": result.detail,
                        "signature": result.diagnostics.signature
                        if result.diagnostics else None,
                        "capture": capture},
                  messages=[f"{args.target}: {result.outcome} "
                            f"(schedule={args.schedule})"])


def cmd_replay(ctx, args) -> Result:
    from .. import targets as targets_mod
    from ..nettransport import replay
    if not targets_mod.is_registered(args.target):
        raise ValidationError(f"unknown target '{args.target}'")
    target = targets_mod.create(args.target)
    if args.schedule and getattr(target, "schedule", None) != args.schedule:
        from ..nettransport import LoopbackTcpTarget
        inner = targets_mod.create(args.target[len("net:"):])
        target = LoopbackTcpTarget(inner, schedule=args.schedule)

    data = _read_input(args.input)
    capture = _load_capture(args.capture)
    verdict = replay(target, data, capture)
    return Result(command="net replay",
                  ok=verdict["chunks_match"],
                  data=verdict,
                  messages=[f"chunks_match={verdict['chunks_match']} "
                            f"outcome={verdict['outcome']}"])
