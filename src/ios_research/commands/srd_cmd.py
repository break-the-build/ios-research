"""`ios-research srd` — opt-in Apple Security Research Device backend (#40).

Bookkeeping and provenance for approved SRD participants. Every subcommand
goes through the explicit approval gate; without configured approval data the
commands fail closed with a SAFETY error (exit 5).
"""

from __future__ import annotations

from ..errors import UsageError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("srd", parents=[parent],
                              help="opt-in Apple Security Research Device "
                                   "backend (approved participants only)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_status = sub.add_parser("status", parents=[parent],
                              help="show the approval gate, provenance, and "
                                   "session state")
    p_status.set_defaults(func=cmd_status)

    p_run = sub.add_parser("run", parents=[parent],
                           help="run one allowlisted local adapter command")
    p_run.add_argument("adapter")
    p_run.add_argument("--timeout", dest="timeout_s", type=float, default=None,
                       help="override the adapter timeout in seconds")
    p_run.add_argument("--note", default="",
                       help="free-text researcher note stored with the run")
    p_run.set_defaults(func=cmd_run)

    p_collect = sub.add_parser("collect", parents=[parent],
                               help="collect artifacts and finalize the "
                                    "session with channel-separated evidence")
    p_collect.set_defaults(func=cmd_collect)

    p.set_defaults(func=cmd_status)


def _backend(ctx):
    from ..srd import SRDDeviceBackend
    return SRDDeviceBackend(ctx.config(), ctx.workspace())


def cmd_status(ctx, args) -> Result:
    backend = _backend(ctx)
    sessions = [r for r in backend.ws.list_json("devices")
                if r.get("kind") == "srd-session"]
    latest = backend.session or {}
    channels = {"retail": 0, "srd": 0}
    for entry in latest.get("runs", []):
        channel = entry.get("channel", "retail")
        if channel in channels:
            channels[channel] += 1
    return Result(
        command="srd status",
        data={
            "configured": True,
            "gate": {
                "approved_user": backend.approval["approved_user"],
                "device_model": backend.approval["device_model"],
                "build": backend.approval["build"],
                "preview": backend.approval["preview"],
                "approval_reference":
                    backend.approval["approval_reference"],
            },
            "provenance": backend.provenance_summary(),
            "adapters": sorted(backend.adapters),
            "state": latest.get("state", "idle"),
            "latest_session_id": latest.get("id"),
            "sessions": len(sessions),
            "evidence_channels": channels,
        },
        messages=[f"SRD target '{backend.approval['device_model']}' "
                  f"approved for '{backend.approval['approved_user']}'; "
                  f"state={latest.get('state', 'idle')}"])


def cmd_run(ctx, args) -> Result:
    if getattr(args, "timeout_s", None) is not None and args.timeout_s <= 0:
        raise UsageError("--timeout must be a positive number of seconds")
    session = _backend(ctx).run(args.adapter, timeout_s=args.timeout_s,
                                notes=args.note)
    runs = session.get("runs", [])
    last = runs[-1] if runs else {}
    return Result(command="srd run",
                  data={"session": session},
                  messages=[f"adapter '{args.adapter}' ran "
                            f"({last.get('tag', '')})"])


def cmd_collect(ctx, args) -> Result:
    session = _backend(ctx).collect()
    counts = session.get("evidence_channels", {})
    return Result(command="srd collect",
                  data={"session": session},
                  messages=["collected: " + ", ".join(
                      f"{k}={v}" for k, v in sorted(counts.items()))])
