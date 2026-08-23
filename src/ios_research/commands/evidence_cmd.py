"""`ios-research evidence` — import researcher-recorded artifacts (#38)."""

from __future__ import annotations

from ..errors import ValidationError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("evidence", parents=[parent],
                              help="import and inspect researcher-recorded "
                                   "evidence (sysdiagnose refs, videos, logs)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_import = sub.add_parser("import", parents=[parent],
                              help="copy one local artifact into the workspace")
    p_import.add_argument("crash_id")
    p_import.add_argument("path")
    p_import.add_argument("--kind", required=True,
                          help="crash-log | sysdiagnose | video | screenshot |"
                               " syslog | other")
    p_import.add_argument("--device-id", default="")
    p_import.add_argument("--build", default="")
    p_import.add_argument("--process", default="")
    p_import.add_argument("--captured-at", default="",
                          help="researcher-supplied ISO-8601 capture time")
    p_import.add_argument("--redaction-ack", action="store_true",
                          dest="redaction_ack",
                          help="confirm review/redaction responsibility for "
                               "video/screenshot artifacts")
    p_import.add_argument("--notes", default="")
    p_import.set_defaults(func=cmd_import)

    p_list = sub.add_parser("list", parents=[parent],
                            help="list evidence linked to a crash")
    p_list.add_argument("crash_id")
    p_list.set_defaults(func=cmd_list)

    p_verify = sub.add_parser("verify", parents=[parent],
                              help="re-hash an artifact against its record")
    p_verify.add_argument("item_id")
    p_verify.set_defaults(func=cmd_verify)

    p.set_defaults(func=cmd_list)


def cmd_import(ctx, args) -> Result:
    from ..evidence import EvidenceStore
    item = EvidenceStore(ctx.workspace()).import_file(
        args.crash_id, args.path, args.kind,
        device_id=args.device_id, build=args.build, process=args.process,
        captured_at=args.captured_at, redaction_ack=args.redaction_ack,
        notes=args.notes)
    return Result(command="evidence import",
                  data={"item": item},
                  messages=[f"imported {item['kind']} {item['id']} "
                            f"(sha256 {item['sha256'][:12]}…)"])


def cmd_list(ctx, args) -> Result:
    from ..evidence import EvidenceStore
    items = EvidenceStore(ctx.workspace()).list(args.crash_id)
    return Result(command="evidence list",
                  data={"items": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{i['id']} {i['kind']} {i['sha256'][:12]}…"
                      for i in d["items"]) or "(none)")


def cmd_verify(ctx, args) -> Result:
    from ..evidence import EvidenceStore
    ok = EvidenceStore(ctx.workspace()).verify_integrity(args.item_id)
    if not ok:
        raise ValidationError(
            f"integrity check failed for '{args.item_id}'")
    return Result(command="evidence verify",
                  data={"item_id": args.item_id, "integrity_ok": True},
                  messages=["integrity verified"])
