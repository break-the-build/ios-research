"""`ios-research supply` — offline dependency vetting (#72)."""

from __future__ import annotations

from pathlib import Path

from ..errors import ExitCode, NotFoundError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("supply", parents=[parent],
                              help="offline supply-chain vetting for "
                                   "research dependencies")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_audit = sub.add_parser("audit", parents=[parent],
                             help="audit a requirements file for pin/hash "
                                  "hygiene")
    p_audit.add_argument("--requirements", required=True,
                         help="path to requirements.txt-style text")
    p_audit.set_defaults(func=cmd_audit)

    p_scan = sub.add_parser("scan", parents=[parent],
                            help="static behavioral scan of a package tree")
    p_scan.add_argument("path", help="directory of *.py files to scan")
    p_scan.set_defaults(func=cmd_scan)

    p_verify = sub.add_parser("verify", parents=[parent],
                              help="verify a SHA-256 lockfile for drift")
    p_verify.add_argument("--lockfile", required=True,
                          help="path to the lockfile JSON")
    p_verify.add_argument("--root", default=".",
                          help="root directory lock paths resolve against")
    p_verify.set_defaults(func=cmd_verify)

    p_list = sub.add_parser("list", parents=[parent],
                            help="list past supply vetting records")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent],
                            help="show one supply record")
    p_show.add_argument("record_id")
    p_show.set_defaults(func=cmd_show)

    p.set_defaults(func=cmd_list)


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise NotFoundError(f"cannot read file: {exc}") from exc


def cmd_audit(ctx, args) -> Result:
    from ..supply import SupplyStore, audit_requirements
    text = _read(args.requirements)
    result = audit_requirements(text)
    rec = SupplyStore(ctx.workspace()).create("audit", args.requirements,
                                              result)
    return Result(command="supply audit",
                  data={"id": rec.id, "kind": rec.kind,
                        "target": rec.target, **result},
                  human=lambda d: (
                      f"{d['total']} entr(ies): {d['pinned']} pinned, "
                      f"{d['hashed']} hashed, risk={d['risk']}"
                      + (f"; unpinned: {', '.join(d['unpinned'])}"
                         if d['unpinned'] else "")))


def cmd_scan(ctx, args) -> Result:
    from ..supply import SupplyStore, scan_behavior
    root = Path(args.path)
    if not root.is_dir():
        raise NotFoundError(f"not a directory: {args.path}")
    result = scan_behavior(root)
    rec = SupplyStore(ctx.workspace()).create("scan", args.path, result)
    return Result(command="supply scan",
                  data={"id": rec.id, "kind": rec.kind,
                        "target": rec.target, **result},
                  human=lambda d: "\n".join(
                      [f"{d['files_scanned']} file(s) scanned "
                       f"(truncated={d['truncated']}, "
                       f"syntax_errors={d['syntax_errors']}), "
                       f"risk={d['risk']}"]
                      + [f"  {f.get('file')}:{f['line']} {f['kind']}"
                         f" {f.get('call', '')}" for f in d["findings"]]))


def cmd_verify(ctx, args) -> Result:
    from ..supply import SupplyStore, verify_lock
    root = Path(args.root)
    if not root.is_dir():
        raise NotFoundError(f"not a directory: {args.root}")
    result = verify_lock(args.lockfile, root)
    rec = SupplyStore(ctx.workspace()).create("verify", args.lockfile,
                                              result)
    verified = result["verified"]
    return Result(command="supply verify",
                  data={"id": rec.id, "kind": rec.kind,
                        "target": rec.target, **result},
                  exit_code=(ExitCode.STATE if not verified else ExitCode.OK),
                  messages=[] if verified else
                  ["lockfile drift detected; see drifted/missing"],
                  human=lambda d: "\n".join(
                      [f"{d['checked']} entr(ies) checked, "
                       f"verified={str(d['verified']).lower()}"]
                      + [f"  DRIFTED {x['path']} expected={x['expected']} "
                         f"actual={x['actual']}" for x in d["drifted"]]
                      + [f"  MISSING {m}" for m in d["missing"]]))


def cmd_list(ctx, args) -> Result:
    from ..supply import SupplyStore
    records = SupplyStore(ctx.workspace()).list()
    data = {"records": [{"id": r.id, "kind": r.kind, "target": r.target,
                         "created_at": r.created_at} for r in records],
            "count": len(records)}
    return Result(command="supply list", data=data,
                  human=lambda d: "\n".join(
                      f"{r['id']:20} {r['kind']:8} {r['target']}"
                      for r in d["records"]) or "(none)")


def cmd_show(ctx, args) -> Result:
    from ..supply import SupplyStore
    rec = SupplyStore(ctx.workspace()).get(args.record_id)
    return Result(command="supply show", data=rec.to_dict())
