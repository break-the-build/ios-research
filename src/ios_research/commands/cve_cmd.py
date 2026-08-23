"""`ios-research cve` — known-CVE patch-regression validation."""

from __future__ import annotations

import os

from ..errors import ExitCode, NotFoundError, UsageError
from ..output import Result


def _registry(ctx):
    from ..cvereg import CveRegistry
    return CveRegistry(ctx.workspace())


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("cve", parents=[parent],
                              help="known-CVE patch-regression validation")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_cat = sub.add_parser("catalog", parents=[parent],
                           help="show built-in mock-analog regression cases")
    p_cat.set_defaults(func=cmd_catalog)

    p_install = sub.add_parser("install-catalog", parents=[parent],
                               help="register built-in analogs in the workspace")
    p_install.set_defaults(func=cmd_install_catalog)

    p_add = sub.add_parser("add", parents=[parent],
                           help="add a published regression input (lab use)")
    p_add.add_argument("cve_id")
    p_add.add_argument("--title", required=True)
    p_add.add_argument("--input-hex", default=None,
                       help="hex-encoded input (mutually exclusive with "
                            "--input-file)")
    p_add.add_argument("--input-file", default=None,
                       help="read the input from this file instead")
    p_add.add_argument("--vulnerable", default="",
                       help="comma-separated targets that must crash")
    p_add.add_argument("--fixed", default="",
                       help="comma-separated targets that must stay clean")
    p_add.add_argument("--reference", default="")
    p_add.add_argument("--note", default="")
    p_add.set_defaults(func=cmd_add)

    p_list = sub.add_parser("list", parents=[parent],
                            help="list registered CVE regression entries")
    p_list.set_defaults(func=cmd_list)

    p_val = sub.add_parser("validate", parents=[parent],
                           help="re-run entries against vulnerable/fixed targets")
    p_val.add_argument("cve_id", nargs="?", default=None)
    p_val.set_defaults(func=cmd_validate)

    p_rm = sub.add_parser("remove", parents=[parent],
                          help="remove an entry from the registry")
    p_rm.add_argument("cve_id")
    p_rm.set_defaults(func=cmd_remove)

    p.set_defaults(func=cmd_list)


def _split_targets(raw: str) -> list[str]:
    items = [t.strip() for t in (raw or "").split(",") if t.strip()]
    return list(dict.fromkeys(items))


def cmd_catalog(ctx, args) -> Result:
    from ..cvereg import builtin_catalog
    catalog = builtin_catalog()
    items = [{"id": s["id"], "title": s["title"], "rationale": s["rationale"],
              "vulnerable_targets": s["vulnerable"],
              "fixed_targets": s["fixed"], "input_hex": s["input"].hex(),
              "input_size": len(s["input"])} for s in catalog]
    return Result(command="cve catalog",
                  data={"analogs": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{a['id']:24} {a['title']}" for a in d["analogs"]))


def cmd_install_catalog(ctx, args) -> Result:
    from ..cvereg import install_builtin_catalog
    added = install_builtin_catalog(_registry(ctx))
    return Result(command="cve install-catalog",
                  data={"added": added},
                  messages=[f"registered {len(added)} built-in analog(s)"])


def _resolve_input(args) -> bytes:
    from ..cvereg import decode_input_hex
    if getattr(args, "input_hex", None) and \
            getattr(args, "input_file", None):
        raise UsageError(
            "pass either --input-hex or --input-file, not both")
    if args.input_hex:
        return decode_input_hex(args.input_hex)
    if args.input_file:
        path = args.input_file
        if not os.path.isfile(path):
            raise NotFoundError(f"input file '{path}' not found")
        with open(path, "rb") as fh:
            data = fh.read()
        # Reuse the same bound check as hex inputs.
        return decode_input_hex(data.hex())
    raise UsageError("provide --input-hex or --input-file")


def cmd_add(ctx, args) -> Result:
    data = _resolve_input(args)
    entry = _registry(ctx).add(
        cve_id=args.cve_id, title=args.title, input_data=data,
        vulnerable_targets=_split_targets(args.vulnerable),
        fixed_targets=_split_targets(args.fixed),
        reference=args.reference, note=args.note)
    return Result(command="cve add",
                  data={"entry": entry.to_dict()},
                  messages=[f"registered {entry.id} "
                            f"({len(data)} byte input)"])


def cmd_list(ctx, args) -> Result:
    entries = _registry(ctx).entries()
    items = [{"id": e.id, "title": e.title,
              "vulnerable_targets": e.vulnerable_targets,
              "fixed_targets": e.fixed_targets,
              "sha256": e.sha256, "last_result": e.last_result}
             for e in entries]
    return Result(command="cve list",
                  data={"entries": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{e['id']:26} vuln={','.join(e['vulnerable_targets'])} "
                      f"fixed={','.join(e['fixed_targets'])} "
                      f"[{e['last_result'] or '-'}]"
                      for e in d["entries"]) or "(none)")


def cmd_validate(ctx, args) -> Result:
    from ..cvereg import validate_entry
    registry = _registry(ctx)
    if getattr(args, "cve_id", None):
        targets_entries = [registry.get(args.cve_id)]
    else:
        targets_entries = registry.entries()
        if not targets_entries:
            raise NotFoundError("no CVE regression entries registered; "
                                "run 'cve install-catalog' first")
    reports = []
    for entry in targets_entries:
        report = validate_entry(entry)
        registry.update_status(
            entry.id, "pass" if report["passed"] else "fail")
        reports.append(report)
    all_passed = all(r["passed"] for r in reports)
    failed = [r["id"] for r in reports if not r["passed"]]
    return Result(command="cve validate",
                  ok=all_passed,
                  exit_code=ExitCode.OK if all_passed else ExitCode.ERROR,
                  data={"reports": reports, "passed": all_passed},
                  messages=[f"{len(reports)} entr(y/ies) validated"
                            + ("" if all_passed
                               else f"; failing: {', '.join(failed)}")])


def cmd_remove(ctx, args) -> Result:
    _registry(ctx).remove(args.cve_id)
    return Result(command="cve remove",
                  data={"removed": args.cve_id},
                  messages=[f"removed {args.cve_id}"])
