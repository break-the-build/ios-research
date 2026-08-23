"""`ios-research detect` — lint and run defensive detection signatures."""

from __future__ import annotations

import json

from ..errors import NotFoundError, UsageError
from ..output import Result


def _load_rules(rules_path: str | None):
    from ..detection import builtin_rules_path, load_rules
    return load_rules(rules_path or builtin_rules_path())


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("detect", parents=[parent],
                              help="defensive detection signatures")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_lint = sub.add_parser("lint", parents=[parent],
                            help="validate a signature rules file")
    p_lint.add_argument("--rules", default=None,
                        help="rules JSON (default: built-in signatures)")
    p_lint.set_defaults(func=cmd_lint)

    p_scan = sub.add_parser("scan", parents=[parent],
                            help="scan a sample file with detection rules")
    p_scan.add_argument("path")
    p_scan.add_argument("--rules", default=None,
                        help="rules JSON (default: built-in signatures)")
    p_scan.set_defaults(func=cmd_scan)

    p_list = sub.add_parser("list-rules", parents=[parent],
                            help="list rules in a rules file")
    p_list.add_argument("--rules", default=None)
    p_list.set_defaults(func=cmd_list_rules)

    p.set_defaults(func=cmd_lint)


def cmd_lint(ctx, args) -> Result:
    from .. import detection
    from ..errors import ExitCode
    rules_path = getattr(args, "rules", None)
    if rules_path:
        with open(rules_path, "r", encoding="utf-8") as fh:
            try:
                doc = json.load(fh)
            except json.JSONDecodeError as exc:
                raise UsageError(
                    f"{rules_path}: invalid JSON "
                    f"({exc.msg} at line {exc.lineno})")
        source = rules_path
    else:
        source = detection.builtin_rules_path()
        doc = _builtin_doc(source)
    issues = detection.lint(doc, source=source)
    count = len(doc.get("rules") or []) if isinstance(doc, dict) else 0
    return Result(command="detect lint",
                  ok=not issues,
                  exit_code=ExitCode.OK if not issues else ExitCode.VALIDATION,
                  data={"source": source, "rules": count, "issues": issues},
                  messages=["rules valid" if not issues
                            else f"{len(issues)} issue(s) found"])


def _builtin_doc(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def cmd_scan(ctx, args) -> Result:
    from .. import detection as det
    import os
    if not os.path.isfile(args.path):
        raise NotFoundError(f"sample '{args.path}' not found")
    rules = _load_rules(getattr(args, "rules", None))
    result = det.scan_file(args.path, rules)
    matches = result["matches"]
    return Result(command="detect scan",
                  data=result,
                  messages=[
                      f"scanned {result['size']} bytes against "
                      f"{result['rules_evaluated']} rules: "
                      f"{len(matches)} match(es)"
                  ] + [f"  {m['severity']:8} {m['rule']} ({m['family']})"
                       for m in matches])


def cmd_list_rules(ctx, args) -> Result:
    rules = _load_rules(getattr(args, "rules", None))
    items = [{"name": r.name, "family": r.family, "severity": r.severity,
              "strings": len(r.strings),
              "description": r.description} for r in rules]
    return Result(command="detect list-rules",
                  data={"rules": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{r['name']:40} {r['severity']:8} {r['family']}"
                      for r in d["rules"]) or "(none)")
