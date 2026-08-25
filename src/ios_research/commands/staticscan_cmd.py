"""`ios-research staticscan` — static-analysis scout (#223)."""

from __future__ import annotations

import json
from pathlib import Path

from ..errors import ExitCode
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("staticscan", parents=[parent],
                              help="static-analysis scout: surface census, "
                                   "parser fingerprinting, call-graph export")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_locate = sub.add_parser("locate", parents=[parent],
                              help="locate a framework binary (loose or "
                                   "dyld shared cache)")
    p_locate.add_argument("framework", help="bare framework name, e.g. "
                                            "AudioToolbox")
    p_locate.set_defaults(func=cmd_locate)

    p_scan = sub.add_parser("scan", parents=[parent],
                            help="census a Mach-O or dyld shared cache: "
                                 "symbols, libraries, constant strings")
    p_scan.add_argument("path")
    p_scan.add_argument("--min-len", type=int, default=4,
                        help="minimum string length (default 4)")
    p_scan.set_defaults(func=cmd_scan)

    p_fp = sub.add_parser("fingerprint", parents=[parent],
                          help="identify parser families by format constants")
    p_fp.add_argument("path")
    p_fp.set_defaults(func=cmd_fingerprint)

    p_dict = sub.add_parser("dict", parents=[parent],
                            help="emit an evidence-backed libFuzzer "
                                 "dictionary")
    p_dict.add_argument("path")
    p_dict.add_argument("--families", default=None,
                        help="comma-separated family filter (default: all "
                             "matched)")
    p_dict.add_argument("--out", default=None,
                        help="write dictionary to a file instead of stdout")
    p_dict.set_defaults(func=cmd_dict)

    p_ex = sub.add_parser("extract", parents=[parent],
                          help="extract a framework dylib from the dyld "
                               "shared cache (via ipsw) for Ghidra analysis")
    p_ex.add_argument("framework",
                      help="bare framework name, e.g. CoreText")
    p_ex.add_argument("--out", default=None,
                      help="output directory (default: <workspace>/artifacts"
                           "/dsc)")
    p_ex.set_defaults(func=cmd_extract)

    p_cg = sub.add_parser("callgraph", parents=[parent],
                          help="normalize a Ghidra export into the "
                               "directed-fuzzing call-graph document")
    p_cg.add_argument("export_json")
    p_cg.add_argument("--out", default=None)
    p_cg.add_argument("--focus", action="store_true",
                      help="list parser focus functions (functions that "
                           "reference format constants)")
    p_cg.set_defaults(func=cmd_callgraph)

    p_diff = sub.add_parser("diff", parents=[parent],
                            help="diff two binaries'/records' format-token "
                                 "fingerprints: new/removed tokens mark "
                                 "newly shipped parsers (#228 beta hunting)")
    p_diff.add_argument("old_path")
    p_diff.add_argument("new_path")
    p_diff.set_defaults(func=cmd_diff)

    p.set_defaults(func=cmd_default)


def cmd_default(ctx, args) -> Result:
    return Result(command="staticscan", ok=False,
                  exit_code=ExitCode.USAGE,
                  error="choose an action: locate | scan | fingerprint | "
                        "dict | callgraph | diff",
                  data={"actions": ["locate", "scan", "fingerprint", "dict",
                                    "callgraph", "diff"]})


def _scan(path: str, min_len: int = 4) -> dict:
    from .. import staticscan
    return staticscan.scan_binary(path, min_len=min_len)


def cmd_locate(ctx, args) -> Result:
    from .. import staticscan
    try:
        data = staticscan.locate_framework(args.framework)
    except Exception as exc:
        return Result(command="staticscan locate", ok=False,
                      exit_code=ExitCode.NOT_FOUND, error=str(exc),
                      data={"framework": args.framework})
    return Result(command="staticscan locate", data=data)


def cmd_scan(ctx, args) -> Result:
    try:
        binary = _scan(args.path, args.min_len)
    except Exception as exc:
        return Result(command="staticscan scan", ok=False,
                      exit_code=ExitCode.NOT_FOUND, error=str(exc),
                      data={"path": args.path})
    data = {"path": binary["path"],
            "is_dyld_shared_cache": binary["is_dyld_shared_cache"],
            "size_bytes": binary["size_bytes"],
            "string_count": len(binary["strings"]),
            "symbol_count": len(binary["symbols"]),
            "libraries": binary["libraries"]}
    return Result(command="staticscan scan", data=data)


def cmd_fingerprint(ctx, args) -> Result:
    from .. import staticscan
    try:
        binary = _scan(args.path)
    except Exception as exc:
        return Result(command="staticscan fingerprint", ok=False,
                      exit_code=ExitCode.NOT_FOUND, error=str(exc),
                      data={"path": args.path})
    matches = staticscan.fingerprint(binary["strings"])
    return Result(command="staticscan fingerprint",
                  data={"path": binary["path"],
                        "families": {f: len(m) for f, m in matches.items()},
                        "matches": matches})


def cmd_dict(ctx, args) -> Result:
    from .. import staticscan
    try:
        binary = _scan(args.path)
    except Exception as exc:
        return Result(command="staticscan dict", ok=False,
                      exit_code=ExitCode.NOT_FOUND, error=str(exc),
                      data={"path": args.path})
    matches = staticscan.fingerprint(binary["strings"])
    families = ({f.strip() for f in args.families.split(",")}
                if args.families else None)
    dictionary = staticscan.build_dictionary(matches, families)
    tokens = dictionary.count('"') // 2
    if not tokens:
        return Result(command="staticscan dict", ok=False,
                      exit_code=ExitCode.VALIDATION,
                      error="no format constants found; nothing to emit",
                      data={"path": binary["path"]})
    if args.out:
        Path(args.out).write_text(dictionary, encoding="utf-8")
        return Result(command="staticscan dict",
                      data={"out": args.out, "tokens": tokens})
    return Result(command="staticscan dict",
                  data={"dictionary": dictionary, "tokens": tokens})


def cmd_extract(ctx, args) -> Result:
    from .. import staticscan
    out_dir = args.out
    if out_dir is None:
        from pathlib import Path
        base = ctx.workspace_path or ".ios-research"
        out_dir = str(Path(base) / "artifacts" / "dsc")
    try:
        data = staticscan.extract_framework(args.framework, out_dir)
    except Exception as exc:
        return Result(command="staticscan extract", ok=False,
                      exit_code=ExitCode.NOT_FOUND, error=str(exc),
                      data={"framework": args.framework})
    return Result(command="staticscan extract", data=data)


def cmd_callgraph(ctx, args) -> Result:
    from .. import staticscan
    try:
        raw = json.loads(Path(args.export_json).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return Result(command="staticscan callgraph", ok=False,
                      exit_code=ExitCode.VALIDATION,
                      error=f"cannot read ghidra export: {exc}",
                      data={"path": args.export_json})
    try:
        normalized = staticscan.parse_ghidra_export(raw)
    except Exception as exc:
        return Result(command="staticscan callgraph", ok=False,
                      exit_code=ExitCode.VALIDATION, error=str(exc),
                      data={"path": args.export_json})
    doc = staticscan.to_callgraph_doc(normalized)
    data = {"nodes": len(doc["nodes"]), "edges": len(doc["edges"]),
            "document": doc}
    if args.focus:
        focus = staticscan.parser_focus_functions(normalized)
        data["focus_functions"] = focus
        data["focus_count"] = len(focus)
    if args.out:
        Path(args.out).write_text(json.dumps(doc, indent=1),
                                  encoding="utf-8")
        data["out"] = args.out
        del data["document"]
    return Result(command="staticscan callgraph", data=data)


def _fingerprint_doc(path: str) -> tuple[str, dict]:
    """Fingerprint a binary path, or load a saved fingerprint document.

    A ``.json`` path is treated as a previously saved document with a
    ``matches`` mapping ({family: [{token, hits}]}) so repeated diffs of a
    huge dyld shared cache don't re-pay the strings pass.
    """
    if path.endswith(".json"):
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        matches = raw.get("matches")
        if not isinstance(matches, dict):
            raise ValueError("saved fingerprint document needs a 'matches' "
                             "object: {family: [{token, hits}]}")
        return raw.get("path", path), matches
    from .. import staticscan
    binary = _scan(path)
    return binary["path"], staticscan.fingerprint(binary["strings"])


def cmd_diff(ctx, args) -> Result:
    from .. import staticscan
    try:
        old_path, old_matches = _fingerprint_doc(args.old_path)
        new_path, new_matches = _fingerprint_doc(args.new_path)
    except Exception as exc:
        return Result(command="staticscan diff", ok=False,
                      exit_code=ExitCode.VALIDATION,
                      error=f"cannot fingerprint inputs: {exc}",
                      data={"old": args.old_path, "new": args.new_path})
    diff = staticscan.diff_fingerprints(old_matches, new_matches)
    data = {"old_path": old_path, "new_path": new_path, **diff}
    if not diff["added_token_count"]:
        # No new parsers to aim at; still a valid (negative) result.
        return Result(command="staticscan diff",
                      error=None,
                      data={**data,
                            "note": "no new format tokens; no directed "
                                    "targets this window"})
    return Result(command="staticscan diff", data=data)
