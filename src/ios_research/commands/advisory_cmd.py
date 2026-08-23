"""`ios-research advisory` — public-advisory corpus and novelty scoring (#59)."""

from __future__ import annotations

from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("advisory", parents=[parent],
                              help="local advisory corpus + crash novelty "
                                   "scoring (no live fetching)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_import = sub.add_parser("import", parents=[parent],
                              help="import a researcher-supplied advisory JSON")
    p_import.add_argument("path", help="JSON file with an 'advisories' array")
    p_import.set_defaults(func=cmd_import)

    p_list = sub.add_parser("list", parents=[parent], help="list corpus")
    p_list.set_defaults(func=cmd_list)

    p_match = sub.add_parser("match", parents=[parent],
                             help="score one crash against the corpus")
    p_match.add_argument("crash_id")
    p_match.set_defaults(func=cmd_match)

    p_scan = sub.add_parser("scan", parents=[parent],
                            help="novelty-score all crashes (novel-first)")
    p_scan.add_argument("--experiment-id", default=None)
    p_scan.set_defaults(func=cmd_scan)

    p.set_defaults(func=cmd_list)


def cmd_import(ctx, args) -> Result:
    from ..advisories import AdvisoryStore
    result = AdvisoryStore(ctx.workspace()).import_file(args.path)
    return Result(command="advisory import", data=result,
                  messages=[f"imported {len(result['imported'])} "
                            f"advisory(ies) from {result['source']}"])


def cmd_list(ctx, args) -> Result:
    from ..advisories import AdvisoryStore
    items = [{"id": a.id, "components": a.components,
              "classifications": a.classifications, "fixed_in": a.fixed_in,
              "source": a.source} for a in AdvisoryStore(
                  ctx.workspace()).list()]
    return Result(command="advisory list",
                  data={"advisories": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{a['id']:24} fixed_in={a['fixed_in'] or '-':12} "
                      f"{','.join(a['components'])}"
                      for a in d["advisories"]) or "(none)")


def cmd_match(ctx, args) -> Result:
    from ..advisories import NoveltyIndex
    index = NoveltyIndex(ctx.workspace())
    crash = index.crashes.get(args.crash_id)
    scored = index.score(crash)
    return Result(command="advisory match", data=scored,
                  messages=[f"{crash.id}: novelty={scored['novelty']} "
                            f"({len(scored['candidates'])} candidate(s))"])


def cmd_scan(ctx, args) -> Result:
    from ..advisories import NoveltyIndex
    result = NoveltyIndex(ctx.workspace()).scan(
        experiment_id=args.experiment_id)
    counts = result["counts"]
    return Result(command="advisory scan", data=result,
                  messages=[f"{result['crashes_scored']} crash(es): "
                            f"novel={counts['novel']} "
                            f"known-unfixed={counts['known-unfixed']} "
                            f"known-fixed={counts['known-fixed']}"])
