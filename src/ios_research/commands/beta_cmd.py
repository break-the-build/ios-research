"""`ios-research beta` — beta-release differential pipeline (#56)."""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("beta", parents=[parent],
                              help="diff two researcher-declared releases and "
                                   "prioritize novel surfaces (beta-bonus "
                                   "category)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_run = sub.add_parser("diff", parents=[parent],
                           help="diff release directories "
                                "(each with a release.json manifest)")
    p_run.add_argument("--release-a", required=True)
    p_run.add_argument("--release-b", required=True)
    p_run.set_defaults(func=cmd_diff)

    p_tag = sub.add_parser("tag", parents=[parent],
                           help="stamp beta provenance onto a corpus so "
                                "reports carry the release pair")
    p_tag.add_argument("diff_id")
    p_tag.add_argument("--corpus", required=True)
    p_tag.set_defaults(func=cmd_tag)

    p_show = sub.add_parser("show", parents=[parent], help="show a diff record")
    p_show.add_argument("diff_id")
    p_show.set_defaults(func=cmd_show)

    p_list = sub.add_parser("list", parents=[parent], help="list diff records")
    p_list.set_defaults(func=cmd_list)

    p.set_defaults(func=cmd_list)


def cmd_diff(ctx, args) -> Result:
    from ..betadiff import BetaDiffEngine
    engine = BetaDiffEngine(ctx.workspace())
    record = engine.run(release_a_path=args.release_a,
                        release_b_path=args.release_b)
    totals = record["totals"]
    return Result(command="beta diff",
                  data={"diff_id": record["id"],
                        "release_a": record["release_a"]["label"],
                        "release_b": record["release_b"]["label"],
                        "totals": totals,
                        "novel_surface_plan": record["novel_surface_plan"],
                        "dictionary_tokens": len(record["dictionary_tokens"])},
                  messages=[f"{record['id']}: {totals['added_symbols']} added "
                            f"symbols across {totals['changed_components']} "
                            f"changed / {totals['new_components']} new "
                            f"components"])


def cmd_tag(ctx, args) -> Result:
    from ..betadiff import BetaDiffEngine
    provenance = BetaDiffEngine(ctx.workspace()).tag_corpus(
        diff_id=args.diff_id, corpus_id=args.corpus)
    return Result(command="beta tag",
                  data={"corpus": args.corpus, "provenance": provenance},
                  messages=[f"corpus {args.corpus} tagged with beta "
                            f"release-pair provenance"])


def cmd_show(ctx, args) -> Result:
    from ..betadiff import BetaDiffEngine
    try:
        record = BetaDiffEngine(ctx.workspace()).get(args.diff_id)
    except Exception as exc:
        raise NotFoundError(f"beta diff '{args.diff_id}' not found") from exc
    rows = "\n".join(
        f"{entry['rank']:>3} {entry['component']:40} +{entry['added_symbols']}"
        for entry in record["novel_surface_plan"][:20])
    return Result(command="beta show",
                  data={"diff": {k: v for k, v in record.items()
                                 if k != "components"}},
                  human=lambda _d: rows or "(no novel surfaces)")


def cmd_list(ctx, args) -> Result:
    from ..betadiff import BetaDiffEngine
    items = [{"id": r["id"], "created_at": r["created_at"],
              "a": r["release_a"]["label"], "b": r["release_b"]["label"]}
             for r in BetaDiffEngine(ctx.workspace()).list()]
    return Result(command="beta list",
                  data={"records": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{r['id']} {r['a']} -> {r['b']}" for r in d["records"])
                  or "(none)")
