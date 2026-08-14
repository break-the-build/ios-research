"""`ios-research corpus` — create/import/list/inspect/dedupe/minimize."""

from __future__ import annotations

from pathlib import Path

from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("corpus", parents=[parent],
                              help="manage testcase corpora")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_create = sub.add_parser("create", parents=[parent], help="create a corpus")
    p_create.add_argument("name")
    p_create.add_argument("--target", default=None)
    p_create.add_argument("--seed-default", action="store_true",
                          help="add a single valid base testcase")
    p_create.set_defaults(func=cmd_create)

    p_import = sub.add_parser("import", parents=[parent],
                              help="import files into a corpus")
    p_import.add_argument("corpus_id")
    p_import.add_argument("path")
    p_import.set_defaults(func=cmd_import)

    p_list = sub.add_parser("list", parents=[parent], help="list corpora")
    p_list.set_defaults(func=cmd_list)

    p_inspect = sub.add_parser("inspect", parents=[parent],
                               help="inspect a corpus")
    p_inspect.add_argument("corpus_id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_dedupe = sub.add_parser("dedupe", parents=[parent],
                              help="remove duplicate testcases")
    p_dedupe.add_argument("corpus_id")
    p_dedupe.set_defaults(func=cmd_dedupe)

    p_min = sub.add_parser("minimize", parents=[parent],
                           help="distill to one testcase per behavior")
    p_min.add_argument("corpus_id")
    p_min.add_argument("--target", default=None)
    p_min.set_defaults(func=cmd_minimize)

    p.set_defaults(func=cmd_list)


def cmd_create(ctx, args) -> Result:
    from ..corpus import CorpusStore
    from ..fuzz import DEFAULT_BASE
    store = CorpusStore(ctx.workspace())
    corpus = store.create(args.name, target=args.target)
    if args.seed_default:
        store.add_bytes(corpus, DEFAULT_BASE, origin="seed")
    return Result(command="corpus create",
                  data={"corpus": store.get(corpus.id).to_dict()},
                  messages=[f"created corpus {corpus.id}"])


def cmd_import(ctx, args) -> Result:
    from ..corpus import CorpusStore
    store = CorpusStore(ctx.workspace())
    corpus = store.get(args.corpus_id)
    added = store.import_path(corpus, Path(args.path))
    return Result(command="corpus import",
                  data={"corpus_id": corpus.id, "added": added,
                        "size": len(store.get(corpus.id).testcases)},
                  messages=[f"imported {added} testcase(s)"])


def cmd_list(ctx, args) -> Result:
    from ..corpus import CorpusStore
    store = CorpusStore(ctx.workspace())
    items = [{"id": c.id, "name": c.name, "size": len(c.testcases),
              "target": c.target} for c in store.list()]
    return Result(command="corpus list",
                  data={"corpora": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{c['id']:20} {c['name']:16} {c['size']} tc"
                      for c in d["corpora"]) or "(none)")


def cmd_inspect(ctx, args) -> Result:
    from ..corpus import CorpusStore
    store = CorpusStore(ctx.workspace())
    corpus = store.get(args.corpus_id)
    origins: dict[str, int] = {}
    for tc in corpus.testcases:
        origins[tc["origin"]] = origins.get(tc["origin"], 0) + 1
    return Result(command="corpus inspect",
                  data={"corpus": corpus.to_dict(), "size": len(corpus.testcases),
                        "origins": origins})


def cmd_dedupe(ctx, args) -> Result:
    from ..corpus import CorpusStore
    store = CorpusStore(ctx.workspace())
    corpus = store.get(args.corpus_id)
    removed = store.dedupe(corpus)
    return Result(command="corpus dedupe",
                  data={"corpus_id": corpus.id, "removed": removed,
                        "size": len(corpus.testcases)},
                  messages=[f"removed {removed} duplicate(s)"])


def cmd_minimize(ctx, args) -> Result:
    from .. import targets
    from ..corpus import CorpusStore
    store = CorpusStore(ctx.workspace())
    corpus = store.get(args.corpus_id)
    target_id = args.target or corpus.target or ctx.config().get("default_target")
    target = targets.create(target_id)
    stats = store.minimize(corpus, target)
    return Result(command="corpus minimize",
                  data={"corpus_id": corpus.id, "target": target_id, **stats},
                  messages=[f"kept {stats['kept']}, removed {stats['removed']}"])
