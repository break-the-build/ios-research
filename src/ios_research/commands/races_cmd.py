"""`ios-research races` — ThreadSanitizer race-record pipeline (#70)."""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("races", parents=[parent],
                              help="ThreadSanitizer race records "
                                   "(import, list, show)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_import = sub.add_parser("import", parents=[parent],
                              help="import a ThreadSanitizer report")
    p_import.add_argument("--report", required=True,
                          help="path to a saved TSan report text file")
    p_import.add_argument("--target", default="unknown",
                          help="target id the report came from")
    p_import.add_argument("--input-sha", default="", dest="input_sha",
                          help="sha256 of the triggering input, if known")
    p_import.set_defaults(func=cmd_import)

    p_list = sub.add_parser("list", parents=[parent], help="list race records")
    p_list.add_argument("--kind", default=None,
                        help="filter by race kind (e.g. 'data race')")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent], help="show a race record")
    p_show.add_argument("race_id")
    p_show.set_defaults(func=cmd_show)

    p.set_defaults(func=cmd_list)


def _summary(race) -> dict:
    return {"id": race.id, "target": race.target, "kind": race.kind,
            "signature": race.signature, "count": race.count,
            "status": race.status}


def cmd_import(ctx, args) -> Result:
    from ..races import RaceStore, import_report
    try:
        with open(args.report, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        raise NotFoundError(f"cannot read report file: {exc}") from exc
    result = import_report(RaceStore(ctx.workspace()), text,
                           target=args.target,
                           sample_input_sha256=args.input_sha)
    return Result(command="races import",
                  data={"report": args.report,
                        "target": args.target, **result},
                  messages=[f"{result['races']} race block(s): "
                            f"{result['recorded']} recorded, "
                            f"{result['duplicates']} duplicate(s)"])


def cmd_list(ctx, args) -> Result:
    from ..races import RaceStore
    items = RaceStore(ctx.workspace()).list(kind=getattr(args, "kind", None))
    data = {"races": [_summary(r) for r in items], "count": len(items)}
    return Result(command="races list", data=data,
                  human=lambda d: "\n".join(
                      f"{r['id']:20} {r['kind']:24} x{r['count']} "
                      f"[{r['status']}]" for r in d["races"]) or "(none)")


def cmd_show(ctx, args) -> Result:
    from ..races import RaceStore
    race = RaceStore(ctx.workspace()).get(args.race_id)
    return Result(command="races show", data=race.to_dict())
