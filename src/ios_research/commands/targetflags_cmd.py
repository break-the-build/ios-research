"""`ios-research targetflags` — inspect the local Target Flag taxonomy (#58)."""

from __future__ import annotations

from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("targetflags", parents=[parent],
                              help="Apple Target Flag taxonomy (local, "
                                   "public data; no Apple interaction)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_list = sub.add_parser("list", parents=[parent],
                            help="list the effective flag taxonomy")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent], help="show one flag")
    p_show.add_argument("flag_id")
    p_show.set_defaults(func=cmd_show)

    p.set_defaults(func=cmd_list)


def cmd_list(ctx, args) -> Result:
    from ..flagcapture import commpage_info
    from ..targetflags import load_taxonomy
    taxonomy = load_taxonomy(ctx.workspace(required=False))
    flags = [{"id": f["id"], "label": f["label"],
              "entry_point": f["entry_point"], "outcome": f["outcome"],
              "evidence_required": f["evidence_required"]}
             for f in taxonomy["flags"]]
    data = {"taxonomy_version": taxonomy["taxonomy_version"],
            "source": taxonomy["source"], "sha256": taxonomy["sha256"],
            "flags": flags, "count": len(flags),
            "commpage": commpage_info()}
    return Result(command="targetflags list", data=data,
                  human=lambda d: "\n".join(
                      f"{f['id']:34} {f['entry_point']} -> {f['outcome']}"
                      for f in d["flags"]) or "(none)")


def cmd_show(ctx, args) -> Result:
    from ..errors import NotFoundError
    from ..targetflags import get_flag, load_taxonomy
    taxonomy = load_taxonomy(ctx.workspace(required=False))
    flag = get_flag(taxonomy, args.flag_id)
    if flag is None:
        raise NotFoundError(f"target flag '{args.flag_id}' not found")
    return Result(command="targetflags show", data={"flag": flag})
