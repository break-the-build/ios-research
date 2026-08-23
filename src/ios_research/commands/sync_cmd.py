"""`ios-research sync` — distributed corpus synchronization (#32)."""

from __future__ import annotations

import argparse

from ..errors import SafetyError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("sync", parents=[parent],
                              help="export/import corpus bundles between "
                                   "local workers (allowlisted dirs only)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_export = sub.add_parser("export", parents=[parent],
                              help="write a deterministic exchange bundle")
    p_export.add_argument("corpus_id")
    p_export.add_argument("--out", required=True,
                          help="output bundle directory")
    p_export.add_argument("--worker", default="local",
                          help="worker identifier recorded in the manifest")
    p_export.add_argument("--cursor", type=int, default=0,
                          help="session cursor to record for lag tracking")
    p_export.set_defaults(func=cmd_export)

    p_import = sub.add_parser("import", parents=[parent],
                              help="import a bundle into a corpus "
                                   "(hashes verified, atomic)")
    p_import.add_argument("corpus_id")
    p_import.add_argument("bundle_dir")
    p_import.add_argument("--allow-root", action="append", dest="allow_roots",
                          default=[], metavar="R",
                          help="directory the bundle must live under; "
                               "repeatable, required")
    p_import.add_argument("--minimize", action=argparse.BooleanOptionalAction,
                          default=False,
                          help="greedy coverage set-cover before merging")
    p_import.set_defaults(func=cmd_import)

    p_status = sub.add_parser("status", parents=[parent],
                              help="aggregate read-only worker status rollup")
    p_status.add_argument("--worker", action="append", dest="workers",
                          required=True, metavar="D",
                          help="worker export directory; repeatable")
    p_status.set_defaults(func=cmd_status)

    p.set_defaults(func=lambda ctx, args: Result(
        command="sync", messages=["use 'sync export', 'sync import' "
                                  "or 'sync status'"]))


def cmd_export(ctx, args) -> Result:
    from ..sync import export_corpus
    summary = export_corpus(ctx.workspace(), args.corpus_id, args.out,
                            worker_id=args.worker, cursor=args.cursor)
    return Result(command="sync export", data=summary,
                  messages=[f"exported {summary['entries']} entry(ies) "
                            f"to {summary['path']}"])


def cmd_import(ctx, args) -> Result:
    from ..sync import import_bundle
    if not args.allow_roots:
        raise SafetyError(
            "bundle import requires at least one --allow-root; refusing to "
            "read from an unlisted location")
    stats = import_bundle(ctx.workspace(), args.corpus_id, args.bundle_dir,
                          allowed_roots=args.allow_roots,
                          minimize=args.minimize)
    return Result(command="sync import", data=stats,
                  messages=[f"imported {stats['imported']} entry(ies), "
                            f"skipped {stats['duplicates_skipped']} "
                            f"duplicate(s)"])


def cmd_status(ctx, args) -> Result:
    from ..sync import aggregate_status
    data = aggregate_status(ctx.workspace(), args.workers)
    unhealthy = data["workers_unhealthy"]
    messages = [f"{data['workers_healthy']} healthy worker(s)"
                + (f", {unhealthy} unhealthy" if unhealthy else "")]
    return Result(command="sync status", data=data, human=lambda d: "\n".join(
        [f"{'worker':<12} {'execs':>8} {'entries':>7} {'feat':>5} "
         f"{'crashes':>7} {'lag':>6}  dir"] + [
            f"{w.get('worker_id', '?')[:12]:<12} "
            f"{w.get('executions', '-'):>8} "
            f"{w.get('corpus_entries', '-'):>7} "
            f"{w.get('coverage_features', '-'):>5} "
            f"{w.get('crashes', '-'):>7} "
            f"{w.get('sync_lag', '-') if w['healthy'] else 'DOWN':>6}  "
            f"{w['worker_dir']}"
            for w in d["workers"]] + [
            f"totals: executions={d['totals']['executions']} "
            f"corpus_entries={d['totals']['corpus_entries']} "
            f"coverage_features={d['totals']['coverage_features']} "
            f"crashes={d['totals']['crashes']}",
        ]))
