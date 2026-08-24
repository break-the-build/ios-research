"""`ios-research campaign` — distributed campaign corpus synchronization (#32).

Opt-in: sync paths must be under a configured allowlisted root
(config ``campaign.sync_roots``) or inside the workspace.
"""

from __future__ import annotations

from pathlib import Path

from ..errors import NotFoundError, UsageError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("campaign", parents=[parent],
                              help="distributed campaign corpus "
                                   "synchronization (opt-in)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_export = sub.add_parser("export", parents=[parent],
                              help="export a corpus as an exchange bundle")
    p_export.add_argument("--corpus", required=True)
    p_export.add_argument("--out", required=True)
    p_export.add_argument("--worker", required=True)
    p_export.add_argument("--campaign", default="default")
    p_export.set_defaults(func=cmd_export)

    p_import = sub.add_parser("import", parents=[parent],
                              help="import an exchange bundle into a corpus")
    p_import.add_argument("--from", dest="from_dir", required=True)
    p_import.add_argument("--corpus", required=True)
    p_import.add_argument("--dry-run", action="store_true")
    p_import.add_argument("--require-new-coverage", action="store_true",
                          help="skip inputs that add no new coverage feature")
    p_import.set_defaults(func=cmd_import)

    p_status = sub.add_parser("status", parents=[parent],
                              help="aggregate worker/corpus sync status")
    p_status.add_argument("--campaign", default=None)
    p_status.set_defaults(func=cmd_status)

    p.set_defaults(func=cmd_status)


def _resolve_corpus(ctx, corpus_id):
    from ..corpus import CorpusStore
    store = CorpusStore(ctx.workspace())
    corpus = store.get(corpus_id)
    return store, corpus


def _checked_path(ctx, raw: str):
    from ..campaign_sync import ensure_allowed_path
    return ensure_allowed_path(Path(raw), ctx.workspace(), ctx.config())


def cmd_export(ctx, args) -> Result:
    from ..campaign_sync import export_bundle
    store, corpus = _resolve_corpus(ctx, args.corpus)
    out = _checked_path(ctx, args.out)
    manifest = export_bundle(ctx.workspace(), store, corpus, out,
                             worker_id=args.worker, campaign_id=args.campaign)
    return Result(command="campaign export",
                  data={"manifest": manifest, "out": str(out)},
                  messages=[f"exported {len(manifest['entries'])} input(s) "
                            f"for worker '{args.worker}'"])


def cmd_import(ctx, args) -> Result:
    from ..campaign_sync import import_bundle
    store, corpus = _resolve_corpus(ctx, args.corpus)
    src = _checked_path(ctx, args.from_dir)
    report = import_bundle(ctx.workspace(), store, corpus, src,
                           dry_run=args.dry_run,
                           require_new_coverage=args.require_new_coverage)
    ok = report["rejected_count"] == 0
    return Result(command="campaign import",
                  ok=ok,
                  data=report,
                  messages=[f"seen={report['entries_seen']} "
                            f"accepted={report['accepted_count']} "
                            f"duplicates={report['duplicates']} "
                            f"rejected={report['rejected_count']} "
                            f"coverage_skipped={report['coverage_skipped']}"
                            + (" (dry run)" if report["dry_run"] else "")])


def cmd_status(ctx, args) -> Result:
    from ..campaign_sync import aggregate_status
    status = aggregate_status(ctx.workspace(), campaign_id=args.campaign)
    return Result(command="campaign status",
                  data=status,
                  human=lambda d: (
                      f"workers={d['worker_count']} "
                      f"inputs={d['total_inputs_imported']} "
                      f"rejected={d['total_rejected']} "
                      f"newest_sync={d['newest_sync'] or '-'}"))
