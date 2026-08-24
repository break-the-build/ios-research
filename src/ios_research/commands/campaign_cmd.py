"""`ios-research campaign` — opt-in distributed campaign coordination (#32).

Subcommands operate on an explicitly allowlisted shared directory
(``distcampaign.allowlist_roots`` in workspace config; see
:mod:`ios_research.distcampaign`):

* ``export``           — append a manifest of not-yet-exported corpus inputs
* ``import``           — pull, verify, quarantine, minimize and merge remote inputs
* ``status-aggregate`` — merge worker status snapshots into one aggregate record
* ``sync``             — one round trip: export own corpus + import others + aggregate

All subcommands are local-directory operations; there is no network discovery.
"""

from __future__ import annotations

from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser(
        "campaign", parents=[parent],
        help="coordinate distributed fuzzing campaigns (opt-in shared-dir sync)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    def _sync_root_arg(parser) -> None:
        parser.add_argument("--sync-root", default=None,
                            help="shared exchange directory (must be "
                                 "allowlisted in config)")

    p_export = sub.add_parser("export", parents=[parent],
                              help="append a manifest exporting corpus inputs")
    p_export.add_argument("campaign_id")
    p_export.add_argument("--producer", required=True,
                          help="this worker's stable id on the exchange")
    p_export.add_argument("--corpus", required=True, help="corpus id to export")
    p_export.add_argument("--session", default=None,
                          help="fuzz session id for live worker status numbers")
    _sync_root_arg(p_export)
    p_export.set_defaults(func=cmd_export)

    p_import = sub.add_parser("import", parents=[parent],
                              help="pull and safely merge remote campaign inputs")
    p_import.add_argument("campaign_id")
    p_import.add_argument("--exclude-producer", default=None,
                          help="skip manifests from this producer (usually self)")
    p_import.add_argument("--corpus", default=None,
                          help="active corpus id (default: 'distributed-<campaign>')")
    p_import.add_argument("--target", default=None,
                          help="target id used for coverage-aware minimization")
    _sync_root_arg(p_import)
    p_import.set_defaults(func=cmd_import)

    p_agg = sub.add_parser("status-aggregate", parents=[parent],
                           help="aggregate worker status snapshots into one JSON")
    p_agg.add_argument("campaign_id")
    _sync_root_arg(p_agg)
    p_agg.set_defaults(func=cmd_status_aggregate)

    p_sync = sub.add_parser("sync", parents=[parent],
                            help="one round trip: export + import + aggregate")
    p_sync.add_argument("campaign_id")
    p_sync.add_argument("--producer", required=True)
    p_sync.add_argument("--corpus", required=True)
    p_sync.add_argument("--exclude-producer", default=None)
    p_sync.add_argument("--target", default=None)
    p_sync.add_argument("--session", default=None)
    _sync_root_arg(p_sync)
    p_sync.set_defaults(func=cmd_sync)

    p.set_defaults(func=cmd_status_aggregate)


# --- shared helpers -----------------------------------------------------------

def _engine(ctx, args):
    """Build a sync engine bound to the allowlisted root (fails closed)."""
    from ..config import Config
    from ..distcampaign import DistCampaignSync, resolve_sync_root
    config = ctx.config()
    root = resolve_sync_root(config, getattr(args, "sync_root", None))
    hmac_key = config.get("distcampaign.hmac_key") or None
    engine = DistCampaignSync(ctx.workspace(), config,
                              hmac_key=str(hmac_key) if hmac_key else None)
    return engine, root


def _session_stats(ctx, session_id: str | None) -> dict | None:
    if not session_id:
        return None
    from ..fuzz import FuzzEngine
    return FuzzEngine(ctx.workspace()).get(session_id).stats()


# --- handlers -------------------------------------------------------------------

def cmd_export(ctx, args) -> Result:
    from ..corpus import CorpusStore
    from ..distcampaign import validate_component
    engine, root = _engine(ctx, args)
    producer = validate_component(args.producer, what="--producer")
    corpus = CorpusStore(ctx.workspace()).get(args.corpus)
    out = engine.export(sync_root=root, campaign_id=args.campaign_id,
                        producer=producer, corpus=corpus,
                        session_stats=_session_stats(ctx, args.session))
    return Result(command="campaign export", data=out,
                  messages=[f"appended manifest sequence {out['sequence']} "
                            f"with {out['exported']} input(s)"])


def cmd_import(ctx, args) -> Result:
    engine, root = _engine(ctx, args)
    corpus = engine.get_or_default_corpus(args.campaign_id, args.corpus)
    out = engine.pull(sync_root=root, campaign_id=args.campaign_id,
                      exclude_producer=args.exclude_producer,
                      active_corpus=corpus, target_id=args.target,
                      assume_yes=bool(getattr(args, "assume_yes", False)))
    return Result(command="campaign import", data=out,
                  human=lambda d: "\n".join(
                    [f"applied {d['manifests_applied']} manifest(s): "
                     f"imported {d['imported']}, duplicates {d['duplicates']}, "
                     f"quarantined {len(d['quarantined'])}"]
                    + [f"  quarantined: {q}" for q in d["quarantined"]]))


def cmd_status_aggregate(ctx, args) -> Result:
    engine, root = _engine(ctx, args)
    agg = engine.aggregate_status(sync_root=root, campaign_id=args.campaign_id)
    return Result(command="campaign status-aggregate", data=agg,
                  human=lambda d: "\n".join(
                      [f"{w['producer']:16} {w['health']:8} exec={w['executions']} "
                       f"crash={w['crashes']} lag={w['lag_seconds']}s"
                       for w in d["workers"]] or ["(no worker status files)"]))


def cmd_sync(ctx, args) -> Result:
    from ..distcampaign import validate_component
    engine, root = _engine(ctx, args)
    producer = validate_component(args.producer, what="--producer")
    corpus = engine.get_or_default_corpus(args.campaign_id, args.corpus)
    exported = engine.export(sync_root=root, campaign_id=args.campaign_id,
                             producer=producer, corpus=corpus,
                             session_stats=_session_stats(ctx, args.session))
    imported = engine.pull(sync_root=root, campaign_id=args.campaign_id,
                           exclude_producer=args.exclude_producer or producer,
                           active_corpus=corpus, target_id=args.target,
                           assume_yes=bool(getattr(args, "assume_yes", False)))
    aggregate = engine.aggregate_status(sync_root=root,
                                        campaign_id=args.campaign_id)
    return Result(command="campaign sync",
                  data={"export": exported, "import": imported,
                        "aggregate": {
                            "worker_count": aggregate["worker_count"],
                            "totals": aggregate["totals"],
                            "sync_lag_seconds":
                                aggregate["sync_lag_seconds"]}},
                  messages=[
                      f"exported sequence {exported['sequence']} "
                      f"({exported['exported']} input(s)); imported "
                      f"{imported['imported']} input(s); workers: "
                      f"{aggregate['worker_count']}"])
