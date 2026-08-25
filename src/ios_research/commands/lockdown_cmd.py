"""`ios-research lockdown` — Lockdown Mode paired-run differential profile (#60)."""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("lockdown", parents=[parent],
                              help="Lockdown Mode paired-run profile "
                                   "(observations only; no bypass tooling)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_create = sub.add_parser("create", parents=[parent],
                              help="declare a standard/Lockdown pair")
    p_create.add_argument("--name", default="lm-pair")
    p_create.add_argument("--target-standard", required=True)
    p_create.add_argument("--target-lockdown", required=True)
    p_create.add_argument("--build-standard", required=True,
                          help="build id of the standard configuration")
    p_create.add_argument("--build-lockdown", required=True,
                          help="build id of the lockdown configuration")
    p_create.add_argument("--corpus", default=None)
    p_create.add_argument("--real-device", action="store_true",
                          dest="real_device",
                          help="pair runs against a real enrolled device "
                               "(opt-in; default is simulation fixtures)")
    p_create.set_defaults(func=cmd_create)

    p_run = sub.add_parser("run", parents=[parent],
                           help="execute the paired run")
    p_run.add_argument("pair_id", nargs="?", default=None)
    p_run.add_argument("--attest-lockdown-enabled", action="store_true",
                       dest="attest",
                       help="researcher attestation that the lockdown "
                            "configuration was enabled")
    p_run.set_defaults(func=cmd_run)

    p_list = sub.add_parser("list", parents=[parent], help="list pairs")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent],
                            help="show latest/one pair and its results")
    p_show.add_argument("pair_id", nargs="?", default=None)
    p_show.set_defaults(func=cmd_show)

    p_state = sub.add_parser("state", parents=[parent],
                             help="verify host Lockdown Mode state and "
                                  "paired-run tooling readiness (#228 §4)")
    p_state.set_defaults(func=cmd_state)

    p.set_defaults(func=cmd_list)


def _lm_state() -> dict:
    """Read the host Lockdown Mode state (0 = off, 1/2 = enabled levels)."""
    import subprocess
    try:
        out = subprocess.run(["sysctl", "-n",
                              "security.mac.lockdown_mode_state"],
                             capture_output=True, text=True, timeout=10)
        raw = out.stdout.strip()
        state = int(raw) if raw.isdigit() else -1
        readable = out.returncode == 0 and state >= 0
    except (OSError, ValueError):
        readable, state = False, -1
    return {"readable": readable, "raw": state,
            "enabled": bool(state >= 1),
            "source": "sysctl security.mac.lockdown_mode_state"}


def cmd_state(ctx, args) -> Result:
    from ..targets import _REGISTRY, create
    lm = _lm_state()
    # Prerequisite probe: at least one mock target must be constructible for
    # the paired run's standard leg; the lockdown leg is the same binary
    # under LM policy.
    mock_targets = []
    for tid in sorted(_REGISTRY):
        try:
            if getattr(create(tid), "mock", False):
                mock_targets.append(tid)
        except Exception:  # noqa: BLE001 - readiness probe only
            continue
    data = {"lockdown_mode": lm,
            "paired_run_ready": lm["readable"] and bool(mock_targets),
            "mock_target_count": len(mock_targets),
            "notes": [
                "enable Lockdown Mode in System Settings > Privacy & "
                "Security (reversible; requires reboot) before the "
                "lockdown leg",
                f"currently: {'ENABLED' if lm['enabled'] else 'disabled'}",
            ]}
    return Result(command="lockdown state", data=data)


def _resolve(engine, pair_id):
    if pair_id:
        return engine.get(pair_id)
    items = engine.list()
    if not items:
        raise NotFoundError("no lockdown pairs found")
    return sorted(items, key=lambda x: x.created_at)[-1]


def cmd_create(ctx, args) -> Result:
    from ..lockdown import LockdownEngine
    engine = LockdownEngine(ctx.workspace())
    pair = engine.create(
        name=args.name, target_standard=args.target_standard,
        target_lockdown=args.target_lockdown,
        build_standard=args.build_standard,
        build_lockdown=args.build_lockdown,
        attested_lockdown_enabled=False,
        simulation=not args.real_device, corpus_id=args.corpus)
    return Result(command="lockdown create",
                  data={"pair_id": pair.id, "simulation": pair.simulation},
                  messages=[f"created pair {pair.id}"])


def cmd_run(ctx, args) -> Result:
    from ..lockdown import LockdownEngine
    engine = LockdownEngine(ctx.workspace())
    pair = _resolve(engine, args.pair_id)
    # Attestation flows through as configuration evidence for this run.
    if args.attest:
        pair.attested_lockdown_enabled = True
    summary = engine.run(pair)
    counts = summary["counts"]
    return Result(command="lockdown run",
                  data={"pair_id": pair.id, "summary": summary},
                  messages=[f"{summary['inputs_checked']} input(s): "
                            f"{counts['candidate-finding']} candidate(s), "
                            f"{counts['hardening-delta']} hardening "
                            f"delta(s)"])


def cmd_list(ctx, args) -> Result:
    from ..lockdown import LockdownEngine
    items = [{"id": x.id, "standard": x.target_standard,
              "lockdown": x.target_lockdown, "status": x.status}
             for x in LockdownEngine(ctx.workspace()).list()]
    return Result(command="lockdown list",
                  data={"pairs": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{x['id']} [{x['status']}] {x['standard']} vs "
                      f"{x['lockdown']}" for x in d["pairs"]) or "(none)")


def cmd_show(ctx, args) -> Result:
    from ..errors import NotFoundError, StateError
    from ..lockdown import LockdownEngine
    engine = LockdownEngine(ctx.workspace())
    pair = _resolve(engine, args.pair_id)
    try:
        results = ctx.workspace().read_json(f"analysis/{pair.id}-results.json")
    except Exception as exc:
        if isinstance(exc, NotFoundError):
            raise
        raise StateError(f"pair '{pair.id}' has not been run") from exc
    rows = "\n".join(
        f"{r['verdict']:18} {r['input_sha256'][:16]} std={r['standard']['outcome']:<9} "
        f"lm={r['lockdown']['outcome']:<9}"
        for r in results["results"][:25])
    return Result(command="lockdown show",
                  data={"pair": pair.to_dict(), "summary": {
                      k: v for k, v in results.items()
                      if k != "results"}},
                  human=lambda _d: rows or "(no inputs checked)")
