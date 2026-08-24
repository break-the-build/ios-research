"""`ios-research fuzz` — start/stop/pause/resume/status/stats."""

from __future__ import annotations

import time

from ..errors import NotFoundError, StateError, UsageError
from ..output import Result


def _require_available(target, target_id: str) -> None:
    """Fail fast with a clear blocker for an unavailable real (non-mock) target.

    Real targets (macOS harness, on-device) need hardware/toolchain that may be
    absent. Rather than fabricate ``ABNORMAL`` crash records for every case, stop
    with an actionable blocker — no fabricated results (see the experiment-loop
    doc and issue #11).
    """
    if getattr(target, "mock", True):
        return
    available = getattr(target, "available", None)
    if callable(available) and not available():
        blocker = ""
        blocker_fn = getattr(target, "blocker", None)
        if callable(blocker_fn):
            blocker = blocker_fn()
        raise StateError(
            f"target '{target_id}' is not available: "
            f"{blocker or 'required device/toolchain not present'}",
            details={"target": target_id, "blocker": blocker})


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("fuzz", parents=[parent],
                              help="run and control fuzzing sessions")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_start = sub.add_parser("start", parents=[parent], help="start fuzzing")
    p_start.add_argument("--target", default=None)
    p_start.add_argument("--corpus", default=None)
    p_start.add_argument("--experiment", default=None)
    p_start.add_argument("--seed", type=int, default=None)
    p_start.add_argument("--max-cases", type=int, default=None)
    p_start.add_argument("--delivery", default=None,
                         choices=["interactive", "one-click", "zero-click",
                                  "proximity", "physical"],
                         help="researcher-declared input-delivery channel "
                              "(reporting provenance, #106)")
    p_start.add_argument("--duration", type=float, default=None,
                         help="wall-clock budget in seconds")
    p_start.add_argument("--workers", type=int, default=None)
    p_start.add_argument("--chunk", type=int, default=None,
                         help="cases to execute this invocation (for resumable runs)")
    p_start.add_argument("--dictionary", default=None,
                         help="path to a token dictionary (constraint-guided mutation, #30)")
    p_start.add_argument("--value-profile", action="store_true", dest="value_profile",
                         help="record value-profile guidance in campaign metadata (#30)")
    p_start.add_argument("--sanitizer-profile", default=None, dest="sanitizer_profile",
                         help="named sanitizer build profile recorded as provenance (#31)")
    p_start.add_argument("--mutator-plugin", default=None, dest="mutator_plugin",
                         help="path to a grammar-aware mutator plugin (#41)")
    p_start.add_argument("--max-input-bytes", type=int, default=None,
                         help="skip mutated inputs larger than this many bytes "
                              "(default 1048576; 0 disables the bound)")
    p_start.add_argument("--sched-perturb", default=None, dest="sched_perturb",
                         help="comma-separated scheduling-perturbation modes "
                              "applied between cases (#70): "
                              "yield,priority,affinity,random-delay")
    p_start.add_argument("--mutator", default=None,
                         choices=["generic", "llm"],
                         help="mutation driver: builtin generic (default) or "
                              "LLM-in-the-loop proposals (#71)")
    p_start.add_argument("--llm-rounds", type=int, default=None,
                         dest="llm_rounds",
                         help="proposal rounds for --mutator llm (#71)")
    p_start.add_argument("--llm-budget", type=int, default=None,
                         dest="llm_budget",
                         help="total model-proposed cases for --mutator llm "
                              "(#71)")
    p_start.add_argument("--llm-proposer-cmd", default=None,
                         dest="llm_proposer_cmd",
                         help="user-declared local command template for "
                              "--mutator llm: round context JSON on stdin, "
                              "one base64 candidate per stdout line (#71)")
    p_start.set_defaults(func=cmd_start)

    for action in ("status", "stats"):
        pa = sub.add_parser(action, parents=[parent],
                            help=f"show fuzz {action}")
        pa.add_argument("session_id", nargs="?", default=None)
        pa.set_defaults(func=cmd_status)

    for action, fn in (("stop", "stop"), ("pause", "pause"), ("resume", "resume")):
        pa = sub.add_parser(action, parents=[parent],
                            help=f"{action} a fuzz session")
        pa.add_argument("session_id", nargs="?", default=None)
        if action == "resume":
            pa.add_argument("--chunk", type=int, default=None)
            pa.add_argument("--duration", type=float, default=None)
        pa.set_defaults(func=_make_control(fn))

    p.set_defaults(func=cmd_status)


def _resolve_session(engine, session_id):
    if session_id:
        return engine.get(session_id)
    session = engine.latest()
    if session is None:
        raise NotFoundError("no fuzz sessions found")
    return session


def cmd_start(ctx, args) -> Result:
    from .. import devices, targets
    from ..corpus import CorpusStore
    from ..experiment import ExperimentStore
    from ..fuzz import FuzzEngine, DEFAULT_BASE
    ws = ctx.workspace()
    cfg = ctx.config()
    target_id = args.target or cfg.get("default_target")
    if not targets.is_registered(target_id):
        raise UsageError(f"unknown target '{target_id}'")
    _require_available(targets.create(target_id), target_id)
    seed = args.seed if args.seed is not None else cfg.get("fuzz.seed", 0)
    max_cases = args.max_cases if args.max_cases is not None \
        else cfg.get("fuzz.max_cases", 1000)
    workers = args.workers if args.workers is not None \
        else cfg.get("fuzz.workers", 1)
    max_workers = cfg.get("limits.max_workers", 8)
    if workers > max_workers:
        raise UsageError(f"workers={workers} exceeds limit {max_workers}")

    # LLM-in-the-loop mutator (#71): resolve and validate before any state is
    # created, so bad budgets/proposer configs fail as pure usage errors.
    proposer = None
    llm_rounds = llm_budget = 0
    raw_mode = getattr(args, "mutator", None) or cfg.get("fuzz.mutator") or ""
    if raw_mode == "generic":
        raw_mode = ""
    if raw_mode:
        if raw_mode != "llm":
            raise UsageError(f"unknown mutator mode '{raw_mode}'")
        from .. import llmmutate
        llm_rounds = args.llm_rounds if args.llm_rounds is not None \
            else cfg.get("fuzz.llm_rounds", llmmutate.DEFAULT_LLM_ROUNDS)
        llm_budget = args.llm_budget if args.llm_budget is not None \
            else cfg.get("fuzz.llm_budget", llmmutate.DEFAULT_LLM_BUDGET)
        llmmutate.validate_budget(
            llm_rounds, llm_budget,
            max_rounds=cfg.get("limits.max_llm_rounds",
                               llmmutate.DEFAULT_MAX_LLM_ROUNDS),
            max_budget=cfg.get("limits.max_llm_budget",
                               llmmutate.DEFAULT_MAX_LLM_BUDGET))
        template = getattr(args, "llm_proposer_cmd", None) \
            or cfg.get("fuzz.llm_proposer_cmd")
        if not template:
            raise UsageError(
                "--mutator llm needs a proposal source: pass "
                "--llm-proposer-cmd (or set fuzz.llm_proposer_cmd)")
        proposer = llmmutate.resolve_proposer(template)

    # Resolve or create corpus.
    corpus_store = CorpusStore(ws)
    if args.corpus:
        corpus = corpus_store.get(args.corpus)
    else:
        corpus_name = f"default-{target_id}"
        existing = [c for c in corpus_store.list() if c.name == corpus_name]
        corpus = existing[0] if existing else corpus_store.create(
            corpus_name, target=target_id)
        if not corpus.testcases:
            seeds = targets.create(target_id).seeds() or [DEFAULT_BASE]
            for seed_bytes in seeds:
                corpus_store.add_bytes(corpus, seed_bytes, origin="seed")

    # Resolve or create experiment.
    exp_store = ExperimentStore(ws)
    if args.experiment:
        experiment = exp_store.get(args.experiment)
    else:
        device = devices.get(cfg.get("default_device"))
        experiment = exp_store.create(
            target=target_id, device=device.id, os_version=device.os_version,
            config_hash=cfg.hash, seed=seed,
            params={"corpus": corpus.id, "max_cases": max_cases,
                    **({"delivery": args.delivery}
                       if getattr(args, "delivery", None) else {}),
                    **({"mutator": "llm", "llm_rounds": llm_rounds,
                        "llm_budget": llm_budget} if proposer else {})})

    engine = FuzzEngine(ws)
    dictionary = getattr(args, "dictionary", None)
    max_input_bytes = getattr(args, "max_input_bytes", None)
    if max_input_bytes is None:
        max_input_bytes = cfg.get("limits.max_input_bytes")
    sched_modes = ()
    raw_sched = getattr(args, "sched_perturb", None)
    if raw_sched:
        from ..races import validate_modes
        sched_modes = validate_modes(
            mode.strip() for mode in raw_sched.split(",") if mode.strip())
    session = engine.create(experiment_id=experiment.id, target=target_id,
                            corpus_id=corpus.id, seed=seed, workers=workers,
                            max_cases=max_cases, duration_s=args.duration,
                            strategy_weights=cfg.get("fuzz.strategy_weights"),
                            dictionary_path=dictionary,
                            value_profile=bool(getattr(args, "value_profile",
                                                       False)),
                            sanitizer_profile=getattr(
                                args, "sanitizer_profile", None),
                            mutator_plugin_path=getattr(
                                args, "mutator_plugin", None),
                            max_input_bytes=max_input_bytes,
                            sched_modes=sched_modes,
                            mutator_mode="llm" if proposer else "",
                            proposer_id=(proposer.proposer_id
                                         if proposer else ""),
                            llm_rounds=llm_rounds,
                            llm_budget=llm_budget)
    deadline = time.monotonic() + args.duration if args.duration else None
    session = engine.advance(session, max_new=args.chunk, deadline=deadline,
                             proposer=proposer)

    # Reflect fuzzing stats onto the experiment.
    experiment.status = "running" if session.status != "completed" else "completed"
    experiment.stats = session.stats()
    exp_store.save(experiment)

    messages = [f"session {session.id}: {session.status} "
                f"({session.cursor}/{session.max_cases} cases, "
                f"{session.unique_crashes} unique crashes)"]
    if proposer:
        messages.append(
            f"llm: rounds {session.llm_rounds_done}/{llm_rounds}, "
            f"proposals {session.llm_cases_used}/{llm_budget} "
            f"(proposer {session.proposer_id})")
    return Result(command="fuzz start",
                  data={"session": session.to_dict(), "stats": session.stats(),
                        "experiment_id": experiment.id},
                  messages=messages)


def cmd_status(ctx, args) -> Result:
    from ..fuzz import FuzzEngine
    engine = FuzzEngine(ctx.workspace())
    session = _resolve_session(engine, getattr(args, "session_id", None))
    return Result(command="fuzz status", data={"stats": session.stats()},
                  human=lambda d: f"{d['stats']['id']} {d['stats']['status']} "
                                  f"{d['stats']['executed']}/{d['stats']['max_cases']} "
                                  f"crashes={d['stats']['unique_crashes']}")


def _make_control(action: str):
    def handler(ctx, args) -> Result:
        from ..fuzz import FuzzEngine
        engine = FuzzEngine(ctx.workspace())
        session = _resolve_session(engine, getattr(args, "session_id", None))
        if action == "pause":
            session = engine.pause(session)
        elif action == "stop":
            session = engine.stop(session)
        elif action == "resume":
            import time as _t
            deadline = (_t.monotonic() + args.duration) \
                if getattr(args, "duration", None) else None
            session = engine.resume(session, max_new=getattr(args, "chunk", None),
                                    deadline=deadline)
        return Result(command=f"fuzz {action}",
                      data={"session": session.to_dict(), "stats": session.stats()},
                      messages=[f"session {session.id}: {session.status}"])
    return handler
