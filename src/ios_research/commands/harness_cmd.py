"""`ios-research harness` — LLM-assisted fuzz driver generation."""

from __future__ import annotations

from ..errors import UsageError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("harness", parents=[parent],
                              help="generate and review fuzz harness candidates")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_gen = sub.add_parser("generate", parents=[parent],
                           help="propose harness candidates for a target")
    p_gen.add_argument("--target", required=True)
    p_gen.add_argument("--provider", default="deterministic-template")
    p_gen.add_argument("--proposals-path", default=None,
                       help="JSON file of proposals (provider 'file')")
    p_gen.add_argument("--max-candidates", type=int, default=3)
    p_gen.add_argument("--smoke", action="store_true",
                       help="execute validated candidates once (opt-in)")
    p_gen.set_defaults(func=cmd_generate)

    p_list = sub.add_parser("list", parents=[parent],
                            help="list harness candidates")
    p_list.add_argument("--status", default=None)
    p_list.add_argument("--target", default=None)
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent],
                            help="show one candidate including its source")
    p_show.add_argument("candidate_id")
    p_show.set_defaults(func=cmd_show)

    p_accept = sub.add_parser("accept", parents=[parent],
                              help="accept a validated candidate")
    p_accept.add_argument("candidate_id")
    p_accept.set_defaults(func=cmd_accept)

    p_reject = sub.add_parser("reject", parents=[parent],
                              help="reject a candidate")
    p_reject.add_argument("candidate_id")
    p_reject.add_argument("--reason", default="")
    p_reject.set_defaults(func=cmd_reject)

    p.set_defaults(func=cmd_list)


def _summary(cand) -> dict:
    return {"id": cand.id, "target": cand.target, "kind": cand.kind,
            "provider": cand.provider, "status": cand.status,
            "valid": bool(cand.validation.get("ok")),
            "rationale": cand.rationale}


def cmd_generate(ctx, args) -> Result:
    from ..harness import HarnessGenerator, create_provider
    if args.max_candidates < 1:
        raise UsageError("--max-candidates must be >= 1")
    provider = create_provider(args.provider, path=args.proposals_path)
    gen = HarnessGenerator(ctx.workspace())
    created = gen.generate(target_id=args.target, provider=provider,
                           max_candidates=args.max_candidates,
                           smoke=args.smoke)
    return Result(
        command="harness generate",
        data={"target": args.target, "provider": provider.name,
              "candidates": [_summary(c) for c in created],
              "count": len(created)},
        messages=[f"generated {len(created)} candidate(s) for {args.target}"])


def _filtered(ctx, args):
    from ..harness import HarnessStore
    items = HarnessStore(ctx.workspace()).list(status=args.status)
    if getattr(args, "target", None):
        items = [c for c in items if c.target == args.target]
    return items


def cmd_list(ctx, args) -> Result:
    items = _filtered(ctx, args)
    data = {"candidates": [_summary(c) for c in items], "count": len(items)}
    return Result(command="harness list", data=data,
                  human=lambda d: "\n".join(
                      f"{c['id']:24} {c['target']:20} {c['kind']:20}"
                      f" [{c['status']}]" for c in d["candidates"]) or "(none)")


def cmd_show(ctx, args) -> Result:
    from ..harness import HarnessStore
    cand = HarnessStore(ctx.workspace()).get(args.candidate_id)
    return Result(command="harness show", data=cand.to_dict())


def cmd_accept(ctx, args) -> Result:
    from ..harness import HarnessGenerator
    cand = HarnessGenerator(ctx.workspace()).transition(
        args.candidate_id, "accept")
    return Result(command="harness accept",
                  data=_summary(cand),
                  messages=[f"accepted {cand.id}"])


def cmd_reject(ctx, args) -> Result:
    from ..harness import HarnessGenerator
    cand = HarnessGenerator(ctx.workspace()).transition(
        args.candidate_id, "reject", reason=args.reason)
    return Result(command="harness reject",
                  data=_summary(cand),
                  messages=[f"rejected {cand.id}"])
