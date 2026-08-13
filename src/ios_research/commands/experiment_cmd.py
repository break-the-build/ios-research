"""`ios-research experiment` — create, list and inspect experiments."""

from __future__ import annotations

from .. import devices, targets
from ..errors import UsageError
from ..experiment import ExperimentStore
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("experiment", parents=[parent],
                              help="manage research experiments")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_create = sub.add_parser("create", parents=[parent],
                              help="create a reproducible experiment")
    p_create.add_argument("--target", default=None)
    p_create.add_argument("--device", default=None)
    p_create.add_argument("--seed", type=int, default=None)
    p_create.set_defaults(func=cmd_create)

    p_list = sub.add_parser("list", parents=[parent], help="list experiments")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent], help="show one experiment")
    p_show.add_argument("experiment_id")
    p_show.set_defaults(func=cmd_show)

    p.set_defaults(func=cmd_list)


def cmd_create(ctx, args) -> Result:
    ws = ctx.workspace()
    cfg = ctx.config()
    target_id = args.target or cfg.get("default_target")
    device_id = args.device or cfg.get("default_device")
    seed = args.seed if args.seed is not None else cfg.get("fuzz.seed", 0)

    # Validate references before creating any state.
    if not targets.is_registered(target_id):
        raise UsageError(f"unknown target '{target_id}'")
    device = devices.get(device_id)

    store = ExperimentStore(ws)
    exp = store.create(target=target_id, device=device_id,
                       os_version=device.os_version, config_hash=cfg.hash,
                       seed=seed)
    return Result(command="experiment create", data={"experiment": exp.to_dict()},
                  messages=[f"created experiment {exp.id}"])


def cmd_list(ctx, args) -> Result:
    store = ExperimentStore(ctx.workspace())
    exps = [e.to_dict() for e in store.list()]
    return Result(command="experiment list",
                  data={"experiments": exps, "count": len(exps)},
                  human=lambda d: "\n".join(
                      f"{e['id']:20} {e['status']:10} {e['target']:14} "
                      f"seed={e['seed']}" for e in d["experiments"]) or "(none)")


def cmd_show(ctx, args) -> Result:
    store = ExperimentStore(ctx.workspace())
    exp = store.get(args.experiment_id)
    return Result(command="experiment show", data={"experiment": exp.to_dict()})
