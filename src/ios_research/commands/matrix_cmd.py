"""`ios-research matrix` — device/OS/build reproduction matrices (#37)."""

from __future__ import annotations

import json
from pathlib import Path

from ..errors import ValidationError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("matrix", parents=[parent],
                              help="device/OS/build matrix reproduction with "
                                   "reliability scoring")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_create = sub.add_parser("create", parents=[parent],
                              help="declare a confirmation matrix")
    p_create.add_argument("--target", required=True)
    p_create.add_argument("--input", required=True,
                          help="path to the input to confirm")
    p_create.add_argument("--trials", type=int, default=10)
    p_create.add_argument("--seed", type=int, default=0)
    p_create.add_argument("--cells", required=True,
                          help="JSON file with an array of cell specs "
                               "(device_id, model, os_name, os_version, build)")
    p_create.set_defaults(func=cmd_create)

    p_run = sub.add_parser("run", parents=[parent],
                           help="execute bounded trials per cell")
    p_run.add_argument("matrix_id")
    p_run.set_defaults(func=cmd_run)

    p_show = sub.add_parser("show", parents=[parent], help="show results")
    p_show.add_argument("matrix_id")
    p_show.set_defaults(func=cmd_show)

    p_list = sub.add_parser("list", parents=[parent], help="list matrices")
    p_list.set_defaults(func=cmd_list)

    p.set_defaults(func=cmd_list)


def cmd_create(ctx, args) -> Result:
    from ..matrix import ReproductionMatrixEngine
    try:
        specs = json.loads(Path(args.cells).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"cannot read cells: {exc}") from exc
    if not isinstance(specs, list):
        raise ValidationError("cells must be a JSON array of objects")
    path = Path(args.input)
    if not path.is_file():
        raise ValidationError(f"input file not found: {path}")
    run = ReproductionMatrixEngine(ctx.workspace()).create(
        target=args.target, input_bytes=path.read_bytes(),
        trials=args.trials, seed=args.seed, cells=specs)
    return Result(command="matrix create",
                  data={"matrix_id": run.id, "cells": len(run.cells),
                        "trials_per_cell": run.trials_per_cell},
                  messages=[f"created matrix {run.id} "
                            f"({len(run.cells)} cells × {run.trials_per_cell} trials)"])


def cmd_run(ctx, args) -> Result:
    from ..matrix import ReproductionMatrixEngine
    engine = ReproductionMatrixEngine(ctx.workspace())
    run = engine.get(args.matrix_id)
    summary = engine.run(run)
    return Result(command="matrix run",
                  data={"matrix_id": run.id, "summary": summary},
                  messages=[f"{summary['reproducible_cells']}/"
                            f"{summary['cells_run']} cells reproduce "
                            f"reliably (rate ≥50% and stable signature)"])


def cmd_show(ctx, args) -> Result:
    from ..matrix import ReproductionMatrixEngine
    engine = ReproductionMatrixEngine(ctx.workspace())
    summary = engine.results(args.matrix_id)
    return Result(command="matrix show", data={"matrix_id": args.matrix_id,
                                               "summary": summary})


def cmd_list(ctx, args) -> Result:
    from ..matrix import ReproductionMatrixEngine
    runs = ReproductionMatrixEngine(ctx.workspace()).list()
    items = [{"id": r.id, "target": r.target, "cells": len(r.cells),
              "status": r.status} for r in runs]
    return Result(command="matrix list",
                  data={"matrices": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{m['id']} {m['target']} cells={m['cells']} {m['status']}"
                      for m in d["matrices"]) or "(none)")
