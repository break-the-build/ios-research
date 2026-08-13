"""`ios-research config` — inspect and modify workspace configuration."""

from __future__ import annotations

import json

from ..config import Config
from ..errors import UsageError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("config", parents=[parent],
                              help="view and edit configuration")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_get = sub.add_parser("get", parents=[parent], help="get a config value")
    p_get.add_argument("key", help="dotted key, e.g. fuzz.workers")
    p_get.set_defaults(func=cmd_get)

    p_set = sub.add_parser("set", parents=[parent], help="set a config value")
    p_set.add_argument("key")
    p_set.add_argument("value", help="JSON or scalar value")
    p_set.set_defaults(func=cmd_set)

    p_list = sub.add_parser("list", parents=[parent], help="print full config")
    p_list.set_defaults(func=cmd_list)

    p_hash = sub.add_parser("hash", parents=[parent],
                            help="print the deterministic config hash")
    p_hash.set_defaults(func=cmd_hash)

    p.set_defaults(func=cmd_list)


def _load(ctx) -> tuple:
    ws = ctx.workspace()
    values = ws.read_json("config/config.json") if \
        ws.path("config/config.json").exists() else {}
    return ws, Config(values)


def cmd_get(ctx, args) -> Result:
    _, cfg = _load(ctx)
    value = cfg.get(args.key)
    if value is None:
        raise UsageError(f"no such config key: {args.key}")
    return Result(command="config get", data={"key": args.key, "value": value},
                  messages=[str(value)])


def _coerce(raw: str):
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def cmd_set(ctx, args) -> Result:
    ws, cfg = _load(ctx)
    new_cfg = cfg.set(args.key, _coerce(args.value))
    ws.write_json("config/config.json", new_cfg.values)
    return Result(command="config set",
                  data={"key": args.key, "value": new_cfg.get(args.key),
                        "config_hash": new_cfg.hash},
                  messages=[f"set {args.key} = {new_cfg.get(args.key)}"])


def cmd_list(ctx, args) -> Result:
    _, cfg = _load(ctx)
    return Result(command="config list",
                  data={"config": cfg.values, "config_hash": cfg.hash},
                  human=lambda d: json.dumps(d["config"], indent=2, sort_keys=True))


def cmd_hash(ctx, args) -> Result:
    _, cfg = _load(ctx)
    return Result(command="config hash", data={"config_hash": cfg.hash},
                  messages=[cfg.hash])
