"""Core commands: version, doctor, info."""

from __future__ import annotations

import platform
import sys

from pathlib import Path

from .. import __version__, FRAMEWORK_NAME
from ..clock import now_iso
from ..config import DEFAULT_CONFIG
from ..output import Result
from ..safety import boundary_summary
from ..workspace import Workspace, WORKSPACE_DIRNAME


def register(subparsers, parent) -> None:
    p_init = subparsers.add_parser("init", parents=[parent],
                                   help="initialize a research workspace")
    p_init.add_argument("--force", action="store_true",
                        help="re-initialize even if a workspace exists")
    p_init.set_defaults(func=cmd_init)

    p_version = subparsers.add_parser("version", parents=[parent],
                                      help="print framework version")
    p_version.set_defaults(func=cmd_version)

    p_doctor = subparsers.add_parser("doctor", parents=[parent],
                                     help="check environment and workspace health")
    p_doctor.set_defaults(func=cmd_doctor)

    p_info = subparsers.add_parser("info", parents=[parent],
                                   help="print framework capabilities and safety boundary")
    p_info.set_defaults(func=cmd_info)


def cmd_init(ctx, args) -> Result:
    base = Path(ctx.workspace_path) if ctx.workspace_path else \
        Path.cwd() / WORKSPACE_DIRNAME
    ws = Workspace(base)
    marker = ws.init(framework_version=__version__, created_at=now_iso(),
                     force=args.force)
    # Seed a default config file so 'config' commands have a home.
    if not ws.path("config/config.json").exists() or args.force:
        ws.write_json("config/config.json", dict(DEFAULT_CONFIG))
    data = {"workspace": str(ws.root), "marker": marker}
    return Result(command="init", data=data,
                  messages=[f"initialized workspace at {ws.root}"])


def cmd_version(ctx, args) -> Result:
    return Result(command="version",
                  data={"framework": FRAMEWORK_NAME, "version": __version__},
                  messages=[f"{FRAMEWORK_NAME} {__version__}"])


def cmd_doctor(ctx, args) -> Result:
    ws = ctx.workspace(required=False)
    checks = []

    def check(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    py_ok = sys.version_info >= (3, 9)
    check("python_version", py_ok, platform.python_version())
    check("platform", True, platform.platform())
    if ws is not None and ws.initialized:
        check("workspace", True, str(ws.root))
    else:
        check("workspace", False, "not initialized (run 'ios-research init')")

    healthy = all(c["ok"] for c in checks if c["name"] != "workspace")
    data = {"healthy": healthy, "checks": checks,
            "workspace_initialized": bool(ws and ws.initialized)}

    def human(d):
        lines = [f"{'ok' if c['ok'] else 'XX'}  {c['name']}: {c['detail']}"
                 for c in d["checks"]]
        lines.append("healthy" if d["healthy"] else "issues found")
        return "\n".join(lines)

    return Result(command="doctor", ok=healthy, data=data, human=human)


def cmd_info(ctx, args) -> Result:
    data = {
        "framework": FRAMEWORK_NAME,
        "version": __version__,
        "safety_boundary": boundary_summary(),
    }
    return Result(command="info", data=data,
                  human=lambda d: f"{d['framework']} {d['version']}\n"
                                  f"authorized research only; "
                                  f"{len(d['safety_boundary']['forbidden'])} "
                                  f"forbidden capabilities enforced")
