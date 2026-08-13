"""Core commands: version, doctor, info."""

from __future__ import annotations

import platform
import sys

from .. import __version__, FRAMEWORK_NAME
from ..output import Result
from ..safety import boundary_summary
from ..workspace import Workspace


def register(subparsers, parent) -> None:
    p_version = subparsers.add_parser("version", parents=[parent],
                                      help="print framework version")
    p_version.set_defaults(func=cmd_version)

    p_doctor = subparsers.add_parser("doctor", parents=[parent],
                                     help="check environment and workspace health")
    p_doctor.set_defaults(func=cmd_doctor)

    p_info = subparsers.add_parser("info", parents=[parent],
                                   help="print framework capabilities and safety boundary")
    p_info.set_defaults(func=cmd_info)


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
