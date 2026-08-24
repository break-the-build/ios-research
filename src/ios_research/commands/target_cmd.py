"""`ios-research target` — list, inspect, and manage research targets.

Format-specific target subcommands (e.g. ``target audio``) are attached by the
respective module (see phase 03). The custom-target SDK subcommands (#33:
``init``/``build``/``validate``/``register``) wrap user-declared local harnesses
as ``custom:<name>`` targets.
"""

from __future__ import annotations

from pathlib import Path

from ..errors import ValidationError
from ..output import Result

# Extra subparser installers contributed by other modules (e.g. audio).
_EXTRA_SUBCOMMANDS = []


def add_subcommand(installer) -> None:
    """Register an installer ``installer(sub, parent)`` for a target subcommand.

    Idempotent: the same installer is only registered once even if the CLI
    parser is rebuilt (e.g. across tests).
    """
    if installer not in _EXTRA_SUBCOMMANDS:
        _EXTRA_SUBCOMMANDS.append(installer)


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("target", parents=[parent],
                              help="manage research targets")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_list = sub.add_parser("list", parents=[parent], help="list known targets")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent], help="inspect one target")
    p_show.add_argument("target_id")
    p_show.set_defaults(func=cmd_show)

    p_init = sub.add_parser("init", parents=[parent],
                            help="write a custom-target template "
                                 "(c|cpp|swift|objc)")
    p_init.add_argument("--language", required=True,
                        choices=["c", "cpp", "swift", "objc"],
                        help="harness language for the template")
    p_init.add_argument("--dest", required=True,
                        help="fresh project directory to populate")
    p_init.add_argument("--name", default=None,
                        help="target name (default: --dest basename)")
    p_init.add_argument("--acknowledge-authorized-use", action="store_true",
                        dest="authorization_ack",
                        help="write authorization.ack=true; building and "
                             "running the target executes user-declared local "
                             "code on your own machine (see SECURITY.md)")
    p_init.set_defaults(func=cmd_init)

    p_build = sub.add_parser("build", parents=[parent],
                             help="build a custom target from its manifest")
    p_build.add_argument("manifest", help="path to target-manifest.json")
    p_build.add_argument("--timeout-s", type=float, default=300.0,
                         dest="timeout_s",
                         help="build budget in seconds (default 300)")
    p_build.set_defaults(func=cmd_build)

    p_validate = sub.add_parser("validate", parents=[parent],
                                help="validate a custom target end to end "
                                     "(seeds, crash parsing, reproducibility)")
    p_validate.add_argument("manifest", help="path to target-manifest.json")
    p_validate.add_argument("--build-timeout-s", type=float, default=300.0,
                            dest="build_timeout_s",
                            help="build budget in seconds (default 300)")
    p_validate.set_defaults(func=cmd_validate)

    p_register = sub.add_parser("register", parents=[parent],
                                help="register a manifest as custom:<name> "
                                     "(no code changes)")
    p_register.add_argument("manifest", help="path to target-manifest.json")
    p_register.set_defaults(func=cmd_register)

    for installer in _EXTRA_SUBCOMMANDS:
        installer(sub, parent)

    p.set_defaults(func=cmd_list)


def cmd_list(ctx, args) -> Result:
    from .. import targets
    items = targets.list_targets()
    return Result(command="target list", data={"targets": items, "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{x['id']:16} {x['kind']:8} {x['description']}"
                      for x in d["targets"]))


def cmd_show(ctx, args) -> Result:
    from .. import targets
    target = targets.create(args.target_id)
    return Result(command="target show", data={"target": target.describe()})


def cmd_init(ctx, args) -> Result:
    from ..targetsdk import init_template
    name = args.name or Path(args.dest).resolve().name
    manifest_path = init_template(args.language, args.dest, name,
                                  acknowledge=args.authorization_ack)
    return Result(
        command="target init",
        data={"language": args.language, "name": name,
              "manifest_path": str(manifest_path),
              "authorization_ack": bool(args.authorization_ack)},
        messages=[
            f"wrote {args.language} template to {args.dest}",
            ("authorization acknowledged in manifest"
             if args.authorization_ack else
             "review target-manifest.json and set authorization.ack=true to "
             "acknowledge authorized use"),
            f"next: ios-research target build {manifest_path}",
        ])


def cmd_build(ctx, args) -> Result:
    from ..targetsdk import build
    result = build(args.manifest, timeout_s=args.timeout_s)
    prov = result["provenance"]
    return Result(
        command="target build",
        data=result,
        messages=[f"built {result['output_path']} in {result['duration_ms']}ms",
                  f"compiler: {prov.get('compiler') or prov['command'][0]}"])


def cmd_validate(ctx, args) -> Result:
    from ..targetsdk import validate_target
    result = validate_target(args.manifest, build_timeout_s=args.build_timeout_s)
    markers = ", ".join(f"{m['marker']}={m['classification']}"
                        for m in result["crash_markers"])
    return Result(
        command="target validate",
        data=result,
        messages=[
            f"{result['target_id']}: seeds {result['seeds_accepted']}/"
            f"{result['seeds_total']} healthy",
            f"crash pipeline: {markers}",
            "reproducible" if result["reproducible"] else "NOT reproducible",
        ])


def cmd_register(ctx, args) -> Result:
    from ..targetsdk import register_manifest
    target_id = register_manifest(ctx.workspace(), args.manifest)
    from .. import targets
    if not targets.is_registered(target_id):  # pragma: no cover - defensive
        raise ValidationError(f"registration of '{target_id}' did not stick")
    return Result(
        command="target register",
        data={"target_id": target_id, "registered": True},
        messages=[f"registered {target_id} (runtime registry + workspace "
                  f"record)",
                  f"next: ios-research target show {target_id}"])
