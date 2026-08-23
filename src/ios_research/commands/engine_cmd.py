"""`ios-research engine` — import artifacts from user-run external engines (#48).

Opt-in and local-only: the framework never launches an external fuzzer, never
changes host security settings, and never uploads anything. Researchers run
their own engines and hand over a manifest describing the artifacts.
"""

from __future__ import annotations

from ..errors import NotFoundError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("engine", parents=[parent],
                              help="import findings from external fuzzing "
                                   "engines (libFuzzer, AFL++, ...) you ran "
                                   "yourself")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_import = sub.add_parser("import", parents=[parent],
                              help="import a campaign manifest (JSON) plus "
                                   "its referenced artifact files")
    p_import.add_argument("manifest", help="path to the import manifest JSON")
    p_import.add_argument("--experiment-id", default=None,
                          help="attach imported findings to an existing "
                               "experiment")
    p_import.set_defaults(func=cmd_import)

    p_list = sub.add_parser("list", parents=[parent],
                            help="list prior engine imports")
    p_list.set_defaults(func=cmd_list)

    p.set_defaults(func=cmd_list)


def cmd_import(ctx, args) -> Result:
    from ..engine_import import EngineImporter
    importer = EngineImporter(ctx.workspace())
    summary = importer.import_manifest(
        args.manifest, experiment_id=args.experiment_id)
    return Result(
        command="engine import",
        data=summary,
        messages=[f"imported {len(summary['crashes'])} new crash(es), "
                  f"{len(summary['crash_deduped'])} duplicate(s) from "
                  f"{summary['engine']['name']}"])


def cmd_list(ctx, args) -> Result:
    from ..engine_import import EngineImporter
    imports = EngineImporter(ctx.workspace(required=False)).list_imports()
    if not imports:
        return Result(command="engine list", data={"imports": []},
                      messages=["no engine imports recorded"])
    return Result(command="engine list",
                  data={"imports": imports,
                        "count": len(imports)})
