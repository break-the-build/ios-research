"""`ios-research suite` — versioned protocol/format suite catalog (#47)."""

from __future__ import annotations

from ..errors import ExitCode, InterruptedError_, NotFoundError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("suite", parents=[parent],
                              help="versioned protocol/format suite catalog "
                                   "(#47)")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_validate = sub.add_parser("validate", parents=[parent],
                                help="validate a suite directory")
    p_validate.add_argument("directory")
    p_validate.set_defaults(func=cmd_validate)

    p_install = sub.add_parser("install", parents=[parent],
                               help="install a suite into the workspace")
    p_install.add_argument("directory")
    p_install.set_defaults(func=cmd_install)

    p_list = sub.add_parser("list", parents=[parent],
                            help="list installed suites")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", parents=[parent], help="show a suite")
    p_show.add_argument("name")
    p_show.add_argument("--version", default=None)
    p_show.set_defaults(func=cmd_show)

    p_remove = sub.add_parser("remove", parents=[parent],
                              help="remove an installed suite")
    p_remove.add_argument("name")
    p_remove.add_argument("--version", required=True)
    p_remove.set_defaults(func=cmd_remove)

    p_bench = sub.add_parser("benchmark", parents=[parent],
                             help="deterministic bounded benchmark campaign")
    p_bench.add_argument("name")
    p_bench.add_argument("--target", required=True)
    p_bench.add_argument("--cases", type=int, default=50)
    p_bench.add_argument("--seed", type=int, default=0)
    p_bench.add_argument("--suite-version", dest="suite_version",
                         default=None)
    p_bench.set_defaults(func=cmd_benchmark)

    p_example = sub.add_parser("example", parents=[parent],
                               help="write the built-in example suite")
    p_example.add_argument("--out", required=True)
    p_example.set_defaults(func=cmd_example)

    p.set_defaults(func=cmd_list)


def cmd_validate(ctx, args) -> Result:
    from ..suites import validate_suite
    report = validate_suite(args.directory)
    if not report["valid"]:
        return Result(ok=False, command="suite validate",
                      data={"report": report},
                      error="suite validation failed: "
                            + "; ".join(report["problems"]),
                      exit_code=ExitCode.VALIDATION)
    return Result(command="suite validate", data={"report": report},
                  messages=[f"suite '{report['name']}' "
                            f"v{report['version']} is valid"])


def cmd_install(ctx, args) -> Result:
    from ..suites import SuiteCatalog
    installed = SuiteCatalog(ctx.workspace()).install(args.directory)
    return Result(command="suite install", data={"installed": installed},
                  messages=[f"installed {installed['name']} "
                            f"v{installed['version']} "
                            f"({installed['files_copied']} files)"])


def cmd_list(ctx, args) -> Result:
    from ..suites import SuiteCatalog
    suites = SuiteCatalog(ctx.workspace()).list()
    items = [{"name": s["name"], "version": s["version"],
              "description": s["description"], "license": s["license"]}
             for s in suites]
    return Result(command="suite list", data={"suites": items,
                                              "count": len(items)},
                  human=lambda d: "\n".join(
                      f"{s['name']} {s['version']} ({s['license']})"
                      for s in d["suites"]) or "(none)")


def cmd_show(ctx, args) -> Result:
    from ..suites import SuiteCatalog
    record = SuiteCatalog(ctx.workspace()).get(args.name,
                                               version=args.version)
    return Result(command="suite show", data={"suite": record})


def cmd_remove(ctx, args) -> Result:
    from ..suites import SuiteCatalog
    if not ctx.confirm(f"remove suite '{args.name}' "
                       f"version '{args.version}'"):
        raise InterruptedError_(
            "suite remove requires confirmation; re-run with --yes")
    removed = SuiteCatalog(ctx.workspace()).remove(args.name,
                                                   version=args.version)
    return Result(command="suite remove", data={"removed": removed},
                  messages=[f"removed {removed['name']} "
                            f"v{removed['version']}"])


def cmd_benchmark(ctx, args) -> Result:
    from ..suites import SuiteCatalog
    ws = ctx.workspace()
    catalog = SuiteCatalog(ws)
    suite = catalog.get(args.name, version=args.suite_version)
    stats = catalog.run_benchmark(suite["path"], args.target,
                                  cases=args.cases, seed=args.seed)
    return Result(command="suite benchmark", data={"benchmark": stats},
                  messages=[f"{stats['suite']['name']} "
                            f"v{stats['suite']['version']} on "
                            f"{stats['target']}: executed="
                            f"{stats['executed']} features="
                            f"{stats['unique_features']} outcomes="
                            f"{stats['outcomes']}"])


def cmd_example(ctx, args) -> Result:
    from ..suites import write_example_suite
    path = write_example_suite(args.out)
    from ..suites import MANIFEST_NAME
    if not (path / MANIFEST_NAME).is_file():  # pragma: no cover - defensive
        raise NotFoundError("example suite generation failed")
    return Result(command="suite example", data={"path": str(path)},
                  messages=[f"example suite written to {path}"])
