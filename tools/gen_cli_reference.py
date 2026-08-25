#!/usr/bin/env python3
"""Regenerate docs/CLI_REFERENCE.md from the committed CLI schema.

The reference is a rendered view of `ios_research.schema.build_cli_schema()`
(the same document committed at docs/cli-schema.json), so it can never drift
from the schema without an explicit regeneration:

    python tools/gen_cli_reference.py            # writes docs/CLI_REFERENCE.md
    python tools/gen_cli_reference.py --check    # exit 1 if it would change

Output is byte-stable across runs: groups and subcommands are sorted, and no
timestamps are emitted.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from ios_research.schema import build_cli_schema  # noqa: E402

DEFAULT_OUT = REPO_ROOT / "docs" / "CLI_REFERENCE.md"

EXIT_CODE_DESC = {
    "OK": "OK",
    "ERROR": "ERROR",
    "USAGE": "USAGE",
    "NOT_FOUND": "NOT_FOUND",
    "VALIDATION": "VALIDATION",
    "SAFETY": "SAFETY",
    "INTERRUPTED": "INTERRUPTED",
    "STATE": "STATE",
}


def _render_arguments(args: dict) -> list[str]:
    lines: list[str] = []
    positionals = args.get("positionals", [])
    options = args.get("options", [])
    if positionals:
        lines.append("Positional arguments:")
        lines.append("")
        for p in positionals:
            req = "" if p.get("required") else " (optional)"
            help_text = p.get("help") or ""
            suffix = f" — {help_text}" if help_text else ""
            lines.append(f"- `{p['name']}`{req}{suffix}")
        if options:
            lines.append("")
    if options:
        lines.append("Options:")
        lines.append("")
        for o in options:
            flags = ", ".join(f"`{f}`" for f in o["flags"])
            req = " (required)" if o.get("required") else ""
            help_text = o.get("help") or ""
            suffix = f" — {help_text}" if help_text else ""
            lines.append(f"- {flags}{req}{suffix}")
    return lines


def render(schema: dict) -> str:
    out: list[str] = []
    out.append("# CLI Reference")
    out.append("")
    out.append(
        "Auto-generated from the framework schema (`ios-research agent inspect`); "
        f"framework version `{schema.get('version', '0.1.0')}`. Regenerate with "
        "`python tools/gen_cli_reference.py` after changing CLI registration."
    )
    out.append("")
    out.append("## Global flags")
    out.append("")
    for flag in schema["global_flags"]:
        out.append(f"- `{flag}`")
    out.append("")
    out.append("## JSON envelope")
    out.append("")
    out.append("Every command supports `--json` and returns:")
    out.append("")
    out.append("```json")
    out.append(
        '{ "ok": true, "command": "...", "data": {}, "messages": [],'
        ' "error": null, "exit_code": 0 }'
    )
    out.append("```")
    out.append("")
    out.append("## Exit codes")
    out.append("")
    for name, code in sorted(schema["exit_codes"].items(), key=lambda kv: kv[1]):
        out.append(f"- `{code}` — {EXIT_CODE_DESC.get(name, name)}")
    out.append("")
    out.append("## Commands")
    out.append("")

    commands = schema["commands"]
    for group in sorted(commands):
        entry = commands[group]
        subs = entry.get("subcommands")
        if not subs:
            out.append(f"### `ios-research {group}`")
            out.append("")
            out.extend(_render_arguments(entry.get("arguments", {})))
            out.append("")
            continue
        bare_args = entry.get("arguments", {})
        has_bare_positional = bool(bare_args.get("positionals"))
        if not has_bare_positional and not bare_args.get("options"):
            pass  # pure dispatch group; subcommands below are the full surface
        else:
            out.append(f"### `ios-research {group}`")
            out.append("")
            out.extend(_render_arguments(bare_args))
            out.append("")
        for sub in sorted(subs):
            out.append(f"### `ios-research {group} {sub}`")
            out.append("")
            out.extend(_render_arguments(subs[sub].get("arguments", {})))
            out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out", type=Path, default=DEFAULT_OUT, help="output path (default: %(default)s)"
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the regenerated reference differs from the file on disk",
    )
    ns = ap.parse_args()
    rendered = render(build_cli_schema())
    if ns.check:
        current = ns.out.read_text(encoding="utf-8") if ns.out.exists() else ""
        if current != rendered:
            print(f"{ns.out} is stale; run: python tools/gen_cli_reference.py", file=sys.stderr)
            return 1
        print(f"{ns.out} is up to date")
        return 0
    ns.out.write_text(rendered, encoding="utf-8")
    print(f"wrote {ns.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
