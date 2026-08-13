"""Output rendering: a single result envelope rendered as human text or JSON.

Every command returns a :class:`Result`. The CLI renders it either as
human-readable text (default) or as a stable JSON envelope (``--json``). The
JSON envelope shape is part of the machine-readable contract.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

from .errors import ExitCode


@dataclass
class Result:
    """Outcome of a command.

    ``data`` is the machine-readable payload. ``human`` is an optional callable
    that renders human-friendly text; if absent a generic renderer is used.
    """

    ok: bool = True
    command: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    messages: list[str] = field(default_factory=list)
    error: str | None = None
    exit_code: int = ExitCode.OK
    human: Callable[[dict[str, Any]], str] | None = None

    def envelope(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "command": self.command,
            "data": self.data,
            "messages": list(self.messages),
            "error": self.error,
            "exit_code": self.exit_code,
        }


def render(result: Result, *, as_json: bool, quiet: bool, stream=None) -> None:
    stream = stream or sys.stdout
    if as_json:
        stream.write(json.dumps(result.envelope(), indent=2, sort_keys=True) + "\n")
        return
    if quiet:
        # In quiet mode emit only errors.
        if result.error:
            sys.stderr.write(result.error + "\n")
        return
    if result.error:
        sys.stderr.write(f"error: {result.error}\n")
    text = result.human(result.data) if result.human else _default_human(result)
    if text:
        stream.write(text + "\n")


def _default_human(result: Result) -> str:
    lines = list(result.messages)
    if result.data:
        for key, value in result.data.items():
            lines.append(f"{key}: {_fmt(value)}")
    return "\n".join(lines)


def _fmt(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)
