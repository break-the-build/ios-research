"""Isolated execution entry point for generated fuzz-harness candidates (#124).

Generated harness code is *untrusted*: it comes from proposal files or model
output. Running it inside the framework process would hand that code access to
framework state and the researcher's environment. This module turns the process
itself into the disposable sandbox: :mod:`ios_research.harness` spawns
``python -m ios_research.harness_runner`` as a short-lived child, feeds it the
candidate over stdin, and reads back a small JSON verdict.

This reduces blast radius (crashes, exits, state corruption cannot reach the
parent) but is **not** a security sandbox: the child runs with the researcher's
privileges. Proposals remain trusted-input artifacts — see SECURITY.md.
"""

from __future__ import annotations

import json
import sys


def _run_candidate(code: str, target_id: str) -> dict:
    """Execute one candidate exactly once and return the verdict dict."""
    from .targets.base import Outcome
    namespace: dict = {"__name__": "generated_harness"}
    try:
        exec(compile(code, "<generated-harness>", "exec"), namespace)
        driver = namespace.get("fuzz")
        if not callable(driver):
            return {"ok": False, "error": "no callable 'fuzz' after execution"}
        from . import targets
        target = targets.create(target_id)
        seeds = target.seeds()
        sample = seeds[0] if seeds else b"MOCK\x01\x01\x00\x02ok"
        outcome = driver(sample)
        return {"ok": outcome in Outcome.ALL, "outcome": outcome}
    except Exception as exc:  # defensive: generated code is untrusted
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def main(argv: list[str] | None = None) -> int:
    try:
        request = json.loads(sys.stdin.read())
        code = request["code"]
        target_id = request["target_id"]
        if not isinstance(code, str) or not isinstance(target_id, str):
            raise ValueError("bad request shape")
    except Exception as exc:
        json.dump({"ok": False,
                   "error": f"runner input error: {type(exc).__name__}: {exc}"},
                  sys.stdout)
        return 2
    json.dump(_run_candidate(code, target_id), sys.stdout)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess
    raise SystemExit(main())
