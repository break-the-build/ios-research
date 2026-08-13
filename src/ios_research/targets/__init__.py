"""Research target abstraction and registry.

A *target* is a controlled, authorized thing under test that accepts an input
and reports a normalized outcome. Targets implement a generic lifecycle:

    prepare() -> execute(input) -> collect_result() -> cleanup()

All targets shipped with the framework are **mock** targets suitable for CI and
for research without physical iOS hardware. Real research-device targets can be
registered later behind the same interface (see docs/PROMPT-03-audio-module.md).
"""

from __future__ import annotations

from typing import Callable

from .base import ExecResult, Outcome, Target, Diagnostics
from .mock import MockParserTarget

# registry maps a target id (e.g. "mock:parser") to a factory callable.
_REGISTRY: dict[str, Callable[[], Target]] = {}


def register(target_id: str, factory: Callable[[], Target]) -> None:
    _REGISTRY[target_id] = factory


def create(target_id: str) -> Target:
    from ..errors import NotFoundError
    if target_id not in _REGISTRY:
        raise NotFoundError(
            f"unknown target '{target_id}'; known: {', '.join(sorted(_REGISTRY))}")
    return _REGISTRY[target_id]()


def list_targets() -> list[dict]:
    out = []
    for tid in sorted(_REGISTRY):
        target = _REGISTRY[tid]()
        out.append(target.describe())
    return out


def is_registered(target_id: str) -> bool:
    return target_id in _REGISTRY


# --- built-in mock targets -------------------------------------------------
register("mock:parser", lambda: MockParserTarget())

__all__ = [
    "ExecResult", "Outcome", "Target", "Diagnostics",
    "register", "create", "list_targets", "is_registered",
]
