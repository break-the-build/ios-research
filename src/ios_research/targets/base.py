"""Core target interface and normalized result/diagnostic types."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


class Outcome:
    """Normalized execution outcomes (stable strings used in JSON)."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    CRASH = "crash"
    ABNORMAL = "abnormal"

    ALL = (ACCEPTED, REJECTED, TIMEOUT, CRASH, ABNORMAL)


@dataclass
class Diagnostics:
    """Normalized crash diagnostics.

    All fields are derived deterministically from the triggering input so that
    the same input always yields the same diagnostics (reproducibility).
    """

    exception_type: str = ""
    signal: str = ""
    faulting_address: str = ""
    instruction_address: str = ""
    access_type: str = "none"          # read | write | exec | none
    registers: dict[str, str] = field(default_factory=dict)
    stack_trace: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    thread: dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    classification_hint: str = "UNKNOWN"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExecResult:
    outcome: str = Outcome.ACCEPTED
    detail: str = ""
    duration_ms: int = 0
    diagnostics: Diagnostics | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "detail": self.detail,
            "duration_ms": self.duration_ms,
            "diagnostics": self.diagnostics.to_dict() if self.diagnostics else None,
        }


class Target:
    """Generic research-target interface.

    Concrete targets override :meth:`_run`. The public :meth:`execute` drives the
    full ``prepare -> run -> collect -> cleanup`` lifecycle.
    """

    target_id: str = "abstract"
    kind: str = "abstract"
    description: str = "abstract target"
    formats: tuple[str, ...] = ()
    mock: bool = True

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.target_id,
            "kind": self.kind,
            "description": self.description,
            "formats": list(self.formats),
            "mock": self.mock,
        }

    # optional format hooks ----------------------------------------------
    def seeds(self) -> list[bytes]:
        """Return valid base inputs used to seed a default corpus."""
        return []

    def structure_mutate(self, data: bytes, rng) -> "bytes | None":
        """Format-aware mutation. Return None to fall back to generic mutation."""
        return None

    # lifecycle -----------------------------------------------------------
    def prepare(self) -> None:  # pragma: no cover - trivial default
        pass

    def cleanup(self) -> None:  # pragma: no cover - trivial default
        pass

    def _run(self, data: bytes) -> ExecResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def execute(self, data: bytes) -> ExecResult:
        self.prepare()
        try:
            result = self._run(data)
        finally:
            self.cleanup()
        return result
