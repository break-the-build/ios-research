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

    def repair(self, data: bytes) -> bytes:
        """Best-effort normalization of an externally proposed input (#71).

        LLM proposals arrive as untrusted bytes; targets that understand their
        format may repair framing here so proposals reach deep parser paths
        instead of being rejected at the header. Default is identity.
        """
        return data

    def callgraph(self):
        """Optional static call graph for directed scheduling (#73).

        Returns ``{"nodes": [names], "edges": [[caller, callee], ...]}`` or
        ``None`` when the target cannot describe its structure. The framework
        uses it only to bias corpus-base selection toward a focus symbol.
        """
        return None

    def focus_symbol_for(self, data: bytes) -> str | None:
        """Optional: which call-graph symbol an input exercises (#73).

        Lets directed scheduling map corpus entries onto call-graph distances
        without instrumentation. Return a symbol name from ``callgraph()``,
        or ``None`` when unknown. Default is ``None``.
        """
        return None

    def coverage_features(self, data: bytes, result: ExecResult):
        """Return stable coverage feature IDs, or ``None`` when unavailable.

        An authorized target adapter may override this hook to expose measured
        coverage from its own instrumentation.  The framework treats IDs as
        opaque; it never derives them from crash diagnostics.  Returning
        ``None`` preserves the deterministic non-coverage fuzzing path.
        """
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
