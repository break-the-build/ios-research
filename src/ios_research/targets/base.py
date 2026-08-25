from __future__ import annotations

import abc
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional


@dataclasses.dataclass
class Diagnostics:
    """Normalized crash diagnostics."""
    exception_type: str
    exception_message: str
    faulting_address: int
    registers: dict[str, int]
    stack_trace: list[dict[str, Any]]
    modules: list[dict[str, Any]]
    raw_output: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Diagnostics:
        return cls(**data)

    def signature(self) -> str:
        """Generate a deterministic crash signature for deduplication."""
        # Use faulting address + top 3 stack frames for signature
        key_parts = [
            self.exception_type,
            hex(self.faulting_address),
            "->".join(f.get("function", "?") for f in self.stack_trace[:3]),
        ]
        return hashlib.sha256("|".join(key_parts).encode()).hexdigest()[:16]


@dataclasses.dataclass
class ExecResult:
    """Result of executing a test case."""
    crashed: bool
    diagnostics: Optional[Diagnostics]
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "crashed": self.crashed,
            "diagnostics": self.diagnostics.to_dict() if self.diagnostics else None,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecResult:
        diag = data.get("diagnostics")
        return cls(
            crashed=data["crashed"],
            diagnostics=Diagnostics.from_dict(diag) if diag else None,
            stdout=data["stdout"],
            stderr=data["stderr"],
            exit_code=data["exit_code"],
            duration_ms=data["duration_ms"],
        )


class Target(abc.ABC):
    """Base class for fuzzing targets."""

    mock: bool = True
    name: str = "base"
    description: str = "Base target"

    def __init__(self, workspace: Path, config: dict[str, Any] | None = None):
        self.workspace = workspace
        self.config = config or {}
        self.corpus_dir = workspace / "corpus" / self.name
        self.crashes_dir = workspace / "crashes" / self.name
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

    @abc.abstractmethod
    def prepare(self) -> None:
        """Set up the target (compile, download, etc.)."""
        pass

    @abc.abstractmethod
    def _run(self, data: bytes) -> ExecResult:
        """Execute one test case, return result."""
        pass

    def execute(self, data: bytes) -> ExecResult:
        """Public execute with timing."""
        start = time.perf_counter()
        result = self._run(data)
        result.duration_ms = int((time.perf_counter() - start) * 1000)
        return result

    def cleanup(self) -> None:
        """Clean up resources."""
        pass

    def get_corpus(self) -> list[bytes]:
        """Get seed corpus."""
        return []

    def save_crash(self, crash_id: str, data: bytes, result: ExecResult) -> Path:
        """Save crash input and diagnostics."""
        crash_dir = self.crashes_dir / crash_id
        crash_dir.mkdir(parents=True, exist_ok=True)
        (crash_dir / "input").write_bytes(data)
        (crash_dir / "result.json").write_text(json.dumps(result.to_dict(), indent=2))
        return crash_dir
