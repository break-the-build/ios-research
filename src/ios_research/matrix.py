"""Device/OS/build matrix reproduction with reliability scoring (#37).

Apple's bounty guidelines require findings to reproduce on current public
software/hardware with standard configurations. This module runs bounded,
repeatable confirmation trials of one input across a declared matrix of
authorized cells — (device, hardware model, OS name/version, build, plus
explicit configuration annotations such as Lockdown Mode or beta state) — and
scores each cell:

* reproduction rate (crashes / trials),
* signature stability (how often the *same* diagnostic signature recurs),
* time-to-crash (duration of the first crashing trial).

It distinguishes repeatable findings from one-off events, records
first/last-affected versions **only across tested cells**, and never infers
support (or non-support) for an untested device or build. Lockdown/beta state
is recorded solely as researcher-provided configuration evidence.

Missing device, OS-version, or build provenance fails validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from . import targets
from .clock import now_iso
from .errors import NotFoundError, ValidationError
from .hashing import sha256_bytes, sha256_text
from .ids import make_id
from .targets.base import Outcome
from .workspace import Workspace

SCHEMA_VERSION = 1
MAX_TRIALS = 100
REQUIRED_CELL_FIELDS = ("device_id", "model", "os_name", "os_version", "build")


@dataclass
class MatrixCell:
    """One authorized (device, build, configuration) combination."""

    device_id: str
    model: str
    os_name: str
    os_version: str
    build: str
    app_version: str = ""
    framework_version: str = ""
    lockdown_mode: bool | None = None     # researcher-provided evidence only
    beta: bool | None = None              # researcher-provided evidence only
    annotations: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return sha256_text(self.canonical)[:16]

    @property
    def canonical(self) -> str:
        return "|".join(str(part) for part in (
            self.device_id, self.model, self.os_name, self.os_version,
            self.build, self.app_version, self.framework_version,
            self.lockdown_mode, self.beta))

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["key"] = self.key
        return out


@dataclass
class MatrixRun:
    id: str
    target: str
    input_sha256: str
    trials_per_cell: int
    seed: int
    cells: list[dict[str, Any]]
    created_at: str
    status: str = "created"
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_cells(specs: list[dict[str, Any]]) -> list[MatrixCell]:
    """Validate cell specs; missing provenance fails validation."""
    if not specs:
        raise ValidationError("matrix requires at least one cell")
    cells: list[MatrixCell] = []
    seen_keys: set[str] = set()
    for index, spec in enumerate(specs):
        if not isinstance(spec, dict):
            raise ValidationError(f"cell {index} must be an object")
        missing = [name for name in REQUIRED_CELL_FIELDS
                   if not str(spec.get(name, "")).strip()]
        if missing:
            raise ValidationError(
                f"cell {index} missing required provenance: "
                f"{', '.join(missing)}")
        unknown = set(spec) - set(MatrixCell.__dataclass_fields__) - {"key"}
        if unknown:
            raise ValidationError(
                f"cell {index} has unsupported fields: {', '.join(sorted(unknown))}")
        cell = MatrixCell(
            device_id=str(spec["device_id"]),
            model=str(spec["model"]),
            os_name=str(spec["os_name"]),
            os_version=str(spec["os_version"]),
            build=str(spec["build"]),
            app_version=str(spec.get("app_version", "")),
            framework_version=str(spec.get("framework_version", "")),
            lockdown_mode=spec.get("lockdown_mode"),
            beta=spec.get("beta"),
            annotations=dict(spec.get("annotations") or {}),
        )
        if cell.key in seen_keys:
            continue  # duplicate canonical cell: keep one
        seen_keys.add(cell.key)
        cells.append(cell)
    return cells


class ReproductionMatrixEngine:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def _rel(self, matrix_id: str) -> str:
        return f"matrices/{matrix_id}/matrix.json"

    def _results_rel(self, matrix_id: str) -> str:
        return f"matrices/{matrix_id}/results.json"

    # lifecycle -----------------------------------------------------------
    def create(self, *, target: str, input_bytes: bytes, trials: int,
               seed: int, cells: list[dict[str, Any]]) -> MatrixRun:
        if not targets.is_registered(target):
            raise NotFoundError(f"unknown target '{target}'")
        if not 1 <= trials <= MAX_TRIALS:
            raise ValidationError(
                f"trials must be between 1 and {MAX_TRIALS}")
        parsed = parse_cells(cells)
        matrix_id = make_id("matrix", target, sha256_bytes(input_bytes),
                            str(seed), str(trials),
                            *[cell.key for cell in parsed])
        run = MatrixRun(
            id=matrix_id, target=target,
            input_sha256=sha256_bytes(input_bytes), trials_per_cell=trials,
            seed=seed,
            cells=[cell.to_dict() for cell in parsed],
            created_at=now_iso())
        self.ws.write_json(self._rel(matrix_id), run.to_dict())
        # Persist the confirmation input beside the matrix for replay.
        self.ws.write_bytes(f"matrices/{matrix_id}/input.bin", input_bytes)
        return run

    def get(self, matrix_id: str) -> MatrixRun:
        rel = self._rel(matrix_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"matrix '{matrix_id}' not found")
        return MatrixRun(**self.ws.read_json(rel))

    def list(self) -> list[MatrixRun]:
        base = self.ws.dir("matrices")
        out = []
        for manifest in sorted(base.glob("*/matrix.json")):
            out.append(MatrixRun(**self.ws.read_json(
                str(manifest.relative_to(self.ws.root)))))
        return out

    # execution -----------------------------------------------------------
    def run(self, run: MatrixRun) -> dict[str, Any]:
        """Execute bounded trials per cell; deterministic for mock targets."""
        input_bytes = self.ws.read_bytes(f"matrices/{run.id}/input.bin")

        cell_results: list[dict[str, Any]] = []
        for cell_dict in run.cells:
            cell = MatrixCell(**{k: v for k, v in cell_dict.items()
                                 if k != "key"})
            cell_results.append(self._run_cell(run, cell, input_bytes))

        summary = {
            "schema_version": SCHEMA_VERSION,
            "cells_run": len(cell_results),
            # Promotion to "reproducible" requires BOTH repeated crashes AND
            # signature stability; an unstable high-rate crash stays a
            # one-off so flaky findings are never silently promoted (#37).
            "reproducible_cells": sum(
                1 for c in cell_results
                if c["reproduction_rate"] >= 0.5 and c["stable"]),
            "one_off_cells": sum(
                1 for c in cell_results
                if 0 < c["reproduction_rate"] and not (
                    c["reproduction_rate"] >= 0.5 and c["stable"])),
            "non_reproducing_cells": sum(
                1 for c in cell_results if c["reproduction_rate"] == 0),
            "per_cell": cell_results,
            "affected_versions": self._affected_versions(cell_results),
            "limitations": [
                "Results apply only to the declared, tested cells; no support "
                "is inferred for any untested device, OS version, or build.",
                "Lockdown Mode / beta state is recorded as researcher-provided "
                "configuration evidence, not detected by this framework.",
                "Reliability scores describe repetition of the recorded "
                "finding; they do not assert exploitability.",
            ],
        }
        self.ws.write_json(self._results_rel(run.id), {
            "matrix_id": run.id, "summary": summary})
        run.status = "run"
        run.summary = {"cells_run": summary["cells_run"],
                       "reproducible_cells": summary["reproducible_cells"]}
        self.ws.write_json(self._rel(run.id), run.to_dict())
        return summary

    def _run_cell(self, run: MatrixRun, cell: MatrixCell,
                  input_bytes: bytes) -> dict[str, Any]:
        target = targets.create(run.target)
        crashes = 0
        signatures: list[str] = []
        first_crash_ms: int | None = None
        durations: list[int] = []
        outcome_counts: dict[str, int] = {}

        for _trial in range(run.trials_per_cell):
            result = target.execute(input_bytes)
            outcome_counts[result.outcome] = \
                outcome_counts.get(result.outcome, 0) + 1
            durations.append(result.duration_ms)
            if result.outcome == Outcome.CRASH:
                crashes += 1
                signature = result.diagnostics.signature \
                    if result.diagnostics else "sig_none"
                signatures.append(signature)
                if first_crash_ms is None:
                    first_crash_ms = result.duration_ms

        dominant = max(signatures, key=signatures.count) if signatures else ""
        stability = (signatures.count(dominant) / len(signatures)
                     if signatures else 0.0)
        return {
            "cell": cell.to_dict(),
            "trials": run.trials_per_cell,
            "crashes": crashes,
            "reproduction_rate": round(crashes / run.trials_per_cell, 4),
            "signature_stability": round(stability, 4),
            "dominant_signature": dominant,
            "stable": bool(stability >= 0.99 and crashes == run.trials_per_cell),
            "time_to_crash_ms": first_crash_ms,
            "outcomes": outcome_counts,
        }

    @staticmethod
    def _affected_versions(cell_results: list[dict[str, Any]],
                           threshold: float = 0.5) -> dict[str, Any]:
        """First/last affected among *tested* OS versions (no inference)."""
        by_version: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        for result in cell_results:
            version = result["cell"]["os_version"]
            if version not in by_version:
                by_version[version] = {
                    "cells": 0, "best_reproduction_rate": 0.0}
                order.append(version)
            entry = by_version[version]
            entry["cells"] += 1
            entry["best_reproduction_rate"] = max(
                entry["best_reproduction_rate"], result["reproduction_rate"])
        affected = [v for v in order
                    if by_version[v]["best_reproduction_rate"] >= threshold]
        return {
            "tested_versions": [
                {"os_version": v, **by_version[v]} for v in order],
            "first_affected": affected[0] if affected else None,
            "last_affected": affected[-1] if affected else None,
            "note": ("determined only across tested cells in declaration "
                     "order; boundary outside the matrix is unknown"),
        }

    # access ----------------------------------------------------------------
    def results(self, matrix_id: str) -> dict[str, Any]:
        rel = self._results_rel(matrix_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"matrix '{matrix_id}' has not been run")
        return self.ws.read_json(rel)["summary"]
