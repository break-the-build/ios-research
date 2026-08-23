"""Metamorphic and property-based oracles for non-crash findings (#42).

Many security-relevant faults never crash: inconsistent parse results,
non-idempotent canonicalization, unbounded resource growth. This module defines
a declarative, local-only oracle interface:

    relation(transform(input)) must relate to reference(input) in a declared way.

* **Transformations** are deterministic, seeded rewrites of an authorized
  target's own input (line reorder/dedupe/trim, byte-chunk shuffle).
* **Relations** compare *observations* (normalized outcome/classification/
  timing) of reference vs. transformed runs — never internal state.
* Confirmed violations persist as findings with their transformed input,
  minimized counterexample, observation data, oracle version, and an explicit
  severity rationale that is **separated from any exploitability claim**.

Timeouts and nondeterministic observations are recorded explicitly and are
never silently promoted to findings: every candidate violation is re-checked;
inconsistent re-checks are marked ``nondeterministic`` instead.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable

from . import targets
from .clock import now_iso
from .errors import NotFoundError, ValidationError
from .hashing import sha256_bytes, sha256_text
from .ids import make_id
from .targets.base import Outcome
from .workspace import Workspace

ORACLE_SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 256 * 1024
MINIMIZE_ITERATIONS = 64


# --- observations -------------------------------------------------------------

@dataclass
class Observation:
    """What we can legitimately see about one execution."""

    outcome: str
    classification: str = ""
    signature: str = ""
    duration_ms: int = 0

    @property
    def key(self) -> str:
        return f"{self.outcome}:{self.classification}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def observe(target, data: bytes, *, deadline_s: float | None = None) -> Observation:
    result = target.execute(data)
    diag = result.diagnostics
    if deadline_s is not None and result.duration_ms > deadline_s * 1000:
        raise TimeoutError(f"observation exceeded {deadline_s}s budget")
    return Observation(
        outcome=result.outcome,
        classification=diag.classification_hint if diag else "",
        signature=diag.signature if diag else "",
        duration_ms=result.duration_ms,
    )


# --- transformations ----------------------------------------------------------

def _t_identity(data: bytes, rng) -> bytes:
    return data


def _t_sort_lines(data: bytes, rng) -> bytes:
    lines = data.split(b"\n")
    return b"\n".join(sorted(lines))


def _t_dedupe_lines(data: bytes, rng) -> bytes:
    seen: set[bytes] = set()
    out = []
    for line in data.split(b"\n"):
        if line not in seen:
            seen.add(line)
            out.append(line)
    return b"\n".join(out)


def _t_trim_lines(data: bytes, rng) -> bytes:
    return b"\n".join(line.strip() for line in data.split(b"\n"))


def _t_shuffle_chunks(data: bytes, rng) -> bytes:
    if len(data) < 8:
        return data
    size = max(2, len(data) // 4)
    chunks = [data[i:i + size] for i in range(0, len(data), size)]
    rng.shuffle(chunks)
    return b"".join(chunks)


TRANSFORMS: dict[str, Callable[[bytes, Any], bytes]] = {
    "identity": _t_identity,
    "sort_lines": _t_sort_lines,
    "dedupe_lines": _t_dedupe_lines,
    "trim_lines": _t_trim_lines,
    "shuffle_chunks": _t_shuffle_chunks,
}


def get_transform(name: str):
    try:
        return TRANSFORMS[name]
    except KeyError:
        raise ValidationError(
            f"unknown transform '{name}'; known: {', '.join(sorted(TRANSFORMS))}"
        ) from None


# --- relations ------------------------------------------------------------------

def _r_outcome_invariant(ref: Observation, other: Observation) -> str | None:
    """A semantically neutral rewrite must not change the parsed verdict."""
    if ref.key != other.key:
        return (f"observation changed under neutral rewrite: "
                f"{ref.key} -> {other.key}")
    return None


def _r_crash_signature_stable(ref: Observation, other: Observation) -> str | None:
    """When both executions crash, they must be the *same* defect."""
    if ref.outcome == Outcome.CRASH and other.outcome == Outcome.CRASH \
            and ref.signature != other.signature:
        return f"crash signature changed: {ref.signature} != {other.signature}"
    return None


def _r_time_bounded(bound_ms: int):
    def check(ref: Observation, other: Observation) -> str | None:
        if other.duration_ms > bound_ms:
            return (f"transformed execution took {other.duration_ms}ms "
                    f"(bound {bound_ms}ms)")
        return None
    return check


RELATIONS: dict[str, Callable[[Observation, Observation], str | None]] = {
    "outcome_invariant": _r_outcome_invariant,
    "crash_signature_stable": _r_crash_signature_stable,
}
RELATIONS["time_bounded_1000"] = _r_time_bounded(1000)

SEVERITY_RATIONALE = {
    "outcome_invariant":
        "inconsistent parsing of equivalent inputs can bypass validation",
    "crash_signature_stable":
        "transform-sensitive crash signatures complicate triage and dedup",
    "time_bounded_1000":
        "unbounded time growth on rewritten-but-equivalent input",
}


def get_relation(name: str):
    try:
        return RELATIONS[name]
    except KeyError:
        raise ValidationError(
            f"unknown relation '{name}'; known: {', '.join(sorted(RELATIONS))}"
        ) from None


# --- engine ---------------------------------------------------------------------

@dataclass
class OracleRunRecord:
    id: str
    target: str
    relations: list[str]
    transforms: list[str]
    created_at: str
    status: str = "created"
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OracleEngine:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def _rel(self, run_id: str) -> str:
        return f"findings/{run_id}/oracle.json"

    # persistence ----------------------------------------------------------
    def save(self, record: OracleRunRecord) -> None:
        self.ws.write_json(self._rel(record.id), record.to_dict())

    def get(self, run_id: str) -> OracleRunRecord:
        rel = self._rel(run_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"oracle run '{run_id}' not found")
        return OracleRunRecord(**self.ws.read_json(rel))

    def list(self) -> list[OracleRunRecord]:
        base = self.ws.dir("findings")
        out = []
        for manifest in sorted(base.glob("*/oracle.json")):
            out.append(OracleRunRecord(**self.ws.read_json(
                str(manifest.relative_to(self.ws.root)))))
        return out

    # execution --------------------------------------------------------------
    def run(self, *, target_id: str, inputs: list[bytes],
            relations: list[str] | None = None,
            transforms: list[str] | None = None,
            trials: int = 2,
            stage_deadline_s: float = 5.0) -> dict[str, Any]:
        if not targets.is_registered(target_id):
            raise NotFoundError(f"unknown target '{target_id}'")
        relations = list(relations or ["outcome_invariant"])
        transforms = list(transforms or ["sort_lines", "dedupe_lines",
                                         "trim_lines"])
        if trials < 2:
            raise ValidationError("trials must be >= 2 to detect "
                                  "nondeterminism")
        for blob in inputs:
            if len(blob) > MAX_INPUT_BYTES:
                raise ValidationError("input exceeds oracle size bound")

        target = targets.create(target_id)
        findings: list[dict[str, Any]] = []
        checked = 0

        for blob in inputs:
            ref_sha = sha256_bytes(blob)
            ref_obs = observe(target, blob)
            for t_name in transforms:
                transform = get_transform(t_name)
                seed = int(sha256_text(f"{t_name}|{ref_sha}"), 16) % (2 ** 31)
                transformed = transform(blob, _Rng(seed))
                if transformed == blob or not transformed:
                    continue
                new_obs = observe(target, transformed,
                                  deadline_s=stage_deadline_s)
                checked += 1
                for r_name in relations:
                    reason = get_relation(r_name)(ref_obs, new_obs)
                    if reason is None:
                        continue
                    findings.append(self._confirm_or_mark_nondeterministic(
                        target=target, target_id=target_id,
                        relation=r_name, transform=t_name,
                        reference=blob, first_reason=reason, trials=trials))

        record_id = make_id("oracle", target_id, str(len(inputs)),
                            ",".join(relations), ",".join(transforms),
                            now_iso())
        record = OracleRunRecord(
            id=record_id, target=target_id,
            relations=relations, transforms=transforms, created_at=now_iso())
        summary = {
            "schema_version": ORACLE_SCHEMA_VERSION,
            "inputs_checked": len(inputs),
            "pairs_evaluated": checked,
            "violations_confirmed": sum(
                1 for f in findings if f["status"] == "confirmed"),
            "nondeterministic": sum(
                1 for f in findings if f["status"] == "nondeterministic"),
            "findings": findings,
            "note": ("observations describe target behavior only; they carry "
                     "no exploitability claim"),
        }
        record.summary = summary
        record.status = "run"
        self.save(record)
        return {"run_id": record.id, **summary}

    def _confirm_or_mark_nondeterministic(
            self, *, target, target_id: str, relation: str, transform: str,
            reference: bytes, first_reason: str,
            trials: int) -> dict[str, Any]:
        """Re-check the violation; instability downgrades to nondeterministic."""
        statuses = []
        reasons = [first_reason]
        for trial in range(trials - 1):
            rng_seed = int(sha256_text(f"{relation}|{trial}"), 16) % (2 ** 31)
            again = get_transform(transform)(reference, _Rng(rng_seed))
            obs = observe(target, again)
            reason = get_relation(relation)(
                observe(target, reference), obs)
            statuses.append(reason is not None)
            if reason:
                reasons.append(reason)
        stable = all(statuses) and len(statuses) == trials - 1
        minimized, minimize_stats = self._minimize(
            target, reference, relation, transform)
        finding_id = make_id(
            "oraclefinding", target_id, relation, transform,
            sha256_bytes(reference))
        finding = {
            "id": finding_id,
            "schema_version": ORACLE_SCHEMA_VERSION,
            "target": target_id,
            "relation": relation,
            "transform": transform,
            "oracle_version": ORACLE_SCHEMA_VERSION,
            "status": "confirmed" if stable else "nondeterministic",
            "reasons": reasons[:4],
            "severity_rationale": SEVERITY_RATIONALE.get(
                relation, "declared relation violated"),
            "exploitability_claim": None,   # explicitly out of scope
            "reference_sha256": sha256_bytes(reference),
            "minimized": minimize_stats,
        }
        # Retain evidence locally: minimized counterexample when found.
        if minimized is not None:
            self.ws.write_bytes(f"findings/{finding_id}/minimized.bin",
                                minimized)
        return finding

    @staticmethod
    def _minimize(target, reference: bytes, relation: str, transform: str,
                  max_iterations: int = MINIMIZE_ITERATIONS
                  ) -> tuple["bytes | None", dict[str, Any]]:
        """Greedy line/chunk delta-debug preserving the violation.

        Returns ``(minimized_bytes_or_None, stats)``.
        """
        start = time.monotonic()

        def violates(candidate: bytes) -> bool:
            try:
                obs_ref = observe(target, reference)
                obs_new = observe(
                    target, get_transform(transform)(candidate, _Rng(1)))
            except TimeoutError:
                return True   # a timeout on smaller input still violates
            return get_relation(relation)(obs_ref, obs_new) is not None

        current = reference
        changed = True
        iterations = 0
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            parts = current.split(b"\n") if b"\n" in current else \
                [current[i:i + max(1, len(current) // 4)]
                 for i in range(0, len(current), max(1, len(current) // 4))]
            if len(parts) < 2:
                break
            half = len(parts) // 2
            for cand in (b"\n".join(parts[half:]),
                         b"\n".join(parts[:half]),
                         b"\n".join(parts[:half] + parts[half:])):
                if cand and cand != current and violates(cand):
                    current = cand
                    changed = True
                    break
        minimized = current if current != reference else None
        stats = {
            "data_sha256": sha256_bytes(minimized) if minimized else None,
            "iterations": iterations,
            "size_reduction": len(reference) - len(current),
            "elapsed_s": round(time.monotonic() - start, 3),
        }
        return minimized, stats


class _Rng:
    """Tiny deterministic RNG so oracle runs need no shared global state."""

    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFF or 1

    def _next(self) -> int:
        self.state = (1103515245 * self.state + 12345) & 0x7FFFFFFF
        return self.state

    def shuffle(self, items: list) -> None:
        for i in reversed(range(1, len(items))):
            j = self._next() % (i + 1)
            items[i], items[j] = items[j], items[i]
