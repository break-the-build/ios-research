"""Declarative metamorphic and property-based oracles for non-crash findings (#42).

An oracle declares, for one authorized target, a set of deterministic input
transformations and the relations expected to hold between the observations of
the original and transformed inputs (e.g. "appending accepted content to an
accepted input must not introduce a crash", "parsing stays under a time
budget").  Runs are seed-free and order-stable, so identical oracle specs and
corpora reproduce byte-identical observation data.

Honesty rules enforced here:
- Observations are behavioral evidence only; nothing in this module assigns or
  implies exploitability.
- Timeouts and nondeterministic observations are tracked explicitly as
  *inconclusive* and can never become findings.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Callable

from .errors import ValidationError
from .hashing import sha256_bytes
from .ids import make_id

ORACLE_SCHEMA_VERSION = 1
ORACLE_VERSION = "oracles/1"

MAX_BASES = 10_000
MAX_COUNTEREXAMPLE_BYTES = 1 << 20


# -- transformations -----------------------------------------------------------

def _t_identity(data: bytes) -> bytes:
    return data


def _t_append_self(data: bytes) -> bytes:
    return data + data


def _t_truncate_half(data: bytes) -> bytes:
    return data[: len(data) // 2]


def _t_flip_first_bit(data: bytes) -> bytes:
    if not data:
        return data
    out = bytearray(data)
    out[0] ^= 0x01
    return bytes(out)


def _t_zero_first_byte(data: bytes) -> bytes:
    if not data:
        return data
    return b"\x00" + data[1:]


TRANSFORMATIONS: dict[str, Callable[[bytes], bytes]] = {
    "identity": _t_identity,
    "append-self": _t_append_self,
    "truncate-half": _t_truncate_half,
    "flip-first-bit": _t_flip_first_bit,
    "zero-first-byte": _t_zero_first_byte,
}

RELATIONS = ("not_crash", "same_outcome", "bounded_time")

_SEVERITY = {
    "NORMAL->CRASH": "high",
    "outcome-change": "medium",
    "bounded_time": "low",
}


def validate_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Validate a declarative oracle spec; returns it unchanged on success."""
    if not isinstance(spec, dict):
        raise ValidationError("oracle spec must be a JSON object")
    if spec.get("schema_version") != ORACLE_SCHEMA_VERSION:
        raise ValidationError(
            f"oracle schema_version must be {ORACLE_SCHEMA_VERSION}")
    target = spec.get("target")
    if not isinstance(target, str) or not target.strip():
        raise ValidationError("oracle spec requires a 'target'")
    transforms = spec.get("transformations")
    if not isinstance(transforms, list) or not transforms:
        raise ValidationError(
            "oracle spec requires a non-empty 'transformations' array")
    unknown = [t for t in transforms if t not in TRANSFORMATIONS]
    if unknown:
        raise ValidationError(
            f"unknown transformations: {', '.join(sorted(set(unknown)))} "
            f"(known: {', '.join(TRANSFORMATIONS)})")
    relations = spec.get("relations")
    if not isinstance(relations, list) or not relations:
        raise ValidationError(
            "oracle spec requires a non-empty 'relations' array")
    unknown = [r for r in relations if r not in RELATIONS]
    if unknown:
        raise ValidationError(f"unknown relations: {', '.join(unknown)}")
    max_ms = spec.get("max_duration_ms", 1000)
    if not isinstance(max_ms, int) or isinstance(max_ms, bool) or max_ms <= 0:
        raise ValidationError("'max_duration_ms' must be a positive integer")
    seeds = spec.get("seeds_b64", [])
    if not isinstance(seeds, list) or any(not isinstance(s, str) for s in seeds):
        raise ValidationError("'seeds_b64' must be an array of strings")
    return spec


@dataclass
class Observation:
    """One recorded target observation (behavioral evidence only)."""

    outcome: str
    detail: str
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {"outcome": self.outcome, "detail": self.detail[:200],
                "duration_ms": self.duration_ms}


@dataclass
class OracleRun:
    """Result of evaluating an oracle spec against a set of base inputs."""

    id: str
    spec: dict[str, Any]
    bases_evaluated: int = 0
    cases_evaluated: int = 0
    violations: list[dict[str, Any]] = field(default_factory=list)
    inconclusive_timeouts: int = 0
    inconclusive_nondeterministic: int = 0
    transitions: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ORACLE_SCHEMA_VERSION,
            "kind": "oracle-run",
            "oracle_version": ORACLE_VERSION,
            "id": self.id,
            "spec": self.spec,
            "bases_evaluated": self.bases_evaluated,
            "cases_evaluated": self.cases_evaluated,
            "violation_count": len(self.violations),
            "violations": self.violations,
            "inconclusive": {
                "timeouts": self.inconclusive_timeouts,
                "nondeterministic": self.inconclusive_nondeterministic,
            },
            # Differential-vocabulary summary for cross-reporting.
            "transitions": self.transitions,
        }


class OracleEngine:
    """Evaluate declarative oracles against an authorized target."""

    def __init__(self, workspace):
        self.ws = workspace

    # -- observation ---------------------------------------------------------

    @staticmethod
    def _observe(target, data: bytes) -> Observation:
        result = target.execute(data)
        return Observation(outcome=result.outcome,
                           detail=result.detail[:200],
                           duration_ms=result.duration_ms)

    def _is_deterministic(self, target, data: bytes, first: Observation,
                          repeats: int = 2) -> bool:
        for _ in range(repeats):
            again = self._observe(target, data)
            if again.outcome != first.outcome:
                return False
        return True

    # -- evaluation ------------------------------------------------------------

    def run(self, spec: dict[str, Any], *, corpus_id: str | None = None,
            run_id: str | None = None) -> OracleRun:
        from .targets import create as create_target

        spec = validate_spec(dict(spec))
        target = create_target(spec["target"])
        bases = self._base_inputs(spec, corpus_id)
        if not bases:
            raise ValidationError(
                "oracle run needs inputs: provide 'seeds_b64' or 'corpus_id'")

        run = OracleRun(
            id=run_id or make_id("orl", spec["target"],
                                 sha256_bytes(_canonical(spec))[:12]),
            spec=spec)

        for base_sha, base_data in bases:
            base_obs = self._observe(target, base_data)
            if base_obs.outcome == "timeout":
                run.inconclusive_timeouts += 1
                continue
            if not self._is_deterministic(target, base_data, base_obs):
                run.inconclusive_nondeterministic += 1
                continue
            run.bases_evaluated += 1

            for transform_name in spec["transformations"]:
                transform = TRANSFORMATIONS[transform_name]
                mutated = transform(base_data)[:MAX_COUNTEREXAMPLE_BYTES]
                obs = self._observe(target, mutated)
                run.cases_evaluated += 1
                self._evaluate(run, spec, target, base_sha, base_data,
                               transform_name, mutated, base_obs, obs)
        self._persist(run)
        return run

    # -- relation checks -----------------------------------------------------

    def _evaluate(self, run: OracleRun, spec: dict[str, Any], target,
                  base_sha: str, base_data: bytes, transform_name: str,
                  mutated: bytes, base_obs: Observation,
                  obs: Observation) -> None:
        relations = spec["relations"]
        transition = f"{_label(base_obs.outcome)}->{_label(obs.outcome)}"

        if obs.outcome == "timeout":
            run.inconclusive_timeouts += 1
            return
        if not self._is_deterministic(target, mutated, obs):
            run.inconclusive_nondeterministic += 1
            return

        violated: list[str] = []
        if "not_crash" in relations and obs.outcome == "crash":
            violated.append("not_crash")
        if "same_outcome" in relations and obs.outcome != base_obs.outcome:
            violated.append("same_outcome")
        if "bounded_time" in relations \
                and obs.duration_ms > spec["max_duration_ms"]:
            violated.append("bounded_time")

        if transition not in ("NORMAL->NORMAL", "CRASH->CRASH") \
                and transition not in [t["transition"] for t in
                                       run.transitions]:
            run.transitions.append({
                "transition": transition,
                "transform": transform_name,
                "base_input_sha256": base_sha})

        if not violated:
            return
        if transition == "NORMAL->CRASH":
            severity_key = "NORMAL->CRASH"
        elif "bounded_time" in violated:
            severity_key = "bounded_time"
        else:
            severity_key = "outcome-change"

        minimized = self._minimize(target, spec, mutated, violated,
                                   base_obs)
        artifact = None
        from .artifacts import ArtifactStore
        store = ArtifactStore(self.ws)
        artifact = store.put(minimized, kind="oracle-counterexample")
        run.violations.append({
            "relation": "+".join(violated),
            "transform": transform_name,
            "base_input_sha256": base_sha,
            "counterexample_sha256": artifact.sha256,
            "original_size": len(mutated),
            "minimized_size": len(minimized),
            "transition": transition,
            "behavioral_severity": _SEVERITY[severity_key],
            "base_observation": base_obs.to_dict(),
            "observation": obs.to_dict(),
            "note": ("behavioral-severity only; this is NOT an "
                     "exploitability claim"),
        })

    def _minimize(self, target, spec: dict[str, Any], mutated: bytes,
                  violated: list[str],
                  base_obs: Observation | None = None) -> bytes:
        """Smallest variant that still violates any of ``violated``."""
        from .triage import ddmin

        def predicate(candidate: bytes) -> bool:
            try:
                obs = self._observe(target, candidate)
            except Exception:
                return False
            if "not_crash" in violated and obs.outcome == "crash":
                return True
            if base_obs is not None and "same_outcome" in violated \
                    and obs.outcome != base_obs.outcome \
                    and obs.outcome != "timeout":
                return True
            if "bounded_time" in violated \
                    and obs.duration_ms > spec["max_duration_ms"]:
                return True
            return False

        try:
            return ddmin(mutated, predicate)
        except Exception:
            return mutated

    # -- inputs / persistence -------------------------------------------------

    def _base_inputs(self, spec: dict[str, Any],
                     corpus_id: str | None) -> list[tuple[str, bytes]]:
        bases: list[tuple[str, bytes]] = []
        if corpus_id:
            from .corpus import CorpusStore
            corpus_store = CorpusStore(self.ws)
            corpus = corpus_store.get(corpus_id)
            for tc in corpus.testcases:
                bases.append((tc["sha256"],
                              corpus_store.read_bytes(corpus, tc["sha256"])))
                if len(bases) >= MAX_BASES:
                    break
        else:
            for i, encoded in enumerate(spec.get("seeds_b64", [])):
                try:
                    data = base64.b64decode(encoded, validate=True)
                except Exception as exc:
                    raise ValidationError(
                        f"seed #{i} is not valid base64: {exc}") from exc
                bases.append((sha256_bytes(data), data))
                if len(bases) >= MAX_BASES:
                    break
        return bases

    def _persist(self, run: OracleRun) -> None:
        self.ws.write_json(f"analysis/oracles/{run.id}.json", run.to_dict())

    # -- queries ---------------------------------------------------------------

    def get(self, run_id: str) -> dict[str, Any]:
        rel = f"analysis/oracles/{run_id}.json"
        if not self.ws.path(rel).exists():
            from .errors import NotFoundError
            raise NotFoundError(f"oracle run '{run_id}' not found")
        return self.ws.read_json(rel)

    def list_runs(self) -> list[dict[str, Any]]:
        out = []
        base = self.ws.dir("analysis") / "oracles"
        if base.is_dir():
            for path in sorted(base.glob("orl_*.json")):
                record = self.ws.read_json(
                    str(path.relative_to(self.ws.root)))
                out.append({"id": record["id"],
                            "target": record["spec"]["target"],
                            "violations": record["violation_count"],
                            "cases": record["cases_evaluated"]})
        return out


def _canonical(spec: dict[str, Any]) -> bytes:
    from .hashing import canonical_json
    return canonical_json(spec).encode("utf-8")


def _label(outcome: str) -> str:
    return "CRASH" if outcome == "crash" else \
        "TIMEOUT" if outcome == "timeout" else "NORMAL"
