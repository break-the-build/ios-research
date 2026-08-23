"""Metamorphic and property-based oracles for non-crash findings (#42)."""

from __future__ import annotations

import base64
import json

import pytest

from ios_research.errors import ValidationError
from ios_research.oracles import (
    TRANSFORMATIONS, OracleEngine, validate_spec,
)
from ios_research.targets.base import ExecResult, Outcome, Target


class BoundedTarget(Target):
    """Accepts inputs up to a hard length boundary, then 'overflows'."""

    id = "test:bounded"

    def execute(self, data: bytes) -> ExecResult:
        if len(data) > 32:
            return ExecResult(outcome=Outcome.CRASH, detail="overflow",
                              diagnostics=None)
        return ExecResult(outcome=Outcome.ACCEPTED, detail="ok")


class PolicyTarget(Target):
    """Never crashes; long inputs are rejected by policy (accepted→rejected)."""

    id = "test:policy"

    def execute(self, data: bytes) -> ExecResult:
        if len(data) > 16:
            return ExecResult(outcome=Outcome.REJECTED, detail="too long")
        return ExecResult(outcome=Outcome.ACCEPTED, detail="ok")


class SlowTarget(Target):
    """Always accepts but reports durations proportional to input size."""

    id = "test:slow"

    def execute(self, data: bytes) -> ExecResult:
        return ExecResult(outcome=Outcome.ACCEPTED, detail="ok",
                          duration_ms=len(data))


@pytest.fixture(autouse=True)
def _register(monkeypatch):
    from ios_research.targets import _REGISTRY
    monkeypatch.setitem(_REGISTRY, BoundedTarget.id, BoundedTarget)
    monkeypatch.setitem(_REGISTRY, PolicyTarget.id, PolicyTarget)
    monkeypatch.setitem(_REGISTRY, SlowTarget.id, SlowTarget)


SPEC = {
    "schema_version": 1,
    "target": "test:bounded",
    "transformations": ["append-self", "flip-first-bit"],
    "relations": ["not_crash", "same_outcome"],
    "max_duration_ms": 1000,
}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# --- validation ------------------------------------------------------------------

@pytest.mark.parametrize("mutation", [
    lambda s: s.update(schema_version=2),
    lambda s: s.update(target=""),
    lambda s: s.update(transformations=["nope"]),
    lambda s: s.update(transformations=[]),
    lambda s: s.update(relations=["psychic"]),
    lambda s: s.update(max_duration_ms=-1),
])
def test_invalid_specs_are_rejected(mutation):
    spec = json.loads(json.dumps(SPEC))
    mutation(spec)
    with pytest.raises(ValidationError):
        validate_spec(spec)


def test_run_requires_inputs():
    engine = OracleEngine.__new__(OracleEngine)   # no workspace needed here
    with pytest.raises(ValidationError, match="inputs"):
        engine.run(dict(SPEC))


# --- discovery + minimization of a non-crashing invariant violation ---------------

def test_oracle_discovers_and_minimizes_crash_introducing_transformation(
        workspace):
    engine = OracleEngine(workspace)
    run = engine.run({**SPEC, "seeds_b64": [_b64(b"A" * 20)]})
    assert run.cases_evaluated == 2            # 1 seed x 2 transformations
    assert len(run.violations) >= 1

    violation = run.violations[0]
    # 'append-self' doubles a clean input past the target's hard boundary.
    assert violation["relation"].startswith("not_crash")
    assert violation["behavioral_severity"] == "high"
    assert violation["transition"] == "NORMAL->CRASH"
    assert violation["minimized_size"] < violation["original_size"]
    assert "NOT an exploitability claim" in violation["note"]
    # Counterexample artifact is retained content-addressed.
    stored = workspace.path("artifacts",
                            violation["counterexample_sha256"][:2],
                            violation["counterexample_sha256"] + ".bin")
    assert stored.is_file()
    assert run.transitions and \
        any(t["transition"] == "NORMAL->CRASH" for t in run.transitions)


def test_same_outcome_relation_flags_silent_behavior_change(workspace):
    engine = OracleEngine(workspace)
    run = engine.run({
        **SPEC,
        "target": "test:policy",
        "relations": ["same_outcome"],
        "seeds_b64": [_b64(b"A" * 10)],       # accepted; append-self -> rejected
        "transformations": ["append-self"],
    })
    assert run.violations and \
        run.violations[0]["relation"] == "same_outcome"
    assert run.violations[0]["behavioral_severity"] == "medium"


def test_bounded_time_violation_is_low_severity(workspace):
    engine = OracleEngine(workspace)
    run = engine.run({
        **SPEC,
        "target": "test:slow",
        "relations": ["bounded_time"],
        "max_duration_ms": 10,
        "seeds_b64": [_b64(b"B" * 50)],
        "transformations": ["append-self"],
    })
    assert run.violations, "100-byte input takes ~100ms > budget"
    assert run.violations[0]["behavioral_severity"] == "low"


# --- honesty: timeouts & nondeterminism stay inconclusive --------------------------

class FlakyTarget(BoundedTarget):
    id = "test:flaky"

    def __init__(self):
        self.calls = 0

    def execute(self, data: bytes) -> ExecResult:
        self.calls += 1
        outcome = Outcome.CRASH if self.calls % 2 == 0 else Outcome.ACCEPTED
        return ExecResult(outcome=outcome, detail="nondeterministic")


def test_nondeterministic_bases_are_inconclusive_not_findings(
        workspace, monkeypatch):
    from ios_research.targets import _REGISTRY
    counter = {"n": 0}

    class CountingFlaky(FlakyTarget):
        def execute(self, data):  # noqa: D102
            counter["n"] += 1
            return ExecResult(outcome=(Outcome.CRASH if counter["n"] % 2
                                       else Outcome.ACCEPTED),
                              detail="nondeterministic")

    monkeypatch.setitem(_REGISTRY, "test:flaky", CountingFlaky)
    engine = OracleEngine(workspace)
    run = engine.run({**SPEC, "target": "test:flaky",
                      "seeds_b64": [_b64(b"AAAA")]})
    assert run.bases_evaluated == 0
    assert run.inconclusive_nondeterministic >= 1
    assert len(run.violations) == 0


def test_timeout_observations_are_tracked_not_promoted(workspace, monkeypatch):
    from ios_research.targets import _REGISTRY

    class TimeoutBase(BoundedTarget):
        id = "test:tbase"

        def execute(self, data):
            return ExecResult(outcome=Outcome.TIMEOUT, detail="stuck")

    monkeypatch.setitem(_REGISTRY, TimeoutBase.id, TimeoutBase)
    engine = OracleEngine(workspace)
    run = engine.run({**SPEC, "target": "test:tbase",
                      "seeds_b64": [_b64(b"AAAA")]})
    assert run.inconclusive_timeouts == 1
    assert len(run.violations) == 0
    assert run.cases_evaluated == 0


# --- reproducibility ---------------------------------------------------------------

def test_runs_are_reproducible_and_persisted(workspace):
    seeds = [_b64(b"AAAA" * 4), _b64(b"C" * 12)]
    first = OracleEngine(workspace).run({**SPEC, "seeds_b64": seeds})
    second = OracleEngine(workspace).run({**SPEC, "seeds_b64": seeds})
    assert first.to_dict() == second.to_dict()
    stored = workspace.path("analysis", "oracles", f"{first.id}.json")
    assert stored.is_file()
    assert json.loads(stored.read_text())["id"] == first.id


# --- CLI envelope ----------------------------------------------------------------

def test_oracle_cli_roundtrip(workspace, tmp_path, capsys):
    from ios_research.cli import main
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(
        {**SPEC, "seeds_b64": [_b64(b"A" * 20)]}), encoding="utf-8")
    ws = ["--workspace", str(workspace.root)]

    code = main([*ws, "oracle", "run", str(spec_path), "--json"])
    env = json.loads(capsys.readouterr().out)
    assert code == 0 and env["ok"] is True
    assert env["data"]["violation_count"] >= 1
    run_id = env["data"]["id"]

    code = main([*ws, "oracle", "show", run_id, "--json"])
    assert json.loads(capsys.readouterr().out)["data"]["id"] == run_id

    code = main([*ws, "oracle", "list", "--json"])
    env = json.loads(capsys.readouterr().out)
    assert code == 0 and env["data"]["count"] == 1
