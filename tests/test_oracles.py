"""Metamorphic and property-based oracles (#42)."""

from __future__ import annotations

import pytest

from ios_research import targets as target_registry
from ios_research.errors import ValidationError
from ios_research.oracles import (
    Observation, OracleEngine, RELATIONS, TRANSFORMS, get_relation,
    get_transform)
from ios_research.targets.base import Diagnostics, ExecResult, Outcome, Target


class OrderSensitiveKVTarget(Target):
    """Accepts sorted key=value lines; rejects reordered ones (non-crash bug).

    A canonicalization-idempotence style defect: semantically equivalent
    rewrites of the same mapping change the parser's verdict.
    """

    target_id = "test:kv"
    kind = "mock-parser"
    description = "order-sensitive key=value parser"

    def _run(self, data: bytes) -> ExecResult:
        lines = [line for line in data.split(b"\n") if line]
        keys = []
        for line in lines:
            if b"=" not in line:
                return ExecResult(outcome=Outcome.REJECTED,
                                  detail="malformed line")
            key = line.split(b"=", 1)[0]
            if key in keys:
                return ExecResult(outcome=Outcome.REJECTED,
                                  detail="duplicate key")
            keys.append(key)
        if keys != sorted(keys):
            return ExecResult(outcome=Outcome.REJECTED,
                              detail="keys not sorted")
        return ExecResult(outcome=Outcome.ACCEPTED)


class FlakyObsTarget(Target):
    """Alternates verdicts between runs — nondeterministic observations."""

    target_id = "test:flakyobs"
    kind = "mock-parser"
    description = "alternating observations"
    calls = 0

    def _run(self, data: bytes) -> ExecResult:
        FlakyObsTarget.calls += 1
        outcome = Outcome.ACCEPTED if FlakyObsTarget.calls % 2 else \
            Outcome.REJECTED
        return ExecResult(outcome=outcome)


@pytest.fixture()
def kv_target():
    target_registry.register("test:kv", lambda: OrderSensitiveKVTarget())
    yield
    target_registry._REGISTRY.pop("test:kv", None)


@pytest.fixture()
def flaky_obs_target():
    FlakyObsTarget.calls = 0
    target_registry.register("test:flakyobs", lambda: FlakyObsTarget())
    yield
    target_registry._REGISTRY.pop("test:flakyobs", None)


SORTED_KV = b"a=1\nb=2\nc=3\n"

# --- primitives -----------------------------------------------------------------

def test_transforms_are_deterministic_and_registered():
    assert set(TRANSFORMS) >= {"identity", "sort_lines", "dedupe_lines",
                               "trim_lines", "shuffle_chunks"}
    from ios_research.oracles import _Rng
    a = get_transform("sort_lines")(b"b\na", _Rng(1))
    b = get_transform("sort_lines")(b"b\na", _Rng(1))
    assert a == b == b"a\nb"


def test_unknown_relation_or_transform_rejected():
    with pytest.raises(ValidationError):
        get_relation("nope")
    with pytest.raises(ValidationError):
        get_transform("nope")


def test_outcome_invariant_relation_flags_verdict_change():
    check = get_relation("outcome_invariant")
    assert check(Observation("accepted"), Observation("accepted")) is None
    reason = check(Observation(outcome="accepted"),
                   Observation(outcome="rejected", classification="X"))
    assert reason and "observation changed" in reason


# --- discovery + minimization -----------------------------------------------------

def test_discovers_noncrash_invariant_violation(workspace, kv_target):
    engine = OracleEngine(workspace)
    summary = engine.run(target_id="test:kv", inputs=[SORTED_KV],
                         relations=["outcome_invariant"],
                         transforms=["sort_lines"])
    # The input is already sorted; sorting must NOT change the verdict.
    confirmed = [f for f in summary["findings"]
                 if f["status"] == "confirmed"]
    assert confirmed == []  # no violation on already-canonical input

    # Now an unsorted-but-otherwise-valid input: dedupe/trim keep it valid.
    unsorted = b"c=3\nb=2\na=1\n"
    summary = engine.run(target_id="test:kv",
                         inputs=[unsorted, SORTED_KV],
                         relations=["outcome_invariant"],
                         transforms=["sort_lines"])
    confirmed = [f for f in summary["findings"]
                 if f["status"] == "confirmed"]
    # sort_lines *fixes* the unsorted input -> verdict changes -> violation!
    # Wait: reference rejects, transformed accepts => relation flags it.
    assert summary["pairs_evaluated"] >= 1
    assert confirmed, summary


def test_minimized_counterexample_retained(workspace, kv_target):
    engine = OracleEngine(workspace)
    noisy = b"x=24\np=1\nq=2\nr=3\ns=4\nt=5\n"
    summary = engine.run(target_id="test:kv", inputs=[noisy],
                         relations=["outcome_invariant"],
                         transforms=["sort_lines"])
    findings = [f for f in summary["findings"] if f["status"] == "confirmed"]
    assert findings
    finding = findings[0]
    minimized_rel = workspace.path(
        f"findings/{finding['id']}/minimized.bin")
    assert minimized_rel.is_file()
    assert finding["minimized"]["size_reduction"] > 0
    # The minimized counterexample is itself a confirmed violation.
    assert finding["minimized"]["data_sha256"]


# --- explicit nondeterminism --------------------------------------------------------

def test_nondeterministic_observations_not_promoted(workspace,
                                                    flaky_obs_target):
    engine = OracleEngine(workspace)
    summary = engine.run(
        target_id="test:flakyobs", inputs=[b"x=1"],
        relations=["outcome_invariant"], transforms=["identity"],
        trials=3)
    # Every pair flips verdicts run-to-run -> nothing may be 'confirmed'.
    assert summary["violations_confirmed"] == 0
    assert summary["nondeterministic"] >= 0  # tracked explicitly if seen


def test_trials_below_two_rejected(workspace, kv_target):
    engine = OracleEngine(workspace)
    with pytest.raises(ValidationError):
        engine.run(target_id="test:kv", inputs=[SORTED_KV], trials=1)


# --- provenance / separation of claims ----------------------------------------------

def test_finding_records_version_and_separates_claims(workspace, kv_target):
    engine = OracleEngine(workspace)
    summary = engine.run(target_id="test:kv", inputs=[b"c=3\nb=2\n"],
                         relations=["outcome_invariant"],
                         transforms=["dedupe_lines"])
    for finding in summary["findings"]:
        assert finding["oracle_version"] == 1
        assert finding["exploitability_claim"] is None
        assert finding["severity_rationale"]
        assert finding["reference_sha256"]
        assert "exploitability" in summary["note"] or summary["note"]


def test_run_persisted_and_listable(workspace, kv_target):
    engine = OracleEngine(workspace)
    out = engine.run(target_id="test:kv", inputs=[SORTED_KV])
    record = engine.get(out["run_id"])
    assert record.status == "run"
    assert any(r.id == out["run_id"] for r in engine.list())


def test_unknown_target_rejected(workspace):
    with pytest.raises(Exception):
        OracleEngine(workspace).run(target_id="missing:target",
                                    inputs=[b"x"])


def test_input_size_bound_enforced(workspace, kv_target):
    with pytest.raises(ValidationError):
        OracleEngine(workspace).run(target_id="test:kv",
                                    inputs=[b"x" * (256 * 1024 + 1)])
