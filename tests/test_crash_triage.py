"""Phase 04 tests: reproduction, classification, minimization, comparison."""

from __future__ import annotations

from ios_research.crashes import CrashStore
from ios_research.corpus import CorpusStore
from ios_research.targets import create
from ios_research.targets.base import Outcome
from ios_research.triage import Triage, ddmin


def _record(workspace, data, experiment_id="exp1", target="mock:parser"):
    store = CrashStore(workspace)
    res = create(target).execute(data)
    assert res.outcome == Outcome.CRASH, res.outcome
    return store.record(experiment_id=experiment_id, target=target,
                        fmt="mock-record", data=data, exec_result=res)


# --- ddmin ----------------------------------------------------------------
def test_ddmin_reduces_to_minimal_predicate():
    # Predicate: contains b"BUG".
    data = b"aaaaBUGbbbbbcccc"
    minimized = ddmin(data, lambda d: b"BUG" in d)
    assert b"BUG" in minimized
    assert len(minimized) < len(data)


def test_ddmin_stops_when_irreducible():
    data = b"BUG"
    assert ddmin(data, lambda d: b"BUG" in d) == b"BUG"


# --- reproduce ------------------------------------------------------------
def test_reproduce_true_for_deterministic_crash(workspace):
    crash = _record(workspace, b"MOCK\x01\xff\x00\x00")  # null dispatch
    triage = Triage(workspace)
    out = triage.reproduce(crash)
    assert out["reproduced"] is True
    assert triage.crashes.get(crash.id).reproduced is True


# --- classify -------------------------------------------------------------
def test_classify_reports_expected_class(workspace):
    crash = _record(workspace, b"MOCK\x01\x01\xff\xff")  # OOB read
    out = Triage(workspace).classify(crash)
    assert out["classification"] == "OUT_OF_BOUNDS_READ"


# --- minimize -------------------------------------------------------------
def test_minimize_shrinks_and_preserves_signature(workspace):
    # Oversized declared length with a long payload: trailing payload bytes are
    # removable while the declared>payload crash condition persists.
    data = b"MOCK\x01\x01\xff\xff" + b"A" * 200
    crash = _record(workspace, data)
    triage = Triage(workspace)
    result = triage.minimize(crash)
    assert result["minimized"] is True
    assert result["minimized_size"] < result["original_size"]
    assert result["signature_preserved"] is True
    # Minimized input still reproduces the same signature.
    minimized = triage.crashes.minimized_bytes(crash)
    res = create("mock:parser").execute(minimized)
    assert res.diagnostics.signature == crash.signature


def test_minimize_populates_regression_corpus(workspace):
    crash = _record(workspace, b"MOCK\x01\x01\xff\xff" + b"B" * 50)
    Triage(workspace).minimize(crash)
    names = [c.name for c in CorpusStore(workspace).list()]
    assert "regression" in names


# --- compare --------------------------------------------------------------
def test_compare_same_signature_is_duplicate(workspace):
    c1 = _record(workspace, b"MOCK\x01\xff\x00\x00", experiment_id="e1")
    c2 = _record(workspace, b"MOCK\x01\xff\x00\x00", experiment_id="e2")
    out = Triage(workspace).compare(c1, c2)
    assert out["same_signature"] is True
    assert out["likely_duplicate"] is True


def test_compare_different_signature_differs(workspace):
    c1 = _record(workspace, b"MOCK\x01\xff\x00\x00")          # null deref
    c2 = _record(workspace, b"MOCK\x01\x01\xff\xff")          # OOB read
    out = Triage(workspace).compare(c1, c2)
    assert out["same_signature"] is False
    assert "classification" in out["field_differences"]
