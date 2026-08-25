"""Phase 04 tests: reproduction, classification, minimization, comparison."""

from __future__ import annotations

import threading
import time

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


class _CountingPredicate:
    """Thread-safe counting wrapper around a predicate."""

    def __init__(self, fn):
        self.fn = fn
        self.count = 0
        self._lock = threading.Lock()

    def __call__(self, data):
        with self._lock:
            self.count += 1
        return self.fn(data)


# --- ddmin workers>1: equivalence ------------------------------------------
def test_ddmin_parallel_matches_serial_output_and_counts():
    # Crash region planted at the FRONT of an even-length multi-KB buffer.
    # Every round splits into two halves and keeps the front half, so the
    # passing complement is always the last candidate of its wave and even
    # the speculated dispatches line up: output AND execution counts are
    # identical between workers=1 and workers=4.
    data = b"BUG" + b"A" * 4093

    serial_pred = _CountingPredicate(lambda d: b"BUG" in d)
    par_pred = _CountingPredicate(lambda d: b"BUG" in d)
    serial = ddmin(data, serial_pred, workers=1)
    parallel = ddmin(data, par_pred, workers=4)

    assert serial == parallel == b"BUG"
    assert par_pred.count == serial_pred.count


def test_ddmin_parallel_equivalence_single_byte_and_non_minimizable():
    # Single-byte input: no rounds at all.
    assert ddmin(b"X", lambda d: b"X" in d, workers=4) == b"X"

    # Non-minimizable input (only the exact original passes): both modes walk
    # every complement of every round, so output AND counts must match.
    data = b"Q" * 64
    pred = _CountingPredicate(lambda d: d == data)
    serial = ddmin(data, pred, max_executions=10_000, workers=1)
    total_serial = pred.count
    pred2 = _CountingPredicate(lambda d: d == data)
    parallel = ddmin(data, pred2, max_executions=10_000, workers=4)
    assert serial == parallel == data
    assert pred2.count == total_serial


def test_ddmin_parallel_output_identical_on_mid_buffer_region():
    # Region planted mid-buffer: some accepting rounds speculate past the
    # first passing complement, so executed counts may exceed the serial run
    # (bounded by workers-1 per wave); the minimized bytes must not differ.
    data = b"A" * 2048 + b"BUG" + b"A" * 2048
    serial = ddmin(data, lambda d: b"BUG" in d, workers=1)
    parallel = ddmin(data, lambda d: b"BUG" in d, workers=4)
    assert serial == parallel == b"BUG"


def test_ddmin_parallel_actually_overlaps_oracle_calls():
    # #274: verify fan-out via observed peak concurrency inside the oracle,
    # not by comparing wall-clock durations (which inverted under runner
    # load). Every oracle call spends its life in a CPU-free sleep, so a
    # workers=4 round evaluating >=2 complements must show peak > 1.
    lock = threading.Lock()
    state = {"active": 0, "peak": 0}

    def probe_has_bug(d):
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        try:
            time.sleep(0.01)
            return b"BUG" in d
        finally:
            with lock:
                state["active"] -= 1

    data = b"BUG" + b"A" * 1500

    state["peak"] = 0
    assert ddmin(data, probe_has_bug, workers=1) == b"BUG"
    assert state["peak"] == 1          # serial path: strictly sequential

    state["peak"] = 0
    assert ddmin(data, probe_has_bug, workers=4) == b"BUG"
    assert state["peak"] > 1           # parallel path: real overlap


def test_ddmin_respects_budget_with_parallel_workers():
    data = b"Q" * 256
    pred = _CountingPredicate(lambda d: d == data)  # never minimizable
    result = ddmin(data, pred, max_executions=7, workers=4)
    assert result == data          # best-so-far return on exhaustion
    assert pred.count == 7         # hard cap: no more than budget invocations


def test_minimize_accepts_workers_kwarg(workspace):
    data = b"MOCK\x01\x01\xff\xff" + b"C" * 300
    crash = _record(workspace, data)
    result = Triage(workspace).minimize(crash, workers=4)
    assert result["minimized"] is True
    assert result["minimized_size"] < result["original_size"]


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
