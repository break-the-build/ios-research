"""Tests for the fuzz-engine executor abstraction (#207).

Locks in the contract from ``ios_research.executors``: index-keyed results in
input order, serial execution identical to a plain for-loop over
``target.execute``, threaded execution that preserves index order under
randomized completion delays, and executors that never touch target lifecycle
or retain case data.
"""

from __future__ import annotations

import random

from ios_research.executors import (SerialExecutor, ThreadedBatchExecutor,
                                    MAX_WORKERS, resolve)
from ios_research.targets.base import ExecResult, Outcome, Target


class _EchoTarget(Target):
    """Deterministic stub whose results are pure functions of the input."""

    target_id = "test:echo"
    kind = "parser"
    description = "returns one accepted result per input"
    formats = ("bin",)

    def _run(self, data: bytes) -> ExecResult:
        return ExecResult(outcome=Outcome.ACCEPTED, detail=data.hex(),
                          duration_ms=1)


class _DelayTarget(Target):
    """Sleeps before answering so threaded completion order is scrambled."""

    target_id = "test:delay"
    kind = "parser"
    description = "sleeps a seeded pseudo-random duration per input"
    formats = ("bin",)

    def __init__(self, seed: int = 7):
        self.rng = random.Random(seed)

    def _run(self, data: bytes) -> ExecResult:
        import time
        # Later indices sleep longer on average: a naive completion-order
        # collector would reverse the batch.
        delay = 0.001 * (1 + int(data[0]) % 8)
        time.sleep(delay)
        return ExecResult(outcome=Outcome.ACCEPTED, detail=str(len(data)),
                          duration_ms=1)


class _SpyTarget(Target):
    """Records every lifecycle call; wraps a deterministic inner result."""

    target_id = "test:spy"
    kind = "parser"
    description = "records prepare/run/cleanup call sequence"
    formats = ("bin",)

    def __init__(self):
        self.calls: list[tuple[str, bytes]] = []

    def prepare(self) -> None:
        self.calls.append(("prepare", b""))

    def cleanup(self) -> None:
        self.calls.append(("cleanup", b""))

    def _run(self, data: bytes) -> ExecResult:
        self.calls.append(("run", data))
        return ExecResult(outcome=Outcome.REJECTED, detail="spied",
                          duration_ms=1)


def _cases(n: int) -> list[tuple[int, bytes]]:
    return [(i, bytes([i % 256]) * (i + 1)) for i in range(n)]


# --- SerialExecutor --------------------------------------------------------
def test_serial_executor_matches_plain_execute_loop():
    target = _EchoTarget()
    cases = _cases(12)
    expected = [(index, target.execute(data)) for index, data in cases]
    got = SerialExecutor(target).run(cases)
    assert [index for index, _ in got] == [index for index, _ in cases]
    assert [(index, r.outcome, r.detail) for index, r in got] == \
        [(index, r.outcome, r.detail) for index, r in expected]


def test_serial_executor_propagates_first_failure():
    class _Boom(_EchoTarget):
        def _run(self, data):
            if data == b"x":
                raise RuntimeError("boom")
            return ExecResult(outcome=Outcome.REJECTED, duration_ms=1)

    executed: list[bytes] = []

    class _Recording(_Boom):
        def execute(self, data):
            executed.append(data)
            return super().execute(data)

    executor = SerialExecutor(_Recording())
    try:
        executor.run([(0, b"a"), (1, b"x"), (2, b"never")])
        raise AssertionError("expected RuntimeError")
    except RuntimeError:
        pass
    # Exactly today's serial semantics: stops at the failing case.
    assert executed == [b"a", b"x"]


# --- ThreadedBatchExecutor -------------------------------------------------
def test_threaded_batch_preserves_index_order_under_random_delays():
    target = _DelayTarget(seed=1234)
    cases = _cases(32)
    for workers in (2, 4, 8):
        got = ThreadedBatchExecutor(target, workers).run(cases)
        assert [index for index, _ in got] == list(range(len(cases)))
        for index, result in got:
            assert result.outcome == Outcome.ACCEPTED
            assert result.detail == str(index + 1)


def test_threaded_batch_results_match_serial_results():
    cases = _cases(16)
    serial = SerialExecutor(_EchoTarget()).run(cases)
    threaded = ThreadedBatchExecutor(_EchoTarget(), workers=4).run(cases)
    assert [(i, r.outcome, r.detail) for i, r in serial] == \
        [(i, r.outcome, r.detail) for i, r in threaded]


def test_threaded_batch_single_case_and_empty_batch():
    target = _EchoTarget()
    executor = ThreadedBatchExecutor(target, workers=4)
    assert executor.run([]) == []
    got = executor.run([(3, b"abc")])
    assert len(got) == 1 and got[0][0] == 3
    assert got[0][1].outcome == Outcome.ACCEPTED


# --- resolve ----------------------------------------------------------------
def test_resolve_returns_serial_for_one_or_fewer_workers():
    target = _EchoTarget()
    for workers in (None, 0, 1):
        executor = resolve(workers, target)
        assert isinstance(executor, SerialExecutor)
        assert executor.target is target


def test_resolve_caps_threaded_workers_at_eight():
    target = _EchoTarget()
    executor = resolve(4, target)
    assert isinstance(executor, ThreadedBatchExecutor)
    assert executor.workers == 4
    capped = resolve(999, target)
    assert isinstance(capped, ThreadedBatchExecutor)
    assert capped.workers == MAX_WORKERS


# --- purity: no lifecycle or retention side effects --------------------------
def test_executors_never_call_prepare_cleanup_directly_or_retain_cases():
    for build in (lambda t: SerialExecutor(t),
                  lambda t: ThreadedBatchExecutor(t, workers=4)):
        spy = _SpyTarget()
        executor = build(spy)
        cases = _cases(9)
        results = executor.run(cases)
        # Every execute() drove exactly its own prepare -> run -> cleanup;
        # the executor added no extra lifecycle calls around the batch.
        runs = [c for c in spy.calls if c[0] == "run"]
        prepares = [c for c in spy.calls if c[0] == "prepare"]
        cleanups = [c for c in spy.calls if c[0] == "cleanup"]
        assert len(runs) == len(prepares) == len(cleanups) == len(cases)
        # Threads interleave the shared call log: compare as multisets.
        assert sorted(data for _, data in runs) == \
            sorted(data for _, data in cases)
        assert len(prepares) == len(cleanups)
        assert all(r.outcome == Outcome.REJECTED for _, r in results)
        # No retention: the executor keeps no copies of inputs or results.
        stored = dict(vars(executor))
        assert set(stored) <= {"target", "workers"}
        for value in stored.values():
            assert not isinstance(value, (bytes, bytearray, list, tuple, dict))


def test_threaded_batch_worker_exception_reraises_in_order_position():
    class _Half(_EchoTarget):
        def _run(self, data):
            if int(data[0]) == 5:
                raise ValueError("case five failed")
            return super()._run(data)

    executor = ThreadedBatchExecutor(_Half(), workers=3)
    try:
        executor.run([(i, bytes([i])) for i in range(10)])
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "case five failed" in str(exc)
