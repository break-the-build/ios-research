"""Execution backends for fuzz-engine case batches (#207).

Contract
--------
An Executor turns a window of generated cases into normalized results::

    run(cases: list[tuple[int, bytes]]) -> list[tuple[int, ExecResult]]

``cases`` are ``(case_index, input_bytes)`` pairs and the returned list
carries the SAME indices in the SAME order (index-keyed), whatever completion
order the backend achieves internally. Executors are pure execution plumbing:

* they MUST NOT call ``Target.prepare()``/``cleanup()`` themselves — each
  ``Target.execute()`` drives its own lifecycle, exactly as the serial loop
  always did;
* they MUST NOT mutate engine state — sessions, corpora, crash stores, or
  scheduling caches stay owned by :class:`~ios_research.fuzz.FuzzEngine`,
  which generates before the batch and reduces after it, strictly in index
  order.

Shared-target thread-safety verdicts (verified by reading both target files)
-----------------------------------------------------------------------------
* ``targets.mac.MacFuzzTarget``: SAFE to share one instance across threads.
  Since #214 its ``prepare()``/``cleanup()`` mutations of the cached harness
  path are serialized by a per-instance ``threading.Lock``; ``_run``
  re-resolves the path if a concurrent cleanup nulled it; and the only other
  shared mutation is a dict assignment into ``_coverage_by_input``, which is
  atomic under the GIL (worst case a duplicate computation, never corruption).
* Mock targets (``targets/mock.py`` and every other shipped ``Target``
  subclass that keeps no instance state): SAFE/stateless. Their ``_run`` and
  ``coverage_features`` are pure functions of the input bytes; they inherit
  the trivial no-op ``prepare()``/``cleanup()`` from the base class, so
  concurrent ``execute()`` calls on one shared instance cannot interfere.
"""

from __future__ import annotations

from typing import Protocol

from .parallel import map_ordered
from .targets.base import ExecResult, Target

# Upper bound on threads per batch, matching ``limits.max_workers``.
MAX_WORKERS = 8


class Executor(Protocol):
    """The execution contract every backend implements (see module docstring)."""

    def run(self, cases: list[tuple[int, bytes]]) -> list[tuple[int, ExecResult]]:
        """Execute ``(case_index, input_bytes)`` pairs; return results keyed by
        the same indices, in input order."""
        ...  # pragma: no cover - protocol


class SerialExecutor:
    """Execute cases one at a time in a for-loop — the original behavior."""

    def __init__(self, target: Target):
        self.target = target

    def run(self, cases: list[tuple[int, bytes]]) -> list[tuple[int, ExecResult]]:
        return [(index, self.target.execute(data)) for index, data in cases]


class ThreadedBatchExecutor:
    """Fan executions out to a small thread pool, returning index-ordered results.

    Real targets spend their time waiting on subprocesses (GIL released), so
    threads overlap that wait without changing any result; the shared target
    instance is safe per the verdicts in the module docstring.
    """

    def __init__(self, target: Target, workers: int):
        self.target = target
        self.workers = max(1, int(workers))

    def run(self, cases: list[tuple[int, bytes]]) -> list[tuple[int, ExecResult]]:
        # map_ordered preserves input order structurally and re-raises worker
        # exceptions at the failing item's position with their original type.
        return map_ordered(self._execute_one, list(cases),
                           max(2, self.workers))

    def _execute_one(self, case: tuple[int, bytes]) -> tuple[int, ExecResult]:
        index, data = case
        return index, self.target.execute(data)


def resolve(workers: int | None, target: Target) -> Executor:
    """Pick an executor for ``workers``: serial at/below one, threaded above."""
    count = max(1, int(workers or 1))
    if count <= 1:
        return SerialExecutor(target)
    return ThreadedBatchExecutor(target, min(MAX_WORKERS, count))
