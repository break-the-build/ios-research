"""Crash triage: reproduction, classification, minimization, comparison.

All triage runs the stored input back through the crash's target, so results are
deterministic. Minimization uses classic delta-debugging (ddmin) and is required
to preserve the crash *signature* — a minimized input that changes the signature
is rejected.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from . import targets
from .corpus import CorpusStore
from .crashes import CrashStore, CrashRecord
from .targets.base import Outcome
from .workspace import Workspace

# Crash classifications (stable strings).
CLASSIFICATIONS = (
    "NULL_DEREFERENCE", "OUT_OF_BOUNDS_READ", "OUT_OF_BOUNDS_WRITE",
    "USE_AFTER_FREE", "INTEGER_ERROR", "TYPE_CONFUSION", "ASSERTION",
    "TIMEOUT", "UNKNOWN",
)


class Triage:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.crashes = CrashStore(workspace)

    def _target(self, crash: CrashRecord):
        return targets.create(crash.target)

    def reproduce(self, crash: CrashRecord) -> dict:
        """Re-run the stored input and check the signature still matches."""
        try:
            data = self.crashes.input_bytes(crash)
        except FileNotFoundError:
            from .errors import NotFoundError
            raise NotFoundError(
                f"crash '{crash.id}' input artifact "
                f"'{crash.input_sha256}' is missing from the workspace")
        result = self._target(crash).execute(data)
        sig = result.diagnostics.signature if result.diagnostics else ""
        reproduced = (result.outcome in (Outcome.CRASH, Outcome.ABNORMAL)
                      and sig == crash.signature)
        crash.reproduced = reproduced
        self.crashes.save(crash)
        return {"reproduced": reproduced, "outcome": result.outcome,
                "expected_signature": crash.signature, "observed_signature": sig}

    def classify(self, crash: CrashRecord) -> dict:
        """Classify from normalized diagnostics (not from exploitability)."""
        classification = crash.diagnostics.get("classification_hint", "UNKNOWN")
        if classification not in CLASSIFICATIONS:
            classification = "UNKNOWN"
        crash.classification = classification
        self.crashes.save(crash)
        return {"classification": classification,
                "signature": crash.signature,
                "access_type": crash.diagnostics.get("access_type")}

    def _predicate(self, crash: CrashRecord) -> Callable[[bytes], bool]:
        target = self._target(crash)
        expected = crash.signature

        def still_crashes(candidate: bytes) -> bool:
            if not candidate:
                return False
            res = target.execute(candidate)
            if res.outcome not in (Outcome.CRASH, Outcome.ABNORMAL):
                return False
            return bool(res.diagnostics and res.diagnostics.signature == expected)

        return still_crashes

    def minimize(self, crash: CrashRecord, *, add_regression: bool = True,
                 max_executions: int | None = None, workers: int = 1) -> dict:
        original = self.crashes.input_bytes(crash)
        predicate = self._predicate(crash)
        executions = {"count": 0}

        def counted(candidate: bytes) -> bool:
            if max_executions is not None and \
                    executions["count"] >= max_executions:
                return False
            executions["count"] += 1
            return predicate(candidate)

        if not counted(original):
            # Cannot minimize what does not reproduce.
            return {"minimized": False, "reason": "input does not reproduce",
                    "original_size": len(original)}
        minimized = ddmin(original, counted, max_executions=max_executions,
                          workers=workers)
        sha = self.crashes.write_minimized(crash, minimized)

        regression_added = False
        if add_regression:
            store = CorpusStore(self.ws)
            corpus = self._regression_corpus(store)
            added = store.add_bytes(corpus, minimized, origin="regression",
                                    parent=crash.input_sha256)
            regression_added = added is not None

        return {"minimized": True, "original_size": len(original),
                "minimized_size": len(minimized), "minimized_sha256": sha,
                "regression_added": regression_added,
                "signature_preserved": True,
                "executions": executions["count"]}

    def _regression_corpus(self, store: CorpusStore):
        for corpus in store.list():
            if corpus.name == "regression":
                return corpus
        return store.create("regression")

    def compare(self, a: CrashRecord, b: CrashRecord) -> dict:
        same_signature = a.signature == b.signature
        fields = ("classification", "outcome", "target", "fmt")
        differences = {f: [getattr(a, f), getattr(b, f)]
                       for f in fields if getattr(a, f) != getattr(b, f)}
        diag_keys = ("exception_type", "signal", "access_type")
        diag_diff = {k: [a.diagnostics.get(k), b.diagnostics.get(k)]
                     for k in diag_keys
                     if a.diagnostics.get(k) != b.diagnostics.get(k)}
        return {
            "a": a.id, "b": b.id,
            "same_signature": same_signature,
            "likely_duplicate": same_signature,
            "field_differences": differences,
            "diagnostic_differences": diag_diff,
        }


def ddmin(data: bytes, predicate: Callable[[bytes], bool],
          max_executions: int | None = None, workers: int = 1) -> bytes:
    """Classic delta-debugging minimization.

    Returns the smallest byte string found for which ``predicate`` still holds.
    ``max_executions`` optionally bounds total predicate invocations; when the
    bound is hit, the best reduction found so far is returned. This keeps
    minimization of very large inputs against slow targets bounded.

    ``workers`` controls how complements *within one round* are evaluated.
    Complements of a single round are mutually independent — only the
    acceptance decision must be sequential. With ``workers=1`` (default) the
    original serial loop runs unchanged. With ``workers > 1`` the complements
    of each round are dispatched to a thread pool in waves of at most
    ``workers`` candidates (each candidate is typically a full target
    execution; the subprocess wait releases the GIL, so threads scale), and
    results are then applied STRICTLY IN INDEX ORDER: the first passing
    complement is accepted exactly as the serial loop would accept it. The
    minimized output is therefore identical for any ``workers`` value on the
    same input.

    Budget semantics: ``max_executions`` gates dispatches. The counter is
    checked BEFORE each candidate is dispatched; once exhausted no new
    dispatches happen and the round aborts to the best-so-far return, exactly
    like serial exhaustion. Candidates already dispatched when the budget trips
    may complete in the background and count toward ``executed``. As a result,
    within a speculative wave that contains a passing complement the execution
    count may exceed the serial run's by at most ``workers - 1`` (speculated
    evaluations the serial loop would never have reached); the returned bytes
    never differ.

    Thread safety: the predicate closes over ONE shared target instance and
    calls ``Target.execute`` per candidate. This is safe for concurrent use:
    ``execute`` wraps each call in prepare/_run/cleanup with no cross-call
    mutable state on the base class; ``MacFuzzTarget._run`` creates uniquely
    named temp files per call (``NamedTemporaryFile(delete=False)``) and its
    only shared field (``_harness_path``) is idempotently re-resolvable, now
    guarded by a lock plus a resilient fallback read in ``_run`` (see
    ``targets/mac.py``). ``tools/mac_campaign/run.py`` already threads
    ``execute_batch`` on a shared instance as precedent.
    """
    if workers > 1:
        return _ddmin_parallel(data, predicate, max_executions, workers)
    n = 2
    executed = 0
    while len(data) >= 2:
        chunk = max(1, len(data) // n)
        subsets = [data[i:i + chunk] for i in range(0, len(data), chunk)]
        reduced = False
        for j in range(len(subsets)):
            complement = b"".join(subsets[:j] + subsets[j + 1:])
            if not complement:
                continue
            if max_executions is not None and executed >= max_executions:
                return data
            executed += 1
            if predicate(complement):
                data = complement
                n = max(n - 1, 2)
                reduced = True
                break
        if not reduced:
            if n >= len(data):
                break
            n = min(len(data), n * 2)
    return data


def _ddmin_parallel(data: bytes, predicate: Callable[[bytes], bool],
                    max_executions: int | None, workers: int) -> bytes:
    """Concrete parallel path of :func:`ddmin` (``workers > 1``).

    Same round structure as the serial loop; complements are evaluated in
    budget-gated waves of at most ``workers`` candidates and accepted strictly
    in index order, which makes the result identical to ``workers=1``.
    """
    n = 2
    executed = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        while len(data) >= 2:
            chunk = max(1, len(data) // n)
            subsets = [data[i:i + chunk] for i in range(0, len(data), chunk)]
            # Empty complements are skipped without counting, like serial.
            complements = [c for c in
                           (b"".join(subsets[:j] + subsets[j + 1:])
                            for j in range(len(subsets)))
                           if c]
            reduced = False
            start = 0
            while start < len(complements):
                # Budget is checked before EACH dispatch; a candidate whose
                # check passed may still be in flight when the budget trips,
                # and it counts toward `executed` like a serial attempt.
                wave: list[bytes] = []
                while (start < len(complements) and len(wave) < workers
                       and (max_executions is None
                            or executed < max_executions)):
                    executed += 1
                    wave.append(complements[start])
                    start += 1
                if not wave:
                    # Budget exhausted before any dispatch: best-so-far
                    # return, exactly like serial exhaustion.
                    return data
                results = list(pool.map(predicate, wave))
                for offset, ok in enumerate(results):
                    if ok:
                        data = wave[offset]
                        n = max(n - 1, 2)
                        reduced = True
                        break
                if reduced:
                    break
            if not reduced:
                if n >= len(data):
                    break
                n = min(len(data), n * 2)
    return data
