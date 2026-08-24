"""Ordered thread-pool fan-out for independent per-record work.

Post-fuzz triage fans out over crashes (reproduce -> minimize -> analyze).
The work items are independent of each other and subprocess-backed
``Target.execute`` calls release the GIL while they wait, so a small thread
pool converts that fan-out into real wall-clock wins (#200) without changing
any result.

The contract is deliberately tiny: output order always equals input order,
and the ``workers <= 1`` path is exactly the plain ordered comprehension the
callers used before — same results, same exceptions, same side effects.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")

# ``Triage.minimize`` finishes with a find-or-create + append + save on the
# shared "regression" corpus — a read-modify-write on one manifest file that
# is not safe to overlap across threads. The fan-out callers therefore hold
# this process-wide lock around ``minimize`` calls; throughput is preserved
# by passing ``workers`` into the ddmin rounds themselves (#214). Everything
# else triage touches is crash-id-scoped and safe to overlap.
TRIAGE_MINIMIZE_LOCK = threading.Lock()


def map_ordered(fn: Callable[[T], R], items: Sequence[T],
                workers: int = 1) -> list[R]:
    """Apply ``fn`` over ``items`` and return results in INPUT ORDER.

    With ``workers <= 1`` (or a single item) this is the plain ordered
    comprehension ``[fn(item) for item in items]`` — bit-identical to the
    serial loops it replaces, including raising on the first failure before
    later items run. With more workers, items are dispatched to a thread pool;
    ``ThreadPoolExecutor.map`` preserves input order, so results come back in
    input order and worker exceptions are re-raised in the calling thread at
    the failing item's position with their original type.
    """
    items = list(items)
    if workers <= 1 or len(items) <= 1:
        return [fn(item) for item in items]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, items))
