"""ios_research_minimizer environment (goal 09 testcase-minimization).

Optimizes delta-debugging (ddmin) parameters. Measures how much crash inputs
shrink, whether they still reproduce, how long minimization takes, and how much
semantic structure survives.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping

from experiment_loop.environments.base import (
    KNOB_INT, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research import targets
from ios_research.targets.base import Outcome
from .common import fuzz_once

_MAGIC = b"MOCK"


def _param_ddmin(data: bytes, predicate: Callable[[bytes], bool], *,
                 start_n: int, min_chunk: int) -> bytes:
    """Delta-debugging with a tunable initial granularity and chunk floor."""
    n = max(2, start_n)
    while len(data) >= 2:
        chunk = max(min_chunk, len(data) // n)
        subsets = [data[i:i + chunk] for i in range(0, len(data), chunk)]
        reduced = False
        for j in range(len(subsets)):
            complement = b"".join(subsets[:j] + subsets[j + 1:])
            if complement and predicate(complement):
                data = complement
                n = max(n - 1, 2)
                reduced = True
                break
        if not reduced:
            if n >= len(data):
                break
            n = min(len(data), n * 2)
    return data


@register
class IosResearchMinimizerEnvironment(BaseEnvironment):
    name = "ios_research_minimizer"
    cost_per_sample = 0.0

    # A fixed amount of padding is added to each crash seed so there is
    # something to remove; it is deliberately NOT a knob, so the optimizer
    # cannot inflate the reduction ratio by padding more.
    _PAD_BYTES = 48

    knob_list = (
        Knob(name="start_n", kind=KNOB_INT, default=2, low=2, high=8, step=1,
             description="initial ddmin partition count"),
        Knob(name="min_chunk", kind=KNOB_INT, default=1, low=1, high=4, step=1,
             description="smallest chunk ddmin will remove"),
    )

    metric_list = (
        MetricSpec("median_input_reduction", MAXIMIZE, "ratio"),
        MetricSpec("reproduction_rate", MAXIMIZE, "ratio"),
        MetricSpec("minimization_time_seconds", MINIMIZE, "seconds"),
        MetricSpec("remaining_semantic_structure", MAXIMIZE, "ratio"),
    )

    def _predicate(self, target, signature: str):
        def still(candidate: bytes) -> bool:
            if not candidate:
                return False
            r = target.execute(candidate)
            return (r.outcome in (Outcome.CRASH, Outcome.ABNORMAL)
                    and bool(r.diagnostics) and r.diagnostics.signature == signature)
        return still

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        start_n = int(config.get("start_n", 2))
        min_chunk = int(config.get("min_chunk", 1))
        pad = self._PAD_BYTES
        target = targets.create("mock:parser")

        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for s in range(samples):
            sub = seed * 100003 + s
            # Discover crash inputs (padded so there is something to minimize).
            found = fuzz_once("mock:parser", None, budget=80, seed=sub)
            reductions, structure, repro = [], [], []
            t0 = time.perf_counter()
            for sig, data in found["signatures"].items():
                original = data + b"A" * pad
                # Confirm the padded input still crashes with the signature.
                if not self._predicate(target, sig)(original):
                    continue
                minimized = _param_ddmin(
                    original, self._predicate(target, sig),
                    start_n=start_n, min_chunk=min_chunk)
                reductions.append(1.0 - len(minimized) / len(original))
                structure.append(1.0 if minimized[:4] == _MAGIC else 0.0)
                r = target.execute(minimized)
                repro.append(1.0 if (r.diagnostics
                             and r.diagnostics.signature == sig) else 0.0)
            elapsed = time.perf_counter() - t0

            if not reductions:
                reductions, structure, repro = [0.0], [0.0], [1.0]
            reductions.sort()
            median = reductions[len(reductions) // 2]
            vals["median_input_reduction"].append(median)
            vals["reproduction_rate"].append(sum(repro) / len(repro))
            vals["minimization_time_seconds"].append(elapsed)
            vals["remaining_semantic_structure"].append(
                sum(structure) / len(structure))

        return self.summarize(Trace(values=vals), samples)
