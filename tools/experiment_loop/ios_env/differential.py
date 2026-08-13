"""ios_research_differential environment (goal 12 differential-testing).

Optimizes the corpus (via mutation-strategy weighting and size) fed to
differential testing between two parser versions, to surface more *actionable*
behavioral differences (severity-changing transitions) per case while keeping
non-actionable noise low.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_INT, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research import mutation, targets
from ios_research.targets.base import Outcome
from .common import STRATEGIES, base_input, weights_from_config

_SEVERITY = {Outcome.ACCEPTED: 0, Outcome.REJECTED: 0,
             Outcome.TIMEOUT: 2, Outcome.CRASH: 3, Outcome.ABNORMAL: 3}
# Possible severity-changing transition types (for coverage).
_POSSIBLE_TRANSITIONS = 6


@register
class IosResearchDifferentialEnvironment(BaseEnvironment):
    name = "ios_research_differential"
    cost_per_sample = 0.0

    knob_list = tuple(
        Knob(name=f"weight_{s}", kind=KNOB_INT, default=1, low=0, high=3, step=1,
             description=f"selection weight for the '{s}' mutation strategy")
        for s in STRATEGIES
    ) + (
        Knob(name="corpus_size", kind=KNOB_INT, default=12, low=6, high=30,
             step=6, description="distinct inputs fed to differential testing"),
    )

    metric_list = (
        MetricSpec("actionable_differences_per_1000_cases", MAXIMIZE, "diffs"),
        MetricSpec("false_positive_rate", MINIMIZE, "ratio"),
        MetricSpec("coverage_difference", MAXIMIZE, "ratio"),
        MetricSpec("execution_time_seconds", MINIMIZE, "seconds"),
    )

    def _corpus(self, weights, size, sub_seed):
        """Fuzz mock:parser to gather up to ``size`` distinct inputs."""
        target = targets.create("mock:parser")
        base = base_input("mock:parser")
        seen: dict[str, bytes] = {}
        i = 0
        while len(seen) < size and i < size * 40:
            data, _ = mutation.mutate(base, sub_seed, i,
                                      struct_fn=target.structure_mutate,
                                      weights=weights)
            seen.setdefault(data.hex(), data)
            i += 1
        return list(seen.values())

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        weights = weights_from_config(config)
        size = int(config.get("corpus_size", 12))
        a = targets.create("mock:parser")
        b = targets.create("mock:parser-v2")

        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for s in range(samples):
            inputs = self._corpus(weights, size, seed * 100003 + s)
            actionable = 0
            non_actionable = 0
            transitions: set[str] = set()
            t0 = time.perf_counter()
            for data in inputs:
                ra, rb = a.execute(data), b.execute(data)
                sev_a, sev_b = _SEVERITY[ra.outcome], _SEVERITY[rb.outcome]
                sig_a = ra.diagnostics.signature if ra.diagnostics else ""
                sig_b = rb.diagnostics.signature if rb.diagnostics else ""
                if sev_a != sev_b:
                    actionable += 1
                    transitions.add(f"{sev_a}->{sev_b}")
                elif sig_a != sig_b:
                    # same severity, different signature: non-actionable noise
                    non_actionable += 1
            elapsed = time.perf_counter() - t0

            cases = len(inputs)
            total_diffs = actionable + non_actionable
            vals["actionable_differences_per_1000_cases"].append(
                actionable / cases * 1000 if cases else 0.0)
            vals["false_positive_rate"].append(
                non_actionable / total_diffs if total_diffs else 0.0)
            vals["coverage_difference"].append(
                len(transitions) / _POSSIBLE_TRANSITIONS)
            vals["execution_time_seconds"].append(elapsed)

        return self.summarize(Trace(values=vals), samples)
