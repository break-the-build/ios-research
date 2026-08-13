"""ios_research environment (goal 13 research-efficiency).

Optimizes how a research run *spends its budget*: strategy weighting plus the
per-run case budget. Findings are unique, reproducible memory-safety crashes;
cost is a compute model over executions. Because unique findings saturate, this
is a genuine efficiency trade-off — more cases cost more but yield diminishing
new findings.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_INT, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research import targets
from .common import (
    STRATEGIES, MEMORY_SAFETY_CLASSES, fuzz_once, weights_from_config,
)

# Compute cost model (dollars). A fixed per-run overhead plus a per-execution
# cost, so spending more executions has to pay for itself in new findings.
_FIXED_OVERHEAD = 0.01
_COST_PER_EXEC = 5e-5


@register
class IosResearchEnvironment(BaseEnvironment):
    name = "ios_research"
    cost_per_sample = 0.0

    knob_list = tuple(
        Knob(name=f"weight_{s}", kind=KNOB_INT, default=1, low=0, high=3, step=1,
             description=f"selection weight for the '{s}' mutation strategy")
        for s in STRATEGIES
    ) + (
        Knob(name="max_cases", kind=KNOB_INT, default=120, low=40, high=280,
             step=40, description="per-run fuzzing budget (cases)"),
    )

    metric_list = (
        MetricSpec("actionable_findings_per_dollar", MAXIMIZE, "findings/$"),
        MetricSpec("actionable_findings_per_hour", MAXIMIZE, "findings/h"),
        MetricSpec("unique_crashes_per_100k_cases", MAXIMIZE, "crashes"),
        MetricSpec("cost_per_unique_crash", MINIMIZE, "$/crash"),
        MetricSpec("reproducible_crash_rate", MAXIMIZE, "ratio"),
    )

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        weights = weights_from_config(config)
        budget = int(config.get("max_cases", 120))
        target = targets.create("mock:parser")

        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for s in range(samples):
            t0 = time.perf_counter()
            found = fuzz_once("mock:parser", weights, budget=budget,
                              seed=seed * 100003 + s)
            # Actionable = unique, reproducible, memory-safety crashes.
            actionable = 0
            reproduced = 0
            for sig, data in found["signatures"].items():
                r = target.execute(data)
                if r.diagnostics and r.diagnostics.signature == sig:
                    reproduced += 1
                    if found["classifications"][sig] in MEMORY_SAFETY_CLASSES:
                        actionable += 1
            elapsed = max(time.perf_counter() - t0, 1e-9)

            unique = found["unique"]
            cost = _FIXED_OVERHEAD + budget * _COST_PER_EXEC
            repro_rate = reproduced / unique if unique else 1.0

            vals["actionable_findings_per_dollar"].append(actionable / cost)
            vals["actionable_findings_per_hour"].append(
                actionable / (elapsed / 3600.0))
            vals["unique_crashes_per_100k_cases"].append(unique / budget * 100_000)
            vals["cost_per_unique_crash"].append(
                cost / unique if unique else cost)
            vals["reproducible_crash_rate"].append(repro_rate)

        return self.summarize(Trace(values=vals), samples)
