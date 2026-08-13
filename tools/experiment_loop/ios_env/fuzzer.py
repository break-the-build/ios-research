"""ios_research_fuzzer environment (goals 05 fuzz-throughput, 06 effectiveness).

Optimizes mutation-strategy weighting and per-run case budget. Measures both
effectiveness (unique crash signatures per budget) and throughput (executions
per second), reflecting the real FuzzEngine inner step.
"""

from __future__ import annotations

import time
import tracemalloc
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_INT, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research import targets
from ios_research.targets.base import Outcome
from .common import STRATEGIES, KNOWN_SIGNATURES, base_input, weights_from_config


@register
class IosResearchFuzzerEnvironment(BaseEnvironment):
    name = "ios_research_fuzzer"
    cost_per_sample = 0.0

    knob_list = tuple(
        Knob(name=f"weight_{s}", kind=KNOB_INT, default=1, low=0, high=3, step=1,
             description=f"selection weight for the '{s}' mutation strategy")
        for s in STRATEGIES
    ) + (
        Knob(name="case_budget", kind=KNOB_INT, default=60, low=30, high=120,
             step=15, description="cases executed per fuzzing sample"),
    )

    metric_list = (
        MetricSpec("unique_crashes_per_100k_cases", MAXIMIZE, "crashes"),
        MetricSpec("reproducible_crash_rate", MAXIMIZE, "ratio"),
        MetricSpec("coverage_growth", MAXIMIZE, "percent"),
        MetricSpec("executions_per_second", MAXIMIZE, "exec/s"),
        MetricSpec("unique_inputs_per_second", MAXIMIZE, "inputs/s"),
        MetricSpec("crash_detection_rate", MAXIMIZE, "ratio"),
        MetricSpec("cpu_percent", MINIMIZE, "percent"),
        MetricSpec("memory_mb", MINIMIZE, "MB"),
    )

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        weights = weights_from_config(config)
        budget = int(config.get("case_budget", 60))
        target = targets.create("mock:parser")
        struct_fn = target.structure_mutate
        base = base_input("mock:parser")
        from ios_research import mutation

        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for s in range(samples):
            sub = seed * 100003 + s
            sigs: dict[str, bytes] = {}
            inputs: set[str] = set()
            crashes = 0
            tracemalloc.start()
            wall0, cpu0 = time.perf_counter(), time.process_time()
            for i in range(budget):
                data, _ = mutation.mutate(base, sub, i, struct_fn=struct_fn,
                                          weights=weights)
                inputs.add(data.hex())
                r = target.execute(data)
                if r.outcome in (Outcome.CRASH, Outcome.ABNORMAL) and r.diagnostics:
                    crashes += 1
                    sigs.setdefault(r.diagnostics.signature, data)
            wall = max(time.perf_counter() - wall0, 1e-9)
            cpu = time.process_time() - cpu0
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            unique = len(sigs)
            reproduced = sum(
                1 for sig, data in sigs.items()
                if (d := target.execute(data).diagnostics) and d.signature == sig)
            repro_rate = reproduced / unique if unique else 1.0

            vals["unique_crashes_per_100k_cases"].append(unique / budget * 100_000)
            vals["reproducible_crash_rate"].append(repro_rate)
            vals["coverage_growth"].append(
                min(100.0, unique / KNOWN_SIGNATURES * 100.0))
            vals["executions_per_second"].append(budget / wall)
            vals["unique_inputs_per_second"].append(len(inputs) / wall)
            vals["crash_detection_rate"].append(crashes / budget)
            vals["cpu_percent"].append(min(100.0, cpu / wall * 100.0))
            vals["memory_mb"].append(peak / (1024 * 1024))

        return self.summarize(Trace(values=vals), samples)
