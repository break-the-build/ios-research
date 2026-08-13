"""experiment-loop environments for ios-research.

Load with experiment-loop's ``--load`` flag:

    python -m experiment_loop run goals/06-fuzz-effectiveness.json \
        --load tools/experiment_loop/ios_research_env.py --samples 40

These environments bind the *real* ios-research code to the experiment-loop
search engine, so the loop optimizes actual framework behavior (not a
simulation). The fuzzer environment measures the exact inner step the
``FuzzEngine`` performs — ``mutation.mutate(...)`` followed by
``target.execute(...)`` — while varying the mutation-strategy weighting.

Safety: this only exercises the framework's mock targets; it introduces no new
capability and stays entirely within the authorized-research boundary.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_INT, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MetricSpec, Observation

from ios_research import mutation, targets
from ios_research.targets.base import Outcome

# The strategy set the FuzzEngine draws from (order fixed for reproducibility).
STRATEGIES = mutation.STRATEGIES

# Distinct crash classifications reachable in the mock:parser target — the
# denominator for coverage growth.
_KNOWN_SIGNATURES = 6

_BASE = b"MOCK" + bytes([1, 1]) + (2).to_bytes(2, "big") + b"ok"
_BUDGET = 60  # cases per fuzzing sample


def _weighted_strategies(config: Mapping[str, Any]) -> tuple[str, ...]:
    """Build a strategy tuple whose repetition encodes each knob's weight.

    ``mutation.mutate`` draws uniformly from the tuple, so repeating a strategy
    ``w`` times gives it weight ``w``. All-zero weights fall back to uniform,
    which is the framework's current default behavior (the baseline).
    """
    out: list[str] = []
    for strat in STRATEGIES:
        weight = int(config.get(f"weight_{strat}", 1))
        out.extend([strat] * max(0, weight))
    return tuple(out) if out else tuple(STRATEGIES)


@register
class IosResearchFuzzerEnvironment(BaseEnvironment):
    """Optimize mutation-strategy weighting for fuzz effectiveness."""

    name = "ios_research_fuzzer"
    cost_per_sample = 0.0  # local execution, no paid API

    knob_list = tuple(
        Knob(name=f"weight_{s}", kind=KNOB_INT, default=1, low=0, high=3, step=1,
             description=f"selection weight for the '{s}' mutation strategy")
        for s in STRATEGIES
    )

    metric_list = (
        MetricSpec(name="unique_crashes_per_100k_cases", direction=MAXIMIZE,
                   unit="crashes",
                   description="distinct crash signatures found, per 100k cases"),
        MetricSpec(name="reproducible_crash_rate", direction=MAXIMIZE,
                   unit="ratio"),
        MetricSpec(name="coverage_growth", direction=MAXIMIZE, unit="percent"),
        MetricSpec(name="executions_per_second", direction=MAXIMIZE,
                   unit="exec/s"),
    )

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        strategies = _weighted_strategies(config)
        target = targets.create("mock:parser")
        struct_fn = target.structure_mutate

        values: dict[str, list[float]] = {
            "unique_crashes_per_100k_cases": [],
            "reproducible_crash_rate": [],
            "coverage_growth": [],
            "executions_per_second": [],
        }

        for s in range(samples):
            sub_seed = seed * 100003 + s  # distinct, deterministic per sample
            signatures: set[str] = set()
            crash_inputs: dict[str, bytes] = {}
            start = time.perf_counter()
            for i in range(_BUDGET):
                data, _ = mutation.mutate(_BASE, sub_seed, i,
                                          strategies=strategies, struct_fn=struct_fn)
                result = target.execute(data)
                if result.outcome in (Outcome.CRASH, Outcome.ABNORMAL) \
                        and result.diagnostics:
                    sig = result.diagnostics.signature
                    if sig not in signatures:
                        signatures.add(sig)
                        crash_inputs[sig] = data
            elapsed = max(time.perf_counter() - start, 1e-9)

            unique = len(signatures)
            # Reproducibility: re-run each discovered input, expect same signature.
            reproduced = 0
            for sig, data in crash_inputs.items():
                r = target.execute(data)
                if r.diagnostics and r.diagnostics.signature == sig:
                    reproduced += 1
            repro_rate = reproduced / unique if unique else 1.0

            values["unique_crashes_per_100k_cases"].append(
                unique / _BUDGET * 100_000)
            values["reproducible_crash_rate"].append(repro_rate)
            values["coverage_growth"].append(
                min(100.0, unique / _KNOWN_SIGNATURES * 100.0))
            values["executions_per_second"].append(_BUDGET / elapsed)

        return self.summarize(Trace(values=values), samples)
