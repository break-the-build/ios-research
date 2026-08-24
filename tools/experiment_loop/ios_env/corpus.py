"""ios_research_corpus environment (goal 07 corpus-quality).

Optimizes mutation-strategy weighting for corpus *quality*: a distilled corpus
that covers many distinct behaviors with few inputs. Rewards high coverage per
input and behavioral diversity while penalizing corpus size.
"""

from __future__ import annotations

from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_INT, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research import mutation, targets
from .common import STRATEGIES, base_input, weights_from_config


@register
class IosResearchCorpusEnvironment(BaseEnvironment):
    name = "ios_research_corpus"
    cost_per_sample = 0.0

    knob_list = tuple(
        Knob(name=f"weight_{s}", kind=KNOB_INT, default=1, low=0, high=6, step=1,
             description=f"selection weight for the '{s}' mutation strategy")
        for s in STRATEGIES
    )

    metric_list = (
        MetricSpec("coverage_per_input", MAXIMIZE, "behaviors/input"),
        MetricSpec("corpus_diversity", MAXIMIZE, "ratio"),
        MetricSpec("unique_behavior_rate", MAXIMIZE, "ratio"),
        MetricSpec("corpus_size", MINIMIZE, "inputs"),
    )

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        weights = weights_from_config(config)
        target = targets.create("mock:parser")
        struct_fn = target.structure_mutate
        base = base_input("mock:parser")
        budget = 80

        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for s in range(samples):
            sub = seed * 100003 + s
            # Distill: keep one input per distinct behavior (outcome+signature).
            behaviors: dict[str, str] = {}   # behavior key -> strategy that found it
            for i in range(budget):
                data, strat = mutation.mutate(base, sub, i, struct_fn=struct_fn,
                                              weights=weights)
                r = target.execute(data)
                sig = r.diagnostics.signature if r.diagnostics else ""
                key = f"{r.outcome}:{sig}"
                behaviors.setdefault(key, strat)
            distinct_behaviors = len(behaviors)          # == distilled corpus size
            strategies_used = len(set(behaviors.values()))

            # Behaviors discovered per case executed: rewards weightings that
            # cover more distinct behaviors within the same budget.
            vals["coverage_per_input"].append(distinct_behaviors / budget)
            vals["corpus_diversity"].append(strategies_used / len(STRATEGIES))
            vals["unique_behavior_rate"].append(distinct_behaviors / budget)
            vals["corpus_size"].append(float(distinct_behaviors))

        return self.summarize(Trace(values=vals), samples)
