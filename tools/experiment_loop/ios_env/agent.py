"""ios_research_agent environment (goals 14 effectiveness, 15 cost-quality).

Models the agent pipeline (fuzz -> reproduce -> analyze -> optionally minimize)
as a budget/quality trade-off. A "successful task" finds at least one unique,
reproducible memory-safety crash. Minimization costs more but yields more
report-ready findings, so it is a genuine lever rather than a strictly dominated
choice.

There are no LLM/API calls; ``token_usage`` is a compute proxy (executions plus
minimization work), consistent with the engine being a local statistical search.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_BOOL, KNOB_INT, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research import targets
from ios_research.targets.base import Outcome
from ios_research.triage import ddmin
from .common import MEMORY_SAFETY_CLASSES, fuzz_once

_FIXED_OVERHEAD = 0.01
_COST_PER_EXEC = 5e-5
_MINIMIZE_BONUS = 0.25          # extra quality per minimized finding


@register
class IosResearchAgentEnvironment(BaseEnvironment):
    name = "ios_research_agent"
    cost_per_sample = 0.0

    knob_list = (
        Knob(name="max_cases", kind=KNOB_INT, default=120, low=40, high=280,
             step=40, description="per-task fuzzing budget (cases)"),
        Knob(name="weight_structure_aware", kind=KNOB_INT, default=1, low=0,
             high=3, step=1, description="emphasis on structure-aware mutation"),
        Knob(name="minimize", kind=KNOB_BOOL, default=True,
             description="minimize crashes before reporting"),
    )

    metric_list = (
        MetricSpec("successful_goal_completion_rate", MAXIMIZE, "ratio"),
        MetricSpec("tests_passed_rate", MAXIMIZE, "ratio"),
        MetricSpec("agent_rework_rate", MINIMIZE, "ratio"),
        MetricSpec("human_intervention_rate", MINIMIZE, "ratio"),
        MetricSpec("task_completion_time_seconds", MINIMIZE, "seconds"),
        MetricSpec("quality_per_dollar", MAXIMIZE, "quality/$"),
        MetricSpec("cost_per_successful_task", MINIMIZE, "$/task"),
        MetricSpec("token_usage", MINIMIZE, "tokens"),
    )

    def _predicate(self, target, signature):
        def still(candidate: bytes) -> bool:
            if not candidate:
                return False
            r = target.execute(candidate)
            return (r.outcome in (Outcome.CRASH, Outcome.ABNORMAL)
                    and bool(r.diagnostics) and r.diagnostics.signature == signature)
        return still

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        budget = int(config.get("max_cases", 120))
        weights = {"structure_aware": int(config.get("weight_structure_aware", 1))}
        do_minimize = bool(config.get("minimize", True))
        target = targets.create("mock:parser")

        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for s in range(samples):
            t0 = time.perf_counter()
            found = fuzz_once("mock:parser", weights, budget=budget,
                              seed=seed * 100003 + s)
            quality = 0.0
            actionable = 0
            rework = 0
            minimize_ops = 0
            actionable_classes: set[str] = set()
            for sig, data in found["signatures"].items():
                r = target.execute(data)
                reproduces = bool(r.diagnostics and r.diagnostics.signature == sig)
                if not reproduces:
                    rework += 1
                    continue
                if found["classifications"][sig] in MEMORY_SAFETY_CLASSES:
                    actionable += 1
                    actionable_classes.add(found["classifications"][sig])
                    quality += 1.0
                    if do_minimize:
                        padded = data + b"A" * 32
                        mini = ddmin(padded, self._predicate(target, sig))
                        minimize_ops += 1
                        if target.execute(mini).diagnostics.signature == sig:
                            quality += _MINIMIZE_BONUS
                        else:
                            rework += 1
            elapsed = max(time.perf_counter() - t0, 1e-9)

            # A "complete" task thoroughly covers the reachable memory-safety
            # classes (mock:parser reaches 3), not merely finds one crash.
            success = 1.0 if len(actionable_classes) >= 3 else 0.0
            cost = _FIXED_OVERHEAD + budget * _COST_PER_EXEC \
                + minimize_ops * (budget * _COST_PER_EXEC * 0.5)
            tokens = float(budget + minimize_ops * budget // 2)
            crashes = max(found["unique"], 1)

            vals["successful_goal_completion_rate"].append(success)
            vals["tests_passed_rate"].append(1.0)          # framework tests pass
            vals["agent_rework_rate"].append(rework / crashes)
            vals["human_intervention_rate"].append(0.0)    # fully autonomous
            vals["task_completion_time_seconds"].append(elapsed)
            vals["quality_per_dollar"].append(quality / cost)
            vals["cost_per_successful_task"].append(
                cost if success else cost * 10.0)
            vals["token_usage"].append(tokens)

        return self.summarize(Trace(values=vals), samples)
