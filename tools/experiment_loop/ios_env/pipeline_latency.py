"""ios_research_pipeline_latency environment (goal 24).

Stage-level wall-clock profile of the discovery-to-evidence pipeline:
crash record -> analyze -> reproduce/minimize -> report -> bounty-validate.
Every run emits a per-stage breakdown, so the environment doubles as the
framework's latency *observability* baseline: regressions show up as stage
shares shifting, not just as a slower total.

All stages are optional knobs mirroring real campaign choices; defaults
(all off) measure the minimal pipeline.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_BOOL, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research.analysis import Analyzer
from ios_research.bounty import BountyReadiness
from ios_research.crashes import CrashStore
from ios_research.report import ReportGenerator
from ios_research.targets.base import Outcome
from ios_research.triage import Triage
from .common import temp_workspace

_CRASH_INPUTS = [
    b"MOCK\x01\x01\xff\xff" + b"A" * 40,
    b"MOCK\x01\xff\x00\x00",
    b"MOCK\x01\x01\x00\x02\xde\xad" + b"B" * 30,
]

_METADATA = {
    "contact": "researcher@example.test",
    "attestations": {"authorized_testing": True},
}

_STAGES = ("record", "analysis", "triage", "report", "validation")


@register
class IosResearchPipelineLatencyEnvironment(BaseEnvironment):
    name = "ios_research_pipeline_latency"
    cost_per_sample = 0.0

    knob_list = (
        Knob(name="do_analyze", kind=KNOB_BOOL, default=False,
             description="run exploitability analysis on each crash"),
        Knob(name="do_reproduce", kind=KNOB_BOOL, default=False,
             description="reproduce each crash before reporting"),
        Knob(name="do_minimize", kind=KNOB_BOOL, default=False,
             description="minimize each crash input before reporting"),
    )

    metric_list = (
        MetricSpec("pipeline_total_seconds", MINIMIZE, "seconds"),
        MetricSpec("triage_stage_seconds", MINIMIZE, "seconds"),
        MetricSpec("report_stage_seconds", MINIMIZE, "seconds"),
        MetricSpec("validation_stage_seconds", MINIMIZE, "seconds"),
        MetricSpec("stages_completed", MAXIMIZE, "count"),
    )

    def _one(self, data: bytes, *, do_analyze: bool, do_reproduce: bool,
             do_minimize: bool) -> dict[str, float]:
        with temp_workspace() as ws:
            from ios_research import targets as targets_mod
            target = targets_mod.create("mock:parser")
            result = target.execute(data)
            if result.outcome != Outcome.CRASH:
                raise ValueError("seeded input did not crash the mock target")

            spent = dict.fromkeys(_STAGES, 0.0)

            t0 = time.perf_counter()
            crash = CrashStore(ws).record(
                experiment_id="exp1", target="mock:parser", fmt="mock-record",
                data=data, exec_result=result)
            spent["record"] = time.perf_counter() - t0

            if do_analyze:
                t0 = time.perf_counter()
                Analyzer(ws).analyze(crash)
                spent["analysis"] = time.perf_counter() - t0

            triage = Triage(ws)
            t0 = time.perf_counter()
            if do_reproduce:
                triage.reproduce(crash)
                crash = triage.crashes.get(crash.id)
            if do_minimize:
                triage.minimize(crash)
                crash = triage.crashes.get(crash.id)
            spent["triage"] = time.perf_counter() - t0

            t0 = time.perf_counter()
            report = ReportGenerator(ws).create(crash.id)
            spent["report"] = time.perf_counter() - t0

            t0 = time.perf_counter()
            BountyReadiness(ws).validate(report, _METADATA)
            spent["validation"] = time.perf_counter() - t0

            out = {"pipeline_total_seconds": sum(spent.values())}
            for stage in _STAGES:
                out[f"{stage}_stage_seconds"] = spent[stage]
            completed = sum(1 for s in _STAGES if spent[s] > 0.0)
            out["stages_completed"] = float(completed)
            return out

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for s in range(samples):
            data = _CRASH_INPUTS[(seed + s) % len(_CRASH_INPUTS)]
            for name, value in self._one(
                    data,
                    do_analyze=bool(config.get("do_analyze", False)),
                    do_reproduce=bool(config.get("do_reproduce", False)),
                    do_minimize=bool(config.get("do_minimize", False)),
            ).items():
                vals.setdefault(name, []).append(value)
        return self.summarize(Trace(values=vals), samples)
