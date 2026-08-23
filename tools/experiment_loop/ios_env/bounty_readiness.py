"""ios_research_bounty_readiness environment (goal 21).

Measures how much of the Apple-bounty evidence chain a pipeline configuration
produces: reproduction + minimization before export drive the
``report bounty-validate`` checklist, and the export pack must stay
byte-deterministic. This is the goal closest to the framework's stated
ultimate purpose (submission-ready responsible-disclosure evidence); it still
measures only *local evidence readiness*, never bounty eligibility.

The control (both knobs off) mirrors a bare ``crash -> report -> export``
pipeline; winning configurations map onto documented researcher workflow.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_BOOL, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research.bounty import BountyReadiness
from ios_research.crashes import CrashStore
from ios_research.report import ReportGenerator
from ios_research.targets.base import Outcome
from ios_research.triage import Triage
from .common import temp_workspace

_CRASH_INPUTS = [
    b"MOCK\x01\x01\xff\xff" + b"A" * 40,          # OUT_OF_BOUNDS_READ
    b"MOCK\x01\xff\x00\x00",                       # NULL_DEREFERENCE
    b"MOCK\x01\x01\x00\x02\xde\xad" + b"B" * 30,   # USE_AFTER_FREE
    b"MOCK\x01\x01\x00\x02\x7fT" + b"C" * 30,      # TYPE_CONFUSION
]

_METADATA = {
    "contact": "researcher@example.test",
    "attestations": {"authorized_testing": True},
}


@register
class IosResearchBountyReadinessEnvironment(BaseEnvironment):
    name = "ios_research_bounty_readiness"
    cost_per_sample = 0.0

    knob_list = (
        Knob(name="reproduce_before_export", kind=KNOB_BOOL, default=False,
             description="confirm crash reproduction before evidence export"),
        Knob(name="minimize_before_export", kind=KNOB_BOOL, default=False,
             description="minimize the crash input before evidence export"),
    )

    metric_list = (
        MetricSpec("validation_pass_rate", MAXIMIZE, "ratio",
                   description="share of bounty-validate checks that pass"),
        MetricSpec("missing_checks", MINIMIZE, "count"),
        MetricSpec("export_determinism", MAXIMIZE, "ratio",
                   description="1.0 when two exports produce identical packs"),
        MetricSpec("pack_artifacts", MAXIMIZE, "count"),
        MetricSpec("evidence_pipeline_seconds", MINIMIZE, "seconds"),
    )

    def _one(self, data: bytes, *, reproduce: bool, minimize: bool) -> dict:
        with temp_workspace() as ws:
            t0 = time.perf_counter()
            from ios_research import targets as targets_mod
            target = targets_mod.create("mock:parser")
            result = target.execute(data)
            if result.outcome != Outcome.CRASH:  # defensive: seeded inputs
                raise ValueError("seeded input did not crash the mock target")
            crash = CrashStore(ws).record(
                experiment_id="exp1", target="mock:parser", fmt="mock-record",
                data=data, exec_result=result)

            triage = Triage(ws)
            if reproduce:
                triage.reproduce(crash)
                crash = triage.crashes.get(crash.id)
            if minimize:
                triage.minimize(crash)
                crash = triage.crashes.get(crash.id)

            report = ReportGenerator(ws).create(crash.id)
            readiness = BountyReadiness(ws)
            verdict = readiness.validate(report, _METADATA)
            elapsed = time.perf_counter() - t0

            checks = verdict.get("checks", [])
            passed = sum(1 for c in checks if c.get("passed")) \
                if checks else 0
            total = max(1, len(checks))
            missing = len(verdict.get("missing", []))

            first = readiness.pack(report, _METADATA)
            second = readiness.pack(report, _METADATA)
            deterministic = 1.0 if first == second else 0.0

            return {
                "validation_pass_rate": passed / total,
                "missing_checks": float(missing),
                "export_determinism": deterministic,
                "pack_artifacts": float(len(first.get("artifacts", []))),
                "evidence_pipeline_seconds": elapsed,
            }

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        reproduce = bool(config.get("reproduce_before_export", False))
        minimize = bool(config.get("minimize_before_export", False))
        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for s in range(samples):
            data = _CRASH_INPUTS[(seed + s) % len(_CRASH_INPUTS)]
            for name, value in self._one(
                    data, reproduce=reproduce, minimize=minimize).items():
                vals[name].append(value)
        return self.summarize(Trace(values=vals), samples)
