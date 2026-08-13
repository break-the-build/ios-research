"""ios_research_reporting environment (goal 17 report-quality).

Optimizes the report *pipeline*: whether the crash is reproduced and minimized
before the report is generated. Minimizing adds a minimized-input artifact and
hash (more complete, more traceable evidence); reproducing substantiates the
report's reproducibility claim. Both cost a little time — a genuine
quality/latency trade-off.

The environment's control (both knobs off) mirrors the current `report create`
behavior, so a winning configuration maps directly onto a framework improvement.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_BOOL, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research import targets
from ios_research.artifacts import ArtifactStore
from ios_research.crashes import CrashStore
from ios_research.report import ReportGenerator
from ios_research.targets.base import Outcome
from ios_research.triage import Triage
from .common import temp_workspace

# A spread of deterministic crash-inducing inputs (distinct classifications).
_CRASH_INPUTS = [
    b"MOCK\x01\x01\xff\xff" + b"A" * 40,          # OUT_OF_BOUNDS_READ
    b"MOCK\x01\xff\x00\x00",                       # NULL_DEREFERENCE
    b"MOCK\x01\x01\x00\x02\xde\xad" + b"B" * 30,   # USE_AFTER_FREE
    b"MOCK\x01\x01\x00\x02\x7fT" + b"C" * 30,      # TYPE_CONFUSION
]

# Core evidence fields a complete report should carry.
_EVIDENCE_FIELDS = ("input_sha256", "minimized_sha256", "crash_signature",
                    "analysis_id", "diagnostic_reference")


@register
class IosResearchReportingEnvironment(BaseEnvironment):
    name = "ios_research_reporting"
    cost_per_sample = 0.0

    knob_list = (
        Knob(name="minimize_before_report", kind=KNOB_BOOL, default=False,
             description="minimize the crash before generating the report"),
        Knob(name="reproduce_before_report", kind=KNOB_BOOL, default=False,
             description="confirm reproduction before generating the report"),
    )

    metric_list = (
        MetricSpec("report_quality_score", MAXIMIZE, "score"),
        MetricSpec("evidence_completeness", MAXIMIZE, "ratio"),
        MetricSpec("claim_traceability", MAXIMIZE, "ratio"),
        MetricSpec("unsupported_claim_rate", MINIMIZE, "ratio"),
        MetricSpec("report_generation_time_seconds", MINIMIZE, "seconds"),
    )

    def _one(self, data: bytes, *, minimize: bool, reproduce: bool):
        with temp_workspace() as ws:
            target = targets.create("mock:parser")
            result = target.execute(data)
            assert result.outcome == Outcome.CRASH
            crash = CrashStore(ws).record(
                experiment_id="exp1", target="mock:parser", fmt="mock-record",
                data=data, exec_result=result)

            triage = Triage(ws)
            t0 = time.perf_counter()
            if reproduce:
                triage.reproduce(crash)
                crash = triage.crashes.get(crash.id)
            if minimize:
                triage.minimize(crash)
                crash = triage.crashes.get(crash.id)

            gen = ReportGenerator(ws)
            report = gen.create(crash.id)
            validation = gen.validate(report)
            elapsed = time.perf_counter() - t0

            ev = report.evidence
            completeness = sum(1 for f in _EVIDENCE_FIELDS if ev.get(f)) \
                / len(_EVIDENCE_FIELDS)

            # Traceability: every referenced artifact/attachment exists on disk.
            store = ArtifactStore(ws)
            refs, present = 0, 0
            for h in ev.get("testcase_hashes", []):
                refs += 1
                present += 1 if store.exists(h) else 0
            for att in report.sections.get("attachments", []):
                if att is None:
                    continue
                refs += 1
                present += 1 if ws.path(att).exists() else 0
            traceability = present / refs if refs else 1.0

            checked = max(1, validation.get("checked_sections", 1))
            unsupported = len(validation.get("issues", [])) / checked

            quality = (0.5 * completeness + 0.3 * traceability
                       + 0.2 * (1.0 - unsupported))
            return {
                "report_quality_score": quality,
                "evidence_completeness": completeness,
                "claim_traceability": traceability,
                "unsupported_claim_rate": unsupported,
                "report_generation_time_seconds": elapsed,
            }

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        minimize = bool(config.get("minimize_before_report", False))
        reproduce = bool(config.get("reproduce_before_report", False))
        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for s in range(samples):
            data = _CRASH_INPUTS[(seed + s) % len(_CRASH_INPUTS)]
            for name, value in self._one(
                    data, minimize=minimize, reproduce=reproduce).items():
                vals[name].append(value)
        return self.summarize(Trace(values=vals), samples)
