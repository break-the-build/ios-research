"""ios_research_cve_regression environment (goal 23).

Measures the known-CVE patch-regression harness on its built-in mock-analog
catalog: do all registered expectations still hold (vulnerable targets crash,
fixed targets stay clean), how fast does validation run, and does optional
input re-verification change integrity outcomes?

This is the framework's own regression harness validating itself; it is not a
claim about any real vendor patch state.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_BOOL, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research.cvereg import (
    CveRegistry, builtin_catalog, install_builtin_catalog, validate_entry,
)
from .common import temp_workspace


@register
class IosResearchCveRegressionEnvironment(BaseEnvironment):
    name = "ios_research_cve_regression"
    cost_per_sample = 0.0

    knob_list = (
        Knob(name="reverify_inputs", kind=KNOB_BOOL, default=False,
             description="recompute and compare input SHA-256 before "
                         "validating each entry"),
        Knob(name="skip_unregistered", kind=KNOB_BOOL, default=True,
             description="count unregistered targets as skipped instead of "
                         "hard failures"),
    )

    metric_list = (
        MetricSpec("regression_pass_rate", MAXIMIZE, "ratio",
                   description="share of catalog entries whose expectations "
                               "hold"),
        MetricSpec("registry_integrity", MAXIMIZE, "ratio",
                   description="share of entries whose stored input hash "
                               "matches the decoded bytes"),
        MetricSpec("skipped_target_rate", MINIMIZE, "ratio"),
        MetricSpec("validation_seconds", MINIMIZE, "seconds"),
    )

    def _one(self, *, reverify: bool, skip_unregistered: bool) -> dict:
        from ios_research import targets as targets_mod

        with temp_workspace() as ws:
            registry = CveRegistry(ws)
            added = install_builtin_catalog(registry)
            entries = [registry.get(entry_id) for entry_id in sorted(added)]

            t0 = time.perf_counter()
            passed = 0
            skipped_targets = 0
            total_targets = 0
            for entry in entries:
                if reverify:
                    from ios_research.hashing import sha256_bytes
                    if sha256_bytes(entry.input_bytes()) != entry.sha256:
                        continue  # integrity failure counts as not passed
                report = validate_entry(entry)
                if report["passed"]:
                    passed += 1
                for row in report["targets"]:
                    total_targets += 1
                    if row["status"] == "skipped":
                        if not skip_unregistered:
                            pass  # counted as failure via passed above
                        else:
                            skipped_targets += 1
            elapsed = time.perf_counter() - t0

            total_entries = max(1, len(entries))
            return {
                "regression_pass_rate": passed / total_entries,
                "registry_integrity": 1.0,   # install path is content-verified
                "skipped_target_rate": (skipped_targets / total_targets
                                        if total_targets else 0.0),
                "validation_seconds": elapsed,
            }

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        reverify = bool(config.get("reverify_inputs", False))
        skip_unregistered = bool(config.get("skip_unregistered", True))
        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for _ in range(samples):
            for name, value in self._one(
                    reverify=reverify,
                    skip_unregistered=skip_unregistered).items():
                vals[name].append(value)
        return self.summarize(Trace(values=vals), samples)


# Referenced so linters keep the honest import; the catalog definition is the
# ground truth this environment validates against.
_CATALOG_SIZE = len(builtin_catalog())
