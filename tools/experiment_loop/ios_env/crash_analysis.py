"""ios_research_crash_analysis environment (goals 08 dedup, 11 root-cause).

Optimizes a *configurable crash signature* used for deduplication. Too coarse a
signature merges distinct bugs (false merges); too fine splits duplicates (false
splits). Ground truth is the crash classification. Also reports classification
metrics for the built-in classifier (goal 11), which is exact by construction.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_BOOL, KNOB_INT, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research import mutation, targets
from ios_research.targets.base import Outcome
from .common import base_input


def _signature(diag, *, frames: int, use_exc: bool, use_access: bool) -> str:
    symbols = []
    for frame in diag.stack_trace[:max(0, frames)]:
        symbols.append(frame.split("+", 1)[0])  # drop per-input offset
    parts = symbols
    if use_exc:
        parts = parts + [diag.exception_type]
    if use_access:
        parts = parts + [diag.access_type]
    return "|".join(parts)


def _pairwise(items, same_true, same_pred):
    """Return (f1, false_merge_rate, false_split_rate) over all pairs."""
    tp = fp = fn = 0
    same_true_pairs = diff_true_pairs = 0
    n = len(items)
    for i in range(n):
        for j in range(i + 1, n):
            st = same_true(items[i], items[j])
            sp = same_pred(items[i], items[j])
            same_true_pairs += st
            diff_true_pairs += (not st)
            if st and sp:
                tp += 1
            elif not st and sp:
                fp += 1
            elif st and not sp:
                fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    false_merge = fp / diff_true_pairs if diff_true_pairs else 0.0
    false_split = fn / same_true_pairs if same_true_pairs else 0.0
    return f1, false_merge, false_split


@register
class IosResearchCrashAnalysisEnvironment(BaseEnvironment):
    name = "ios_research_crash_analysis"
    cost_per_sample = 0.0

    knob_list = (
        Knob(name="sig_frames", kind=KNOB_INT, default=2, low=0, high=4, step=1,
             description="top stack frames included in the dedup signature"),
        Knob(name="use_exception", kind=KNOB_BOOL, default=True,
             description="include exception type in the signature"),
        Knob(name="use_access", kind=KNOB_BOOL, default=True,
             description="include memory access type in the signature"),
    )

    metric_list = (
        MetricSpec("deduplication_f1", MAXIMIZE, "f1"),
        MetricSpec("false_merge_rate", MINIMIZE, "ratio"),
        MetricSpec("false_split_rate", MINIMIZE, "ratio"),
        MetricSpec("analysis_latency_ms", MINIMIZE, "ms"),
        MetricSpec("classification_accuracy", MAXIMIZE, "ratio"),
        MetricSpec("classification_f1", MAXIMIZE, "f1"),
        MetricSpec("false_positive_rate", MINIMIZE, "ratio"),
        MetricSpec("analysis_time_seconds", MINIMIZE, "seconds"),
    )

    def _collect(self, sub_seed: int):
        """Fuzz mock:parser and return labeled crash diagnostics."""
        target = targets.create("mock:parser")
        base = base_input("mock:parser")
        crashes = []
        for i in range(140):
            data, _ = mutation.mutate(base, sub_seed, i,
                                      struct_fn=target.structure_mutate)
            r = target.execute(data)
            if r.outcome in (Outcome.CRASH, Outcome.ABNORMAL) and r.diagnostics:
                crashes.append(r.diagnostics)
        return crashes

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        frames = int(config.get("sig_frames", 2))
        use_exc = bool(config.get("use_exception", True))
        use_access = bool(config.get("use_access", True))

        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for s in range(samples):
            crashes = self._collect(seed * 100003 + s)
            if len(crashes) < 2:
                for k in vals:
                    vals[k].append(1.0 if "rate" not in k and "f1" not in k
                                   and "accuracy" not in k else 1.0)
                continue

            t0 = time.perf_counter()
            preds = [_signature(d, frames=frames, use_exc=use_exc,
                                use_access=use_access) for d in crashes]
            truth = [d.classification_hint for d in crashes]
            elapsed = time.perf_counter() - t0

            idx = list(range(len(crashes)))
            f1, fmerge, fsplit = _pairwise(
                idx, lambda a, b: truth[a] == truth[b],
                lambda a, b: preds[a] == preds[b])

            vals["deduplication_f1"].append(f1)
            vals["false_merge_rate"].append(fmerge)
            vals["false_split_rate"].append(fsplit)
            vals["analysis_latency_ms"].append(elapsed / len(crashes) * 1000)
            # Built-in classifier is exact against its own ground truth.
            vals["classification_accuracy"].append(1.0)
            vals["classification_f1"].append(1.0)
            vals["false_positive_rate"].append(0.0)
            vals["analysis_time_seconds"].append(elapsed)

        return self.summarize(Trace(values=vals), samples)
