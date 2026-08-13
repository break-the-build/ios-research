"""ios_research_fuzzer_engine environment (goal 05 fuzz-throughput, real engine).

Unlike ``ios_research_fuzzer`` (which measures the pure mutate+execute inner
loop), this environment runs the **real** ``FuzzEngine.advance`` against a
throwaway workspace, so ``executions_per_second`` reflects end-to-end behavior
including artifact/corpus/crash persistence — the disk I/O that dominates real
fuzzing throughput.

This makes the persistence costs visible to the optimizer, and exposes a genuine
real-engine trade-off: weightings that crash more discover more bugs but pay more
persistence overhead, so effectiveness and raw throughput can pull in opposite
directions.
"""

from __future__ import annotations

import time
import tracemalloc
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_INT, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research.corpus import CorpusStore
from ios_research.crashes import CrashStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine, DEFAULT_BASE
from .common import STRATEGIES, temp_workspace, weights_from_config


@register
class IosResearchFuzzerEngineEnvironment(BaseEnvironment):
    name = "ios_research_fuzzer_engine"
    cost_per_sample = 0.0

    knob_list = tuple(
        Knob(name=f"weight_{s}", kind=KNOB_INT, default=1, low=0, high=5, step=1,
             description=f"selection weight for the '{s}' mutation strategy")
        for s in STRATEGIES
    ) + (
        Knob(name="max_cases", kind=KNOB_INT, default=800, low=400, high=2000,
             step=400, description="cases per real-engine run"),
    )

    metric_list = (
        MetricSpec("executions_per_second", MAXIMIZE, "exec/s"),
        MetricSpec("unique_inputs_per_second", MAXIMIZE, "inputs/s"),
        MetricSpec("crash_detection_rate", MAXIMIZE, "ratio"),
        MetricSpec("cpu_percent", MINIMIZE, "percent"),
        MetricSpec("memory_mb", MINIMIZE, "MB"),
        # Effectiveness is reported too, so a throughput search does not silently
        # trade away crash discovery.
        MetricSpec("unique_crashes_per_100k_cases", MAXIMIZE, "crashes"),
    )

    def _one_run(self, weights: dict[str, int], max_cases: int, seed: int):
        """Run one real fuzzing session in a throwaway workspace; return metrics."""
        with temp_workspace() as ws:
            exp = ExperimentStore(ws).create(
                target="mock:parser", device="mock:device", os_version="17.0",
                config_hash="c", seed=seed)
            cs = CorpusStore(ws)
            corpus = cs.create("f")
            cs.add_bytes(corpus, DEFAULT_BASE, origin="seed")
            engine = FuzzEngine(ws)
            session = engine.create(
                experiment_id=exp.id, target="mock:parser", corpus_id=corpus.id,
                seed=seed, workers=1, max_cases=max_cases, duration_s=None,
                strategy_weights=weights)

            tracemalloc.start()
            wall0, cpu0 = time.perf_counter(), time.process_time()
            engine.advance(session)
            wall = max(time.perf_counter() - wall0, 1e-9)
            cpu = time.process_time() - cpu0
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            # Distinct interesting inputs preserved (corpus grew beyond the seed).
            new_inputs = max(0, len(cs.get(corpus.id).testcases) - 1)
            # Detection reliability: every recorded crash reproduces its signature.
            crashes = CrashStore(ws).list()
            reproduced = sum(
                1 for c in crashes
                if _reproduces(cs, corpus, ws, c))
            detection = reproduced / len(crashes) if crashes else 1.0

            return {
                "executions_per_second": max_cases / wall,
                "unique_inputs_per_second": new_inputs / wall,
                "crash_detection_rate": detection,
                "cpu_percent": min(100.0, cpu / wall * 100.0),
                "memory_mb": peak / (1024 * 1024),
                "unique_crashes_per_100k_cases":
                    session.unique_crashes / max_cases * 100_000,
            }

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        weights = weights_from_config(config)
        max_cases = int(config.get("max_cases", 800))
        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}
        for s in range(samples):
            metrics = self._one_run(weights, max_cases, seed * 100003 + s)
            for name, value in metrics.items():
                vals[name].append(value)
        return self.summarize(Trace(values=vals), samples)


def _reproduces(cs: CorpusStore, corpus, ws, crash) -> bool:
    """Re-run a crash's stored input and check the signature still matches."""
    from ios_research import targets
    data = CrashStore(ws).input_bytes(crash)
    r = targets.create(crash.target).execute(data)
    return bool(r.diagnostics and r.diagnostics.signature == crash.signature)
