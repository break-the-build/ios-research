"""Bounded, reproducible stage timing for the mock fuzzing pipeline.

The profiler is deliberately a measurement tool, not an optimizer. It runs in
an isolated temporary workspace and only accepts mock targets, making it safe
to repeat locally or in CI without testing a real system.
"""

from __future__ import annotations

import tempfile
import time
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import __version__, mutation, targets
from .clock import now_iso
from .corpus import CorpusStore
from .experiment import ExperimentStore
from .fuzz import FuzzEngine
from .workspace import Workspace


@dataclass
class _Stages:
    seconds: dict[str, float] = field(default_factory=dict)
    calls: dict[str, int] = field(default_factory=dict)

    def measure(self, name: str, fn: Callable, *args, **kwargs):
        started = time.perf_counter()
        try:
            return fn(*args, **kwargs)
        finally:
            self.seconds[name] = self.seconds.get(name, 0.0) + (
                time.perf_counter() - started)
            self.calls[name] = self.calls.get(name, 0) + 1


def profile_campaign(*, target_id: str = "mock:parser", max_cases: int = 1000,
                     seed: int = 0) -> dict[str, Any]:
    """Profile one deterministic mock-target campaign by pipeline stage."""
    if not target_id.startswith("mock:"):
        raise ValueError("benchmark profile accepts mock targets only")
    if max_cases <= 0:
        raise ValueError("max_cases must be positive")

    stages = _Stages()
    with tempfile.TemporaryDirectory(prefix="ios-research-profile-") as tmp:
        workspace = Workspace(Path(tmp) / ".ios-research")
        workspace.init(framework_version=__version__, created_at=now_iso())
        corpus_store = CorpusStore(workspace)
        target = targets.create(target_id)
        corpus = corpus_store.create("profile", target=target_id)
        for data in target.seeds():
            corpus_store.add_bytes(corpus, data, origin="seed")
        experiment = ExperimentStore(workspace).create(
            target=target_id, device="mock:device", os_version="mock",
            config_hash="benchmark-profile-v1", seed=seed,
            params={"driver": "benchmark profile", "max_cases": max_cases})
        engine = FuzzEngine(workspace)
        session = engine.create(
            experiment_id=experiment.id, target=target_id, corpus_id=corpus.id,
            seed=seed, workers=1, max_cases=max_cases, duration_s=None)

        original_mutate = mutation.mutate
        original_create = targets.create
        original_add = engine.corpus_store.add_bytes
        original_save_corpus = engine.corpus_store.save
        original_save_session = engine.save

        def timed_mutate(*args, **kwargs):
            return stages.measure("mutation", original_mutate, *args, **kwargs)

        def timed_create(requested_id: str):
            created = original_create(requested_id)
            original_execute = created.execute

            def timed_execute(*args, **kwargs):
                return stages.measure("target_execution", original_execute,
                                      *args, **kwargs)

            created.execute = timed_execute
            return created

        def timed_add(*args, **kwargs):
            return stages.measure("persistence", original_add, *args, **kwargs)

        def timed_save_corpus(*args, **kwargs):
            return stages.measure("persistence", original_save_corpus,
                                  *args, **kwargs)

        def timed_save_session(*args, **kwargs):
            return stages.measure("persistence", original_save_session,
                                  *args, **kwargs)

        mutation.mutate = timed_mutate
        targets.create = timed_create
        engine.corpus_store.add_bytes = timed_add
        engine.corpus_store.save = timed_save_corpus
        engine.save = timed_save_session
        started = time.perf_counter()
        try:
            completed = engine.advance(session)
        finally:
            mutation.mutate = original_mutate
            targets.create = original_create
            engine.corpus_store.add_bytes = original_add
            engine.corpus_store.save = original_save_corpus
            engine.save = original_save_session
        wall_seconds = time.perf_counter() - started

    # Mock targets do not produce sanitizer reports. Keep this explicit in the
    # stable result shape rather than misattributing target execution time.
    stages.seconds.setdefault("sanitizer_report_parsing", 0.0)
    stages.calls.setdefault("sanitizer_report_parsing", 0)
    stage_rows = {
        name: {
            "seconds": round(stages.seconds.get(name, 0.0), 6),
            "calls": stages.calls.get(name, 0),
            "wall_percent": round(
                100 * stages.seconds.get(name, 0.0) / wall_seconds, 3)
            if wall_seconds else 0.0,
        }
        for name in ("mutation", "target_execution", "sanitizer_report_parsing",
                     "persistence")
    }
    return {
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "target": target_id,
        "seed": seed,
        "max_cases": max_cases,
        "executed_cases": completed.cursor,
        "wall_seconds": round(wall_seconds, 6),
        "stages": stage_rows,
        "notes": [
            "Mock-target baseline; native harness/sanitizer startup is excluded.",
            "Temporary workspace is removed after profiling.",
        ],
    }
