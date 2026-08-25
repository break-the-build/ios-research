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
        original_write_bytes = workspace.write_bytes
        original_write_json = workspace.write_json

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

        def timed_write_bytes(rel, *args, **kwargs):
            name = "input_writes" if "/inputs/" in rel else "other_writes"
            return stages.measure(name, original_write_bytes, rel, *args,
                                  **kwargs)

        def timed_write_json(rel, *args, **kwargs):
            if rel.startswith("corpus/"):
                name = "corpus_manifests"
            elif rel.startswith("crashes/"):
                name = "crash_records"
            elif rel.startswith("fuzz/"):
                name = "session_checkpoints"
            else:
                name = "other_metadata"
            return stages.measure(name, original_write_json, rel, *args,
                                  **kwargs)

        mutation.mutate = timed_mutate
        targets.create = timed_create
        workspace.write_bytes = timed_write_bytes
        workspace.write_json = timed_write_json
        started = time.perf_counter()
        try:
            completed = engine.advance(session)
        finally:
            mutation.mutate = original_mutate
            targets.create = original_create
            workspace.write_bytes = original_write_bytes
            workspace.write_json = original_write_json
        wall_seconds = time.perf_counter() - started

    # Mock targets do not produce sanitizer reports. Keep this explicit in the
    # stable result shape rather than misattributing target execution time.
    stages.seconds.setdefault("sanitizer_report_parsing", 0.0)
    stages.calls.setdefault("sanitizer_report_parsing", 0)
    persistence_names = ("input_writes", "corpus_manifests", "crash_records",
                         "session_checkpoints", "other_writes",
                         "other_metadata")
    persistence_seconds = sum(stages.seconds.get(name, 0.0)
                              for name in persistence_names)
    persistence_calls = sum(stages.calls.get(name, 0) for name in persistence_names)
    stages.seconds["persistence"] = persistence_seconds
    stages.calls["persistence"] = persistence_calls
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
        "persistence_breakdown": {
            name: {
                "seconds": round(stages.seconds.get(name, 0.0), 6),
                "calls": stages.calls.get(name, 0),
            }
            for name in persistence_names
        },
        "notes": [
            "Mock-target baseline; native harness/sanitizer startup is excluded.",
            "Temporary workspace is removed after profiling.",
        ],
    }


def profile_native_campaign(*, target_id: str, max_cases: int,
                            acknowledged: bool) -> dict[str, Any]:
    """Profile a bounded, explicitly authorized macOS harness locally.

    No campaign workspace or inputs are retained. Startup is estimated from an
    empty-input run; the remaining harness time is reported as target decode.
    """
    if not acknowledged:
        raise ValueError("pass --acknowledge-authorized-use for native profiling")
    if not target_id.startswith("mac:") or max_cases <= 0:
        raise ValueError("native profiling requires mac:<target> and positive cases")
    from .targets import mac

    target = targets.create(target_id)
    if not target.available():
        raise ValueError(f"native harness for {target_id} is not available")
    seeds = target.seeds()
    if not seeds:
        raise ValueError(f"native target {target_id} has no seed inputs")
    stages = _Stages()
    original_run = mac.subprocess.run
    original_parse = mac.asan.parse

    def timed_run(*args, **kwargs):
        return stages.measure("harness_process", original_run, *args, **kwargs)

    def timed_parse(*args, **kwargs):
        return stages.measure("sanitizer_report_parsing", original_parse,
                              *args, **kwargs)

    mac.subprocess.run = timed_run
    mac.asan.parse = timed_parse
    started = time.perf_counter()
    try:
        # A single empty-input run estimates executable/process startup. It is
        # deliberately reported separately and never treated as a decode.
        target.execute(b"")
        startup = stages.seconds.get("harness_process", 0.0)
        before = stages.seconds.get("harness_process", 0.0)
        for index in range(max_cases):
            target.execute(seeds[index % len(seeds)])
        process_seconds = stages.seconds.get("harness_process", 0.0) - before
    finally:
        mac.subprocess.run = original_run
        mac.asan.parse = original_parse
    wall_seconds = time.perf_counter() - started
    startup_per_case = startup
    decode_seconds = max(0.0, process_seconds - startup_per_case * max_cases)
    return {
        "target": target_id,
        "max_cases": max_cases,
        "executed_cases": max_cases,
        "wall_seconds": round(wall_seconds, 6),
        "stages": {
            "mutation": {"seconds": 0.0, "calls": 0},
            "process_startup": {"seconds": round(startup, 6), "calls": 1},
            "target_execution": {"seconds": round(decode_seconds, 6),
                                 "calls": max_cases},
            "sanitizer_report_parsing": {
                "seconds": round(stages.seconds.get("sanitizer_report_parsing", 0.0), 6),
                "calls": stages.calls.get("sanitizer_report_parsing", 0)},
            "persistence": {"seconds": 0.0, "calls": 0},
        },
        "notes": [
            "No campaign workspace or input artifacts are retained.",
            "Target execution is process time less one empty-input startup estimate per case.",
        ],
    }
