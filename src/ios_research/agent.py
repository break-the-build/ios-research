"""Agent-facing operations.

These wrap the framework in deterministic, machine-readable operations suitable
for LLM agents (such as Claude Code). Agents get environment inspection, a
schema of the whole CLI, and a bounded end-to-end pipeline.

Agents are explicitly *not* given exploit-deployment, surveillance, persistence,
credential-theft, or sandbox/TCC-bypass capabilities (see `safety.py`).
"""

from __future__ import annotations

from typing import Any

from .analysis import Analyzer
from .context import Context
from .corpus import CorpusStore, Corpus
from .crashes import CrashStore
from .devices import get as get_device
from .experiment import ExperimentStore
from .fuzz import FuzzEngine, DEFAULT_BASE
from .schema import build_cli_schema
from .triage import Triage
from . import targets


class Agent:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.ws = ctx.workspace()

    def status(self) -> dict[str, Any]:
        cs = CrashStore(self.ws)
        return {
            "workspace": str(self.ws.root),
            "counts": {
                "experiments": len(ExperimentStore(self.ws).list()),
                "corpora": len(CorpusStore(self.ws).list()),
                "fuzz_sessions": len(FuzzEngine(self.ws).list()),
                "crashes": len(cs.list()),
                "analyses": len(Analyzer(self.ws).list()),
            },
            "targets": [t["id"] for t in targets.list_targets()],
            "ready": True,
        }

    def inspect(self) -> dict[str, Any]:
        return build_cli_schema()

    def run(self, *, target: str, seed: int, max_cases: int,
            minimize: bool = True) -> dict[str, Any]:
        """Bounded end-to-end pipeline: fuzz -> triage -> analyze -> summarize."""
        cfg = self.ctx.config()
        device = get_device(cfg.get("default_device"))
        exp = ExperimentStore(self.ws).create(
            target=target, device=device.id, os_version=device.os_version,
            config_hash=cfg.hash, seed=seed,
            params={"driver": "agent.run", "max_cases": max_cases})

        corpus = self._pipeline_corpus(target)
        engine = FuzzEngine(self.ws)
        session = engine.create(experiment_id=exp.id, target=target,
                                corpus_id=corpus.id, seed=seed, workers=1,
                                max_cases=max_cases, duration_s=None)
        session = engine.advance(session)

        triage = Triage(self.ws)
        analyzer = Analyzer(self.ws)
        crash_summaries = []
        for crash_id in session.crash_ids:
            crash = triage.crashes.get(crash_id)
            triage.reproduce(crash)
            if minimize:
                triage.minimize(crash)
            analysis = analyzer.analyze(triage.crashes.get(crash_id))
            crash_summaries.append({
                "crash_id": crash_id,
                "classification": crash.classification,
                "indicator": analysis.exploitability_classification,
                "confidence": analysis.confidence,
            })

        return {
            "experiment_id": exp.id,
            "fuzz": session.stats(),
            "unique_crashes": session.unique_crashes,
            "crashes": crash_summaries,
        }

    def analyze(self) -> dict[str, Any]:
        analyses = Analyzer(self.ws).analyze_batch()
        by_indicator: dict[str, int] = {}
        for a in analyses:
            by_indicator[a.exploitability_classification] = \
                by_indicator.get(a.exploitability_classification, 0) + 1
        return {"analyzed": len(analyses), "by_indicator": by_indicator,
                "analysis_ids": [a.id for a in analyses]}

    def experiment(self, *, target: str, seed: int) -> dict[str, Any]:
        cfg = self.ctx.config()
        device = get_device(cfg.get("default_device"))
        exp = ExperimentStore(self.ws).create(
            target=target, device=device.id, os_version=device.os_version,
            config_hash=cfg.hash, seed=seed, params={"driver": "agent.experiment"})
        return {"experiment": exp.to_dict()}

    def _pipeline_corpus(self, target: str) -> Corpus:
        store = CorpusStore(self.ws)
        name = f"agent-{target}"
        for c in store.list():
            if c.name == name:
                return c
        corpus = store.create(name, target=target)
        seeds = targets.create(target).seeds() or [DEFAULT_BASE]
        for seed_bytes in seeds:
            store.add_bytes(corpus, seed_bytes, origin="seed")
        return corpus
