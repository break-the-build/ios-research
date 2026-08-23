"""Continuous regression fuzzing, symbolication, and flaky triage (#49).

One-off campaigns decay into noise. This module wraps the fuzz engine in a
*repeatable*, bounded campaign that can be scheduled in CI against declared,
authorized targets:

* **Stability triage** — every unique crash signature is replayed a fixed
  number of times; signatures reproducing 100% are ``confirmed``, partial ones
  are isolated as ``flaky`` and are never auto-promoted to confirmed findings,
* **Trend reports** — each campaign appends an append-only, machine-readable
  trend entry (executions, coverage features, corpus size, crash counts)
  diffable against the previous run,
* **Optional symbolication** — a researcher-supplied symbol map rewrites
  normalized stack frames; anything not covered by the map is emitted as an
  explicitly ``(unsymbolicated)`` frame rather than silently passed through,
* **Regression gate** — replays a corpus across two target versions and only
  passes when every flagged regression *reproduces stably*.

All execution stays inside the existing authorized-target boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from . import differential, targets
from .clock import now_iso
from .corpus import CorpusStore
from .errors import NotFoundError, StateError, ValidationError
from .fuzz import FuzzEngine
from .hashing import sha256_text
from .ids import make_id
from .targets.base import Outcome
from .workspace import Workspace

CAMPAIGN_SCHEMA_VERSION = 1
MAX_TRIALS = 50


def apply_symbol_map(frames: list[str],
                     symbol_map: dict[str, str] | None) -> list[str]:
    """Rewrite frames via a researcher-supplied map; mark the rest explicitly."""
    if not symbol_map:
        return [f"{frame} (unsymbolicated)" for frame in frames]
    out = []
    for frame in frames:
        replacement = None
        for needle, symbol in symbol_map.items():
            if needle and needle in frame:
                replacement = f"{frame.split(' ')[0]} {symbol}".strip()
                break
        if replacement is None:
            replacement = f"{frame} (unsymbolicated)"
        out.append(replacement)
    return out


@dataclass
class CampaignRecord:
    id: str
    target: str
    cases: int
    seed: int
    created_at: str
    status: str = "created"
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RegressionCampaignEngine:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.fuzz_engine = FuzzEngine(workspace)

    # persistence -----------------------------------------------------------
    def _rel(self, campaign_id: str) -> str:
        return f"research/{campaign_id}.json"

    def _trend_rel(self, campaign_id: str) -> str:
        return f"research/{campaign_id}-trend.json"

    def get(self, campaign_id: str) -> CampaignRecord:
        if not self.ws.path(self._rel(campaign_id)).exists():
            raise NotFoundError(f"campaign '{campaign_id}' not found")
        return CampaignRecord(**self.ws.read_json(self._rel(campaign_id)))

    def list(self) -> list[CampaignRecord]:
        base = self.ws.dir("research")
        out = []
        for manifest in sorted(base.glob("camp_*.json")):
            name = manifest.name.replace("-trend.json", ".json")
            if manifest.name == name:
                out.append(CampaignRecord(
                    **self.ws.read_json(str(manifest.relative_to(
                        self.ws.root)))))
        return out

    # execution ---------------------------------------------------------------
    def run(self, *, target_id: str, cases: int, seed: int = 0,
            trials: int = 3, symbol_map: dict[str, str] | None = None,
            dictionary_path: str | None = None) -> dict[str, Any]:
        if not targets.is_registered(target_id):
            raise NotFoundError(f"unknown target '{target_id}'")
        if not 1 <= trials <= MAX_TRIALS:
            raise ValidationError(f"trials must be 1..{MAX_TRIALS}")

        experiment_id = make_id("experiment", "campaign", target_id,
                                str(seed), now_iso())
        corpus_store = CorpusStore(self.ws)
        corpus_name = f"campaign-{target_id}"
        existing = [c for c in corpus_store.list() if c.name == corpus_name]
        corpus = existing[0] if existing else corpus_store.create(
            corpus_name, target=target_id)
        if not corpus.testcases:
            for seed_bytes in (targets.create(target_id).seeds()
                               or [b"MOCK\x01\x01\x00\x02ok"]):
                corpus_store.add_bytes(corpus, seed_bytes, origin="seed")

        session = self.fuzz_engine.create(
            experiment_id=experiment_id, target=target_id,
            corpus_id=corpus.id, seed=seed, workers=1,
            max_cases=cases, duration_s=None,
            dictionary_path=dictionary_path)
        before_features = set(session.coverage_features)
        before_corpus = len(corpus.testcases)
        session = self.fuzz_engine.advance(session)

        # Stability triage over each unique signature.
        target = targets.create(target_id)
        from .crashes import CrashStore
        triage: dict[str, dict[str, Any]] = {}
        store = CrashStore(self.ws)
        for crash in store.list(experiment_id=experiment_id):
            input_bytes = store.input_bytes(crash)
            reproductions = 0
            signatures: list[str] = []
            for _trial in range(trials):
                result = target.execute(input_bytes)
                if result.outcome == Outcome.CRASH:
                    reproductions += 1
                    signatures.append(result.diagnostics.signature
                                      if result.diagnostics else "sig_none")
            dominant = max(signatures, key=signatures.count) \
                if signatures else ""
            rate = reproductions / trials
            if reproductions == trials and \
                    signatures.count(dominant) == trials:
                status = "confirmed"
            elif reproductions:
                status = "flaky"          # never auto-promoted (#49)
            else:
                status = "not_reproducing"
            triage[crash.signature] = {
                "status": status,
                "reproduction_rate": round(rate, 4),
                "signature_stability": round(
                    signatures.count(dominant) / len(signatures), 4)
                if signatures else 0.0,
                "trials": trials,
            }

        after_corpus = len(corpus_store.get(corpus.id).testcases)
        summary = {
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "target": target_id,
            "cases": session.cursor,
            "seed": seed,
            "unique_signatures": len(triage),
            "confirmed": sum(1 for t in triage.values()
                             if t["status"] == "confirmed"),
            "flaky_isolated": sum(1 for t in triage.values()
                                  if t["status"] == "flaky"),
            "not_reproducing": sum(1 for t in triage.values()
                                   if t["status"] == "not_reproducing"),
            "signatures": triage,
            "corpus_size": {"before": before_corpus, "after": after_corpus},
            "coverage_features": {
                "before": len(before_features),
                "after": len(session.coverage_features),
            },
        }
        if symbol_map:
            summary["symbolication"] = {
                "applied": True,
                "mapped_entries": len(symbol_map),
                "note": ("frames not covered by the researcher-supplied map "
                         "are reported as explicitly unsymbolicated"),
            }

        campaign_id = make_id("campaign", target_id, str(cases), str(seed))
        # Compute the trend entry BEFORE persisting this record so "previous"
        # really means the prior campaign, never this one.
        trend = self._trend_entry(campaign_id, summary)
        record = CampaignRecord(id=campaign_id, target=target_id,
                                cases=session.cursor, seed=seed,
                                created_at=now_iso(), status="run",
                                # Full metric snapshot so the next run's
                                # trend entry can compute deltas.
                                summary={
                                    "cases": session.cursor,
                                    "confirmed": summary["confirmed"],
                                    "flaky_isolated":
                                        summary["flaky_isolated"],
                                    "corpus_size":
                                        summary["corpus_size"],
                                    "coverage_features":
                                        summary["coverage_features"],
                                })
        self.ws.write_json(self._rel(campaign_id), record.to_dict())
        self.ws.write_json(self._trend_rel(campaign_id), trend)
        return summary | {"campaign_id": campaign_id}

    def _trend_entry(self, campaign_id: str,
                     summary: dict[str, Any]) -> dict[str, Any]:
        previous = self.latest()
        entry = {
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": campaign_id,
            "target": summary["target"],
            "created_at": now_iso(),
            "metrics": {
                "cases": summary["cases"],
                "corpus_size": summary["corpus_size"]["after"],
                "coverage_features": summary["coverage_features"]["after"],
                "confirmed_crashes": summary["confirmed"],
                "flaky_isolated": summary["flaky_isolated"],
            },
        }
        if previous is not None and previous.summary:
            prev_trend = previous.summary
            entry["delta_vs_previous"] = {
                key: (summary_metric - prev_metric)
                for key, summary_metric, prev_metric in (
                    ("cases", summary["cases"],
                     prev_trend.get("cases", 0)),
                    ("corpus_size", summary["corpus_size"]["after"],
                     prev_trend.get("corpus_size", {}).get("after", 0)),
                    ("coverage_features",
                     summary["coverage_features"]["after"],
                     prev_trend.get("coverage_features", {}).get("after", 0)),
                    ("confirmed_crashes", summary["confirmed"],
                     prev_trend.get("confirmed", 0)),
                    ("flaky_isolated", summary["flaky_isolated"],
                     prev_trend.get("flaky_isolated", 0)),
                )
            }
        else:
            entry["delta_vs_previous"] = None
        return entry

    def latest(self) -> CampaignRecord | None:
        campaigns = self.list()
        return sorted(campaigns, key=lambda c: c.created_at)[-1] \
            if campaigns else None

    # regression gate ------------------------------------------------------------
    def gate(self, *, target_baseline: str, target_candidate: str,
             corpus_id: str | None = None) -> dict[str, Any]:
        """CI gate: flag regressions and require stable reproduction."""
        diff_engine = differential.DifferentialEngine(self.ws)
        diff = diff_engine.create(
            name=f"gate-{target_baseline}-{target_candidate}",
            target_a=target_baseline, target_b=target_candidate,
            config_hash=sha256_text(f"{target_baseline}>{target_candidate}"))
        diff_engine.run(diff)

        candidate = targets.create(target_candidate)
        results = diff_engine.results(diff)
        gated_regressions = []
        for row in results:
            if not row["is_regression"]:
                continue
            data_sha = row["input_sha256"]
            corpus = diff_engine.corpus_store.get(diff.corpus_id)
            blob = diff_engine.corpus_store.read_bytes(corpus, data_sha)
            reproduces = sum(
                1 for _ in range(3)
                if candidate.execute(blob).outcome == Outcome.CRASH)
            gated_regressions.append({
                "input_sha256": data_sha,
                "transition": row["transition"],
                "stably_reproduced": reproduces == 3,
                "reproduction_rate": reproduces / 3,
            })
        passed = bool(gated_regressions) is False or all(
            r["stably_reproduced"] for r in gated_regressions)
        report = {
            "kind": "regression-gate",
            "diff_id": diff.id,
            "target_baseline": target_baseline,
            "target_candidate": target_candidate,
            "regressions_flagged": len(gated_regressions),
            "gated_regressions": gated_regressions,
            "passed": passed,
        }
        self.ws.write_json(f"research/gate-{diff.id}.json", report)
        return report
