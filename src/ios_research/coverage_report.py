"""Coverage, corpus-quality, and target-reachability reports (#34).

Turns a fuzz session's measured coverage into stable, diffable reports:

* **Attribution** — which corpus input introduced each feature.
* **Corpus quality** — hot inputs (power-schedule selections) and
  coverage-preserving minimization savings computed from stored feature sets
  (no re-execution, fully deterministic).
* **Plateau** — cases executed since the last new feature (0 when no adapter).
* **Reachability** — optional user-declared static function/feature inventory
  compared against dynamic coverage to flag likely harness gaps.

Black-box device campaigns have no coverage adapter; their reports explicitly
say so and never fabricate code-coverage numbers. Reports redact secret-shaped
keys before export.
"""

from __future__ import annotations

from typing import Any

from .bounty import redact_value
from .corpus import CorpusStore
from .errors import NotFoundError
from .fuzz import FuzzEngine, FuzzSession

REPORT_SCHEMA_VERSION = 1


class CoverageReporter:
    def __init__(self, workspace):
        self.ws = workspace
        self.engine = FuzzEngine(workspace)
        self.corpus_store = CorpusStore(workspace)

    # -- machine-readable ---------------------------------------------------
    def build(self, session: FuzzSession) -> dict[str, Any]:
        corpus = self.corpus_store.get(session.corpus_id)

        attribution: dict[str, list[str]] = {}
        for tc in corpus.testcases:
            introduced = tc.get("coverage_new_features") or []
            if tc.get("coverage_features"):
                introduced = tc["coverage_features"]
            for feature in introduced:
                attribution.setdefault(feature, []).append(tc["sha256"])

        savings = self._minimization_savings(corpus.testcases)

        available = session.coverage_available
        report = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "kind": "coverage-report",
            "session": {
                "id": session.id,
                "experiment_id": session.experiment_id,
                "target": session.target,
                "status": session.status,
                "executed": session.cursor,
                "max_cases": session.max_cases,
            },
            "coverage": {
                "available": available is True,
                "measured": available is True,
                "note": ("measured by an authorized target adapter"
                         if available is True else
                         "no coverage adapter; black-box campaign — telemetry "
                         "reported as-is, code coverage not fabricated"),
                "unique_features": len(session.coverage_features),
                "features": sorted(session.coverage_features),
                "retained_inputs": len(set(session.coverage_retained_shas)),
                "adapter_errors": session.coverage_adapter_errors,
            },
            "attribution": {feature: shas[:8]
                            for feature, shas in sorted(attribution.items())},
            "corpus_quality": {
                "inputs": len(corpus.testcases),
                "hot_inputs": self._hot_inputs(session),
                "minimization_savings": savings,
            },
            "plateau": {
                "cases_since_new_feature": (
                    session.cases_since_new_feature
                    if available is True else 0),
                "plateaued": bool(available is True
                                  and session.cases_since_new_feature >= 100),
            },
        }
        return redact_value(report)

    def from_session_id(self, session_id: str | None) -> dict[str, Any]:
        if session_id:
            session = self.engine.get(session_id)
        else:
            session = self.engine.latest()
            if session is None:
                raise NotFoundError("no fuzz sessions found")
        return self.build(session)

    @staticmethod
    def _hot_inputs(session: FuzzSession, limit: int = 5) -> list[dict]:
        counts = session.coverage_selection_counts or {}
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return [{"sha256": sha, "selections": count}
                for sha, count in ranked[:limit]]

    @staticmethod
    def _minimization_savings(testcases: list[dict]) -> dict[str, Any]:
        """Greedy set cover over *stored* feature sets (deterministic)."""
        feature_sets: dict[str, set[str]] = {}
        all_features: set[str] = set()
        for tc in testcases:
            features = set(tc.get("coverage_features") or ())
            feature_sets[tc["sha256"]] = features
            all_features |= features
        covered: set[str] = set()
        kept: int = 0
        remaining = list(testcases)
        while remaining:
            candidate = max(
                remaining,
                key=lambda tc: (len(feature_sets[tc["sha256"]] - covered),
                                -tc["size"], tc["sha256"]))
            gained = feature_sets[candidate["sha256"]] - covered
            if not gained:
                break
            covered |= gained
            kept += 1
            remaining.remove(candidate)
        removable = max(len(testcases) - kept, 0)
        return {
            "features_retained": len(all_features),
            "kept": kept,
            "removable": removable,
            "reduction_ratio": round(removable / len(testcases), 4)
            if testcases else 0.0,
        }

    # -- diffing --------------------------------------------------------------
    @staticmethod
    def compare(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
        """Diff two reports: growth, regression, and per-feature deltas."""
        base_features = set(base["coverage"]["features"])
        head_features = set(head["coverage"]["features"])
        return {
            "kind": "coverage-comparison",
            "base_session": base["session"]["id"],
            "head_session": head["session"]["id"],
            "growth": sorted(head_features - base_features),
            "regression": sorted(base_features - head_features),
            "shared": len(base_features & head_features),
            "base_unique": len(base_features),
            "head_unique": len(head_features),
            "delta": len(head_features) - len(base_features),
            "corpus_inputs": {
                "base": base["corpus_quality"]["inputs"],
                "head": head["corpus_quality"]["inputs"],
            },
        }

    # -- reachability -----------------------------------------------------------
    @staticmethod
    def reachability(report: dict[str, Any],
                     static_inventory: set[str] | list[str]) -> dict[str, Any]:
        """Compare declared statically-reachable items with dynamic coverage.

        ``static_inventory`` comes from a researcher-supplied symbol/function
        map for a source-available, authorized target. Items never exercised
        are reported as likely harness gaps; dynamically-covered items absent
        from the inventory are reported separately rather than silently
        dropped.
        """
        inventory = set(static_inventory)
        dynamic = set(report["coverage"]["features"])
        gaps = sorted(inventory - dynamic)
        unmapped = sorted(dynamic - inventory)
        total = len(inventory)
        reached = total - len(gaps)
        return {
            "kind": "reachability-analysis",
            "session": report["session"]["id"],
            "static_inventory_size": total,
            "dynamically_reached": reached,
            "reach_ratio": round(reached / total, 4) if total else None,
            "likely_harness_gaps": gaps,
            "dynamic_unmapped": unmapped,
            "note": ("gaps are candidates for harness/corpus investment; they "
                     "do not assert unreachable-by-design"),
        }

    # -- markdown ---------------------------------------------------------------
    @staticmethod
    def markdown(report: dict[str, Any]) -> str:
        cov = report["coverage"]
        lines = [
            "# Coverage report",
            "",
            f"- Session: `{report['session']['id']}`",
            f"- Target: `{report['session']['target']}` "
            f"({report['session']['executed']}/"
            f"{report['session']['max_cases']} cases)",
            f"- Coverage: {'measured' if cov['measured'] else 'not available'}"
            f" — {cov['unique_features']} unique features",
            "",
            "> " + cov["note"],
            "",
            "## Feature attribution",
            "" if report["attribution"] else "_none_",
        ]
        for feature, shas in report["attribution"].items():
            lines.append(f"- `{feature}` ← {len(shas)} input(s)")
        quality = report["corpus_quality"]
        lines += [
            "",
            "## Corpus quality",
            "",
            f"- Inputs: {quality['inputs']}",
            f"- Minimization: could remove "
            f"{quality['minimization_savings']['removable']} of "
            f"{quality['inputs']} while retaining "
            f"{quality['minimization_savings']['features_retained']} features",
        ]
        if quality["hot_inputs"]:
            lines.append("- Hot inputs:")
            lines += [f"  - `{item['sha256'][:16]}…` ×{item['selections']}"
                      for item in quality["hot_inputs"]]
        plateau = report["plateau"]
        lines += [
            "",
            "## Plateau",
            "",
            (f"- {plateau['cases_since_new_feature']} cases since last new "
             f"feature{' — PLATEAUED' if plateau['plateaued'] else ''}"),
        ]
        return "\n".join(lines) + "\n"
