"""Differential testing and regression analysis.

Runs a corpus through two targets (e.g. two versions/configurations) and records
per-testcase results and diagnostic differences, classifying behavioral
transitions and flagging regressions. Differential experiments are reproducible:
they pin corpus, targets, seed and configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from . import targets
from .clock import now_iso
from .corpus import CorpusStore
from .errors import NotFoundError
from .ids import make_id
from .targets.base import Outcome
from .workspace import Workspace

# Behavior categories and their severity rank (higher = worse).
_CATEGORY = {
    Outcome.ACCEPTED: "NORMAL",
    Outcome.REJECTED: "REJECT",
    Outcome.TIMEOUT: "TIMEOUT",
    Outcome.CRASH: "CRASH",
    Outcome.ABNORMAL: "CRASH",
}
_RANK = {"NORMAL": 0, "REJECT": 0, "TIMEOUT": 2, "CRASH": 3}

# Crafted inputs covering diverse behaviors across parser versions.
_DEFAULT_INPUTS = [
    b"MOCK\x01\x01\x00\x02ok",          # accept / accept
    b"MOCK\x01\xff\x00\x00",            # v1 null-deref crash, v2 fixed
    b"MOCK\x02\x01\x00\x02payload",     # v1 accept, v2 OOB-write regression
    b"MOCK\x01\x01\xff\xffshort",       # OOB read on both
    b"MOCK\x01\x7e\x00\x02ok",          # v1 assertion, v2 fixed
    b"MOCK\x01\x01\x00\x02\xde\xad",    # use-after-free on both
]


@dataclass
class DiffExperiment:
    id: str
    name: str
    target_a: str
    target_b: str
    corpus_id: str
    seed: int
    config_hash: str
    created_at: str
    status: str = "created"
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _category(outcome: str) -> str:
    return _CATEGORY.get(outcome, "CRASH")


class DifferentialEngine:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.corpus_store = CorpusStore(workspace)

    def _rel(self, diff_id: str) -> str:
        return f"diffs/{diff_id}/diff.json"

    def _results_rel(self, diff_id: str) -> str:
        return f"diffs/{diff_id}/results.json"

    # lifecycle -----------------------------------------------------------
    def create(self, *, name: str, target_a: str, target_b: str,
               config_hash: str, seed: int = 0,
               corpus_id: str | None = None) -> DiffExperiment:
        for tid in (target_a, target_b):
            if not targets.is_registered(tid):
                raise NotFoundError(f"unknown target '{tid}'")
        if corpus_id is None:
            corpus = self._default_corpus()
            corpus_id = corpus.id
        else:
            self.corpus_store.get(corpus_id)  # validate

        diff_id = make_id("diff", name, target_a, target_b, corpus_id, str(seed))
        diff = DiffExperiment(
            id=diff_id, name=name, target_a=target_a, target_b=target_b,
            corpus_id=corpus_id, seed=seed, config_hash=config_hash,
            created_at=now_iso())
        self.ws.write_json(self._rel(diff_id), diff.to_dict())
        return diff

    def _default_corpus(self):
        name = "diff-default"
        for c in self.corpus_store.list():
            if c.name == name:
                return c
        corpus = self.corpus_store.create(name)
        for data in _DEFAULT_INPUTS:
            self.corpus_store.add_bytes(corpus, data, origin="seed")
        return corpus

    def get(self, diff_id: str) -> DiffExperiment:
        rel = self._rel(diff_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"diff experiment '{diff_id}' not found")
        return DiffExperiment(**self.ws.read_json(rel))

    def list(self) -> list[DiffExperiment]:
        base = self.ws.dir("diffs")
        out = []
        for manifest in sorted(base.glob("*/diff.json")):
            out.append(DiffExperiment(**self.ws.read_json(
                str(manifest.relative_to(self.ws.root)))))
        return out

    # execution -----------------------------------------------------------
    def run(self, diff: DiffExperiment) -> dict:
        corpus = self.corpus_store.get(diff.corpus_id)
        target_a = targets.create(diff.target_a)
        target_b = targets.create(diff.target_b)

        results = []
        transitions: dict[str, int] = {}
        regressions = 0
        differing = 0

        for tc in corpus.testcases:
            data = self.corpus_store.read_bytes(corpus, tc["sha256"])
            ra = target_a.execute(data)
            rb = target_b.execute(data)
            cat_a, cat_b = _category(ra.outcome), _category(rb.outcome)
            sig_a = ra.diagnostics.signature if ra.diagnostics else ""
            sig_b = rb.diagnostics.signature if rb.diagnostics else ""
            differs = cat_a != cat_b or sig_a != sig_b
            is_regression = _RANK[cat_b] > _RANK[cat_a]
            transition = f"{cat_a}->{cat_b}"
            if differs:
                differing += 1
                transitions[transition] = transitions.get(transition, 0) + 1
            if is_regression:
                regressions += 1
            results.append({
                "input_sha256": tc["sha256"],
                "a": {"outcome": ra.outcome, "category": cat_a,
                      "signature": sig_a,
                      "classification": ra.diagnostics.classification_hint
                      if ra.diagnostics else None},
                "b": {"outcome": rb.outcome, "category": cat_b,
                      "signature": sig_b,
                      "classification": rb.diagnostics.classification_hint
                      if rb.diagnostics else None},
                "transition": transition,
                "differs": differs,
                "is_regression": is_regression,
            })

        summary = {
            "testcases": len(results),
            "differing": differing,
            "regressions": regressions,
            "transitions": transitions,
        }
        self.ws.write_json(self._results_rel(diff.id),
                           {"diff_id": diff.id, "results": results})
        diff.status = "run"
        diff.summary = summary
        self.ws.write_json(self._rel(diff.id), diff.to_dict())
        return summary

    def results(self, diff: DiffExperiment) -> list[dict]:
        rel = self._results_rel(diff.id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"diff '{diff.id}' has not been run")
        return self.ws.read_json(rel)["results"]

    def compare(self, diff: DiffExperiment) -> dict:
        results = self.results(diff)
        return {
            "diff_id": diff.id,
            "summary": diff.summary,
            "differences": [r for r in results if r["differs"]],
            "regressions": [r for r in results if r["is_regression"]],
        }

    def report(self, diff: DiffExperiment) -> dict:
        comparison = self.compare(diff)
        return {
            "diff_id": diff.id,
            "name": diff.name,
            "target_a": diff.target_a,
            "target_b": diff.target_b,
            "corpus_id": diff.corpus_id,
            "seed": diff.seed,
            "config_hash": diff.config_hash,
            "summary": diff.summary,
            "transitions": diff.summary.get("transitions", {}),
            "regression_count": diff.summary.get("regressions", 0),
            "regressions": comparison["regressions"],
        }
