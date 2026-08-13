"""Corpus and testcase management.

A *corpus* is a named collection of testcases. Each testcase is stored
content-addressed by SHA-256 and carries lineage metadata (origin, parent,
mutation strategy, seed) so any input can be traced back to how it was created.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .clock import now_iso
from .errors import NotFoundError, ValidationError
from .hashing import sha256_bytes
from .ids import make_id
from .workspace import Workspace


@dataclass
class Testcase:
    id: str
    sha256: str
    size: int
    origin: str                    # seed | import | mutation
    parent: str | None = None      # parent testcase sha256 (lineage)
    mutation: str | None = None    # mutation strategy that produced it
    seed: int | None = None
    iteration: int | None = None
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Corpus:
    id: str
    name: str
    created_at: str
    target: str | None = None
    testcases: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def shas(self) -> set[str]:
        return {tc["sha256"] for tc in self.testcases}


class CorpusStore:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def _manifest_rel(self, corpus_id: str) -> str:
        return f"corpus/{corpus_id}/corpus.json"

    def _input_rel(self, corpus_id: str, sha256: str) -> str:
        return f"corpus/{corpus_id}/inputs/{sha256}.bin"

    # lifecycle -----------------------------------------------------------
    def create(self, name: str, target: str | None = None) -> Corpus:
        corpus_id = make_id("corpus", name)
        if self.ws.path(self._manifest_rel(corpus_id)).exists():
            raise ValidationError(f"corpus '{name}' ({corpus_id}) already exists")
        corpus = Corpus(id=corpus_id, name=name, created_at=now_iso(),
                        target=target)
        self.save(corpus)
        return corpus

    def save(self, corpus: Corpus) -> None:
        self.ws.write_json(self._manifest_rel(corpus.id), corpus.to_dict())

    def get(self, corpus_id: str) -> Corpus:
        rel = self._manifest_rel(corpus_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"corpus '{corpus_id}' not found")
        return Corpus(**self.ws.read_json(rel))

    def list(self) -> list[Corpus]:
        base = self.ws.dir("corpus")
        out = []
        for manifest in sorted(base.glob("*/corpus.json")):
            out.append(Corpus(**self.ws.read_json(
                str(manifest.relative_to(self.ws.root)))))
        return out

    # testcases -----------------------------------------------------------
    def add_bytes(self, corpus: Corpus, data: bytes, *, origin: str,
                  parent: str | None = None, mutation: str | None = None,
                  seed: int | None = None, iteration: int | None = None,
                  dedupe: bool = True) -> Testcase | None:
        sha = sha256_bytes(data)
        if dedupe and sha in corpus.shas:
            return None
        self.ws.write_bytes(self._input_rel(corpus.id, sha), data)
        tc = Testcase(
            id=make_id("testcase", corpus.id, sha),
            sha256=sha, size=len(data), origin=origin, parent=parent,
            mutation=mutation, seed=seed, iteration=iteration,
            created_at=now_iso(),
        )
        corpus.testcases.append(tc.to_dict())
        self.save(corpus)
        return tc

    def read_bytes(self, corpus: Corpus, sha256: str) -> bytes:
        return self.ws.read_bytes(self._input_rel(corpus.id, sha256))

    def import_path(self, corpus: Corpus, path: Path) -> int:
        """Import a file or all files in a directory. Returns count added."""
        path = Path(path)
        if not path.exists():
            raise NotFoundError(f"import path does not exist: {path}")
        files = [path] if path.is_file() else sorted(
            p for p in path.rglob("*") if p.is_file())
        added = 0
        for f in files:
            if self.add_bytes(corpus, f.read_bytes(), origin="import") is not None:
                added += 1
        return added

    # maintenance ---------------------------------------------------------
    def dedupe(self, corpus: Corpus) -> int:
        """Remove duplicate manifest entries (same sha256). Returns removed."""
        seen: set[str] = set()
        kept: list[dict] = []
        for tc in corpus.testcases:
            if tc["sha256"] in seen:
                continue
            seen.add(tc["sha256"])
            kept.append(tc)
        removed = len(corpus.testcases) - len(kept)
        corpus.testcases = kept
        self.save(corpus)
        return removed

    def minimize(self, corpus: Corpus, target) -> dict:
        """Distill the corpus to one representative per distinct behavior.

        Runs each testcase through ``target`` and keeps the first testcase for
        each unique ``(outcome, signature)`` behavior key.
        """
        kept: list[dict] = []
        behaviors: set[str] = set()
        for tc in corpus.testcases:
            data = self.read_bytes(corpus, tc["sha256"])
            res = target.execute(data)
            sig = res.diagnostics.signature if res.diagnostics else ""
            key = f"{res.outcome}:{sig}"
            if key in behaviors:
                continue
            behaviors.add(key)
            kept.append(tc)
        removed = len(corpus.testcases) - len(kept)
        corpus.testcases = kept
        self.save(corpus)
        return {"kept": len(kept), "removed": removed,
                "behaviors": len(behaviors)}
