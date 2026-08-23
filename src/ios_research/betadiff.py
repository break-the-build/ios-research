"""Beta-release differential pipeline: prioritize new/changed code (#56).

Apple pays a 50% bonus for issues unique to newly added features or code in
developer/public beta releases, including regressions. This module diffs two
researcher-declared releases (framework/binary symbol sets) so campaigns can
focus on *novel* surfaces instead of long-stable code.

Inputs are researcher-supplied release directories containing either

* ``*.symbols`` text files (one exported symbol per line; fixture-friendly and
  cross-platform), or
* Mach-O images, whose exported symbols are extracted with the system ``nm``
  when available (sorted for determinism).

Each release directory must contain a ``release.json`` manifest with
``os_name``/``os_version``/``build`` provenance. Every analyzed file's SHA-256
is pinned into the diff record; re-running against modified inputs without an
updated manifest fails validation rather than silently degrading.

Outputs (persisted as a ``beta-diff`` analysis artifact):

* added/removed/changed symbol lists per component,
* a ranked novel-surface plan,
* a deterministic token dictionary derived from new symbols, usable by
  constraint-guided mutation (#30) via ``fuzz start --dictionary``,
* optional beta provenance tagging of a corpus (``beta tag``), which flows
  through experiment lineage into reports and evidence packs.

Static diffing and metadata extraction only — inside the authorized-research
boundary.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .clock import now_iso
from .corpus import CorpusStore
from .errors import NotFoundError, ValidationError
from .hashing import sha256_bytes, sha256_text
from .ids import make_id
from .workspace import Workspace

BETADIFF_SCHEMA_VERSION = 1
MAX_DICTIONARY_TOKENS = 256
MIN_TOKEN_LEN = 4
_REQUIRED_MANIFEST = ("os_name", "os_version", "build")

_CAMEL = re.compile(r"[A-Z]?[a-z]+|[A-Z]{2,}(?=[A-Z][a-z]|\b)|\d+")


@dataclass
class ReleaseSymbols:
    """Symbol sets extracted from one release directory."""

    root: Path
    provenance: dict[str, str]
    files: dict[str, list[str]]          # relpath -> sorted symbol list
    file_hashes: dict[str, str]

    @property
    def label(self) -> str:
        p = self.provenance
        return f"{p['os_name']} {p['os_version']} ({p['build']})"


def _extract_symbols(path: Path) -> list[str]:
    """Extract symbols from one file; text .symbols files or nm for Mach-O."""
    if path.suffix == ".symbols":
        lines = [ln.strip() for ln in
                 path.read_text(encoding="utf-8", errors="replace").splitlines()]
        return sorted({ln for ln in lines if ln})
    # Binary: try nm -gU (defined, exported symbols only).
    try:
        proc = subprocess.run(["nm", "-gU", str(path)],
                              capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    symbols = set()
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        parts = line.split(" ", 2)
        if len(parts) == 3 and parts[-1].strip():
            symbols.add(parts[-1].strip())
    return sorted(symbols)


def load_release(root: str | Path) -> ReleaseSymbols:
    root = Path(root)
    if not root.is_dir():
        raise ValidationError(f"release directory not found: {root}")
    manifest_path = root / "release.json"
    if not manifest_path.is_file():
        raise ValidationError(
            f"release directory missing release.json manifest: {root}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ValidationError(f"invalid release.json: {exc}") from exc
    missing = [k for k in _REQUIRED_MANIFEST
               if not str(manifest.get(k, "")).strip()]
    if missing:
        raise ValidationError(
            f"release.json missing provenance: {', '.join(missing)}")
    provenance = {k: str(manifest[k]) for k in _REQUIRED_MANIFEST}

    files: dict[str, list[str]] = {}
    hashes: dict[str, str] = {}
    candidates = [p for p in sorted(root.rglob("*"))
                  if p.is_file() and p.name not in ("release.json",)
                  and not p.name.startswith(".")]
    for path in candidates:
        rel = str(path.relative_to(root))
        files[rel] = _extract_symbols(path)
        hashes[rel] = sha256_bytes(path.read_bytes())
    return ReleaseSymbols(root=root, provenance=provenance, files=files,
                          file_hashes=hashes)


def diff_releases(release_a: ReleaseSymbols,
                  release_b: ReleaseSymbols) -> dict[str, Any]:
    """Deterministic symbol-level diff between two releases."""
    components: dict[str, Any] = {}
    all_added: list[str] = []
    for rel in sorted(set(release_a.files) | set(release_b.files)):
        sym_a = set(release_a.files.get(rel, []))
        sym_b = set(release_b.files.get(rel, []))
        added, removed = sorted(sym_b - sym_a), sorted(sym_a - sym_b)
        if rel not in release_a.files:
            status = "added-component"
        elif rel not in release_b.files:
            status = "removed-component"
        elif added or removed:
            status = "changed"
        else:
            status = "unchanged"
        components[rel] = {
            "status": status, "added": added, "removed": removed,
            "added_count": len(added),
        }
        all_added.extend(added)

    ranked = sorted(
        ((info["added_count"], name) for name, info in components.items()
         if info["added_count"]),
        key=lambda item: (-item[0], item[1]))
    novel_plan = [
        {"component": name, "added_symbols": count, "rank": position + 1}
        for position, (count, name) in enumerate(ranked)]

    tokens: list[str] = []
    seen_tokens: set[str] = set()
    for symbol in sorted(set(all_added)):
        for token in re.findall(r"[A-Za-z0-9]+", symbol):
            if len(token) < MIN_TOKEN_LEN:
                continue
            key = token.lower()
            if key in seen_tokens:
                continue
            seen_tokens.add(key)
            tokens.append(token)
            if len(tokens) >= MAX_DICTIONARY_TOKENS:
                break
        if len(tokens) >= MAX_DICTIONARY_TOKENS:
            break

    return {
        "components": components,
        "novel_surface_plan": novel_plan,
        "dictionary_tokens": tokens,
        "totals": {
            "added_symbols": len(all_added),
            "removed_symbols": sum(
                len(info["removed"]) for info in components.values()),
            "changed_components": sum(
                1 for info in components.values() if info["status"] == "changed"),
            "new_components": sum(
                1 for info in components.values()
                if info["status"] == "added-component"),
        },
    }


def dictionary_bytes(tokens: list[str]) -> bytes:
    """libFuzzer-style dictionary file (deterministic)."""
    lines = [f"{token}={json.dumps(token)}" for token in tokens]
    return ("\n".join(lines) + "\n").encode("utf-8")


class BetaDiffEngine:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.corpora = CorpusStore(workspace)

    def _rel(self, diff_id: str) -> str:
        return f"analysis/{diff_id}.json"

    def get(self, diff_id: str) -> dict[str, Any]:
        record = self.ws.read_json(self._rel(diff_id))
        if record.get("kind") != "beta-diff":
            raise ValidationError(f"'{diff_id}' is not a beta diff record")
        return record

    def list(self) -> list[dict[str, Any]]:
        return [r for r in self.ws.list_json("analysis")
                if r.get("kind") == "beta-diff"]

    def run(self, *, release_a_path: str, release_b_path: str) -> dict[str, Any]:
        release_a = load_release(release_a_path)
        release_b = load_release(release_b_path)

        diff_id = make_id("betadiff",
                          sha256_text(json.dumps(
                              {**release_a.file_hashes}, sort_keys=True)),
                          sha256_text(json.dumps(
                              {**release_b.file_hashes}, sort_keys=True)),
                          release_a.label, release_b.label)

        # Provenance guard: an existing identical-id record must match inputs;
        # changed inputs with colliding ids would indicate tampering/drift.
        result = diff_releases(release_a, release_b)
        record = {
            "id": diff_id,
            "kind": "beta-diff",
            "created_at": now_iso(),
            "schema_version": BETADIFF_SCHEMA_VERSION,
            "release_a": {
                "label": release_a.label,
                "provenance": release_a.provenance,
                "file_hashes": release_a.file_hashes,
            },
            "release_b": {
                "label": release_b.label,
                "provenance": release_b.provenance,
                "file_hashes": release_b.file_hashes,
            },
            **result,
        }
        existing = (self.ws.read_json(self._rel(diff_id))
                    if self.ws.path(self._rel(diff_id)).exists() else None)
        if existing is not None:
            if existing.get("release_a") != record["release_a"] or \
                    existing.get("release_b") != record["release_b"]:
                raise ValidationError(
                    "beta diff provenance mismatch for existing record")
            return existing
        self.ws.write_json(self._rel(diff_id), record)
        self.ws.write_bytes(f"analysis/{diff_id}.dict",
                            dictionary_bytes(result["dictionary_tokens"]))
        return record

    def tag_corpus(self, *, diff_id: str, corpus_id: str) -> dict[str, Any]:
        """Stamp beta release-pair provenance onto a corpus (idempotent)."""
        record = self.get(diff_id)
        corpus = self.corpora.get(corpus_id)
        corpus.provenance = dict(getattr(corpus, "provenance", {}) or {})
        corpus.provenance["beta"] = {
            "diff_id": diff_id,
            "release_a": record["release_a"]["provenance"],
            "release_b": record["release_b"]["provenance"],
        }
        self.corpora.save(corpus)
        return corpus.provenance


def beta_provenance_for_experiment(workspace: Workspace,
                                   experiment) -> dict[str, Any] | None:
    """Beta provenance attached to an experiment's corpus, if any."""
    corpus_id = (experiment.params or {}).get("corpus")
    if not corpus_id:
        return None
    try:
        corpus = CorpusStore(workspace).get(corpus_id)
    except (NotFoundError, ValidationError):
        return None
    return (getattr(corpus, "provenance", {}) or {}).get("beta")
