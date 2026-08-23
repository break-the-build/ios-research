"""Public-advisory cross-reference and novelty scoring (#59).

Bounty eligibility requires *novel* issues. This module maintains a local,
researcher-imported advisory corpus (Apple security-release notes, CVE feeds)
and matches recorded crashes against it so campaigns stop rediscovering
publicly known or already-fixed bugs and can prioritize genuinely novel
signatures for submission.

Design constraints:

* **Local and deterministic** — the corpus is imported from researcher-supplied
  JSON with pinned provenance; no live scraping at triage time. The same
  crash + corpus always yields the same score.
* **Non-destructive** — advisory data never mutates crash records. Scan results
  are separate artifacts.
* **Conservative** — a match is stored as a candidate with confidence; low
  single-signal candidates never demote a crash's novelty class on their own.

Novelty classes:

* ``novel``          — no candidate matched with at least MEDIUM confidence
* ``known-unfixed``  — matched an advisory that does not declare a fix version
* ``known-fixed``    — matched an advisory declaring ``fixed_in``
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .clock import now_iso
from .crashes import CrashStore, CrashRecord
from .errors import NotFoundError, ValidationError
from .hashing import sha256_bytes
from .ids import make_id
from .workspace import Workspace

ADVISORY_SCHEMA_VERSION = 1

# Confidence ranks for candidate matches.
LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"
_RANK = {LOW: 1, MEDIUM: 2, HIGH: 3}
_PROMOTION_RANK = _RANK[MEDIUM]  # minimum rank that affects novelty class

NOVEL = "novel"
KNOWN_UNFIXED = "known-unfixed"
KNOWN_FIXED = "known-fixed"


@dataclass
class Advisory:
    """One public advisory in the local corpus."""

    id: str                                  # e.g. CVE-2024-1234 / APPLE-XX-YYYY
    components: list[str] = field(default_factory=list)
    classifications: list[str] = field(default_factory=list)
    signature_patterns: list[str] = field(default_factory=list)
    fixed_in: str = ""                       # empty => no declared fix
    summary: str = ""
    source: str = ""
    imported_at: str = ""
    source_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AdvisoryStore:
    """Workspace-backed corpus of imported advisories."""

    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def _rel(self, advisory_id: str) -> str:
        return f"advisories/{advisory_id}.json"

    def put(self, advisory: Advisory) -> Advisory:
        self.ws.write_json(self._rel(advisory.id), advisory.to_dict())
        return advisory

    def get(self, advisory_id: str) -> Advisory:
        if not self.ws.path(self._rel(advisory_id)).exists():
            raise NotFoundError(f"advisory '{advisory_id}' not found")
        return Advisory(**self.ws.read_json(self._rel(advisory_id)))

    def list(self) -> list[Advisory]:
        return [Advisory(**d) for d in self.ws.list_json("advisories")]

    def import_file(self, path: str) -> dict[str, Any]:
        """Import researcher-supplied advisory JSON; corrupt imports fail safely.

        Expected shape::

            {"source": "...", "advisories": [{"id": ..., "components": [...],
             "classifications": [...], "signature_patterns": [...],
             "fixed_in": "...", "summary": "..."}]}
        """
        try:
            raw = Path(path).read_bytes()
            data = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise ValidationError(f"cannot read advisories: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(
                data.get("advisories"), list) or not data["advisories"]:
            raise ValidationError(
                "advisory file must be an object with a non-empty "
                "'advisories' array")
        source = str(data.get("source", Path(path).name))
        digest = sha256_bytes(raw)

        # Strict validation: a malformed entry fails the whole import so the
        # corpus never ends up in a half-imported state.
        imported: list[str] = []
        seen_ids: set[str] = set()
        for index, item in enumerate(data["advisories"]):
            if not isinstance(item, dict):
                raise ValidationError(f"advisory {index} must be an object")
            advisory_id = str(item.get("id", "")).strip()
            if not advisory_id:
                raise ValidationError(f"advisory {index} missing 'id'")
            if advisory_id in seen_ids:
                raise ValidationError(f"duplicate advisory id: {advisory_id}")
            seen_ids.add(advisory_id)
            advisory = Advisory(
                id=advisory_id,
                components=[str(c) for c in item.get("components", [])],
                classifications=[str(c)
                                 for c in item.get("classifications", [])],
                signature_patterns=[str(p)
                                    for p in item.get("signature_patterns",
                                                      [])],
                fixed_in=str(item.get("fixed_in", "") or ""),
                summary=str(item.get("summary", "") or ""),
                source=source, imported_at=now_iso(), source_sha256=digest,
            )
            self.put(advisory)
            imported.append(advisory.id)
        return {"imported": imported,
                "source": source, "source_sha256": digest,
                "schema_version": ADVISORY_SCHEMA_VERSION}


def _norm(value: str) -> str:
    """Normalize an identifier so 'mock:parser', 'MockParser' and
    'mock-parser' compare equal."""
    return "".join(ch for ch in value.lower() if ch.isalnum())


def _contains_any(haystacks: list[str], needles: list[str]) -> bool:
    h = [_norm(x) for x in haystacks if x]
    n = [_norm(x) for x in needles if x]
    return any(needle in item or item in needle
               for item in h for needle in n if needle and item)


def match_crash(crash: CrashRecord, advisory: Advisory) -> tuple[str, list[str]]:
    """Return (confidence, reasons) for one crash/advisory pair."""
    diag = crash.diagnostics or {}
    haystacks = ([crash.target]
                 + list(diag.get("modules") or [])
                 + [crash.fmt])
    reasons: list[str] = []
    score = 0
    if advisory.components and _contains_any(haystacks, advisory.components):
        score += 1
        reasons.append("component match")
    if crash.classification and _norm(crash.classification) in [
            _norm(c) for c in advisory.classifications if c]:
        score += 1
        reasons.append("classification match")
    sig = _norm(crash.signature)
    if advisory.signature_patterns and any(
            _norm(p) and _norm(p) in sig
            for p in advisory.signature_patterns):
        score += 2
        reasons.append("signature pattern match")
    confidence = LOW
    for level, rank in ((HIGH, 4), (MEDIUM, 2)):
        if score >= rank:
            confidence = level
            break
    return confidence, reasons


class NoveltyIndex:
    """Scores crash records against the advisory corpus (read-only)."""

    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.crashes = CrashStore(workspace)
        self.advisories = AdvisoryStore(workspace)

    def score(self, crash: CrashRecord) -> dict[str, Any]:
        candidates = []
        best_rank = 0
        best_fixed = None
        for advisory in self.advisories.list():
            confidence, reasons = match_crash(crash, advisory)
            if not reasons:
                continue
            rank = _RANK[confidence]
            affects = rank >= _PROMOTION_RANK
            candidates.append({
                "advisory_id": advisory.id,
                "confidence": confidence,
                "reasons": reasons,
                "fixed_in": advisory.fixed_in or None,
                "affects_novelty": affects,
            })
            if affects:
                if rank > best_rank:
                    best_rank, best_fixed = rank, bool(advisory.fixed_in)
                elif rank == best_rank and advisory.fixed_in:
                    best_fixed = True
        candidates.sort(key=lambda c: (-_RANK[c["confidence"]], c["advisory_id"]))
        if best_rank == 0:
            novelty = NOVEL
        elif best_fixed:
            novelty = KNOWN_FIXED
        else:
            novelty = KNOWN_UNFIXED
        return {
            "crash_id": crash.id,
            "signature": crash.signature,
            "classification": crash.classification,
            "novelty": novelty,
            "candidates": candidates,
        }

    def scan(self, *, experiment_id: str | None = None) -> dict[str, Any]:
        crashes = self.crashes.list(experiment_id=experiment_id)
        scored = sorted((self.score(crash) for crash in crashes),
                        key=lambda s: ({NOVEL: 0, KNOWN_UNFIXED: 1,
                                        KNOWN_FIXED: 2}[s["novelty"]],
                                       s["crash_id"]))
        counts = {NOVEL: 0, KNOWN_UNFIXED: 0, KNOWN_FIXED: 0}
        for item in scored:
            counts[item["novelty"]] += 1
        result = {
            "schema_version": ADVISORY_SCHEMA_VERSION,
            "advisories_loaded": len(self.advisories.list()),
            "crashes_scored": len(scored),
            "counts": counts,
            "results": scored,
            "priority_order": [item["crash_id"] for item in scored],
            "note": ("novel-first priority ordering; known-bug crashes remain "
                     "fully reproducible — scoring never mutates crash records"),
        }
        # Persist as a standalone artifact so scans are comparable over time.
        scan_id = make_id("novelty", experiment_id or "all",
                          str(len(scored)), str(counts[NOVEL]),
                          str(counts[KNOWN_UNFIXED]), str(counts[KNOWN_FIXED]))
        self.ws.write_json(f"analysis/{scan_id}.json",
                           {"id": scan_id, "kind": "novelty-scan",
                            "created_at": now_iso(), **result})
        result["scan_id"] = scan_id
        return result
