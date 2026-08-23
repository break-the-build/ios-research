"""Multi-agent suspicious-point triage over the crash store.

Instead of treating crashes as flat signature events, this module extracts
*suspicious points* (risky code regions derived from normalized stack traces),
clusters crashes that share points, re-verifies each crash against its target,
probes deterministic trigger-condition variants, and persists a structured
triage report for downstream review/reporting.

Every stage is deterministic: point weights, cluster membership and PoC
variants are pure functions of crash content, so the same workspace state
always yields the same report.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from . import targets
from .clock import now_iso
from .errors import NotFoundError, ValidationError
from .hashing import sha256_text
from .ids import make_id
from .workspace import Workspace

# Severity base scores per stable classification. Higher = more suspicious.
_SEVERITY = {
    "USE_AFTER_FREE": 40,
    "DOUBLE_FREE": 38,
    "OUT_OF_BOUNDS_WRITE": 36,
    "OUT_OF_BOUNDS_READ": 34,
    "OUT_OF_BOUNDS": 34,
    "NULL_DEREFERENCE": 30,
    "TYPE_CONFUSION": 32,
    "INTEGER_ERROR": 24,
    "ASSERTION": 26,
    "UNKNOWN": 20,
}

# Frames considered when extracting points.
TOP_FRAMES = 5


def extract_points(crash) -> list[dict[str, Any]]:
    """Derive scored suspicious points from a crash's stack trace.

    Frames use the normalized ``Module`Symbol`` form produced by the sanitizer
    parsers; frames without a module still yield a point.
    """
    diag = crash.diagnostics or {}
    severity = _SEVERITY.get(crash.classification, _SEVERITY["UNKNOWN"])
    points: list[dict[str, Any]] = []
    for idx, frame in enumerate((diag.get("stack_trace") or [])[:TOP_FRAMES]):
        module, _, symbol = frame.partition("`")
        if not symbol:
            symbol, module = module, ""
        score = max(1, severity // (idx + 1))
        points.append({
            "module": module,
            "symbol": symbol,
            "frame_index": idx,
            "score": score,
        })
    return points


def _symbol_set(points: list[dict[str, Any]]) -> frozenset[str]:
    return frozenset(p["symbol"] for p in points if p["symbol"])


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def cluster_points(items: list[dict[str, Any]],
                   *, threshold: float = 0.6) -> list[dict[str, Any]]:
    """Group analyzed crashes whose suspicious-point symbols overlap.

    Single-linkage clustering over Jaccard similarity of the top-frame symbol
    sets. Returns clusters sorted by total weight (desc), each with a
    representative (highest-scoring member).
    """
    n = len(items)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(n):
        for j in range(i + 1, n):
            if jaccard(_symbol_set(items[i]["points"]),
                       _symbol_set(items[j]["points"])) >= threshold:
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[max(ri, rj)] = min(ri, rj)

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)

    clusters = []
    for members_idx in groups.values():
        members = [items[i] for i in members_idx]
        rep = max(members, key=lambda m: (m["total_score"], m["crash_id"]))
        clusters.append({
            "representative": rep["crash_id"],
            "members": [m["crash_id"] for m in members],
            "size": len(members),
            "symbols": sorted(_symbol_set(
                [p for m in members for p in m["points"]])),
            "total_score": sum(m["total_score"] for m in members),
        })
    clusters.sort(key=lambda c: (-c["total_score"], c["representative"]))
    return clusters


@dataclass
class SpointsReport:
    id: str
    scope_experiment_id: str | None
    created_at: str
    stats: dict[str, Any] = field(default_factory=dict)
    points: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    clusters: list[dict[str, Any]] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SpointsEngine:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    # -- storage -----------------------------------------------------------
    def _rel(self, report_id: str) -> str:
        return f"spoints/{report_id}.json"

    def save(self, report: SpointsReport) -> None:
        self.ws.write_json(self._rel(report.id), report.to_dict())

    def get(self, report_id: str) -> SpointsReport:
        if not self.ws.path(self._rel(report_id)).exists():
            raise NotFoundError(f"spoints report '{report_id}' not found")
        return SpointsReport(**self.ws.read_json(self._rel(report_id)))

    def list(self) -> list[SpointsReport]:
        out = [SpointsReport(**rec) for rec in self.ws.list_json("spoints")]
        return sorted(out, key=lambda r: (r.created_at, r.id))

    # -- pipeline ----------------------------------------------------------
    def run(self, *, experiment_id: str | None = None,
            limit: int | None = None) -> SpointsReport:
        from .crashes import CrashStore
        from .triage import Triage

        crashes = CrashStore(self.ws).list(experiment_id=experiment_id)
        if limit is not None:
            if limit < 1:
                raise ValidationError("--limit must be >= 1")
            crashes = crashes[:limit]
        if not crashes:
            raise NotFoundError("no crashes found for the requested scope")

        triage = Triage(self.ws)
        results: list[dict[str, Any]] = []
        analyzed: list[dict[str, Any]] = []

        for crash in crashes:
            repro = triage.reproduce(crash)
            points = extract_points(crash) if repro["reproduced"] else []
            entry = {
                "crash_id": crash.id,
                "verified": bool(repro["reproduced"]),
                "classification": crash.classification,
                "points": points,
                "total_score": sum(p["score"] for p in points),
                "poc": {},
            }
            if entry["verified"] and points:
                entry["poc"] = self._probe_variants(crash)
            results.append(entry)
            if entry["verified"]:
                analyzed.append(entry)

        clusters = cluster_points(analyzed)
        verified = sum(1 for r in results if r["verified"])
        triggered = sum(1 for r in results if r["poc"].get("triggered"))
        now = now_iso()
        report = SpointsReport(
            id=make_id("spoints", experiment_id or "*", len(results),
                       sha256_text("|".join(r["crash_id"] for r in results)),
                       now),
            scope_experiment_id=experiment_id,
            created_at=now,
            stats={
                "crashes": len(results),
                "verified": verified,
                "rejected": len(results) - verified,
                "clusters": len(clusters),
                "poc_triggered": triggered,
                "largest_cluster": max((c["size"] for c in clusters), default=0),
            },
            points={e["crash_id"]: e["points"] for e in analyzed},
            clusters=clusters,
            results=[{k: v for k, v in e.items() if k != "points"}
                     for e in results],
        )
        self.save(report)
        return report

    # -- poc agent ---------------------------------------------------------
    def _probe_variants(self, crash, *, variants: int = 6) -> dict[str, Any]:
        """Deterministically probe trigger-condition variants.

        Mutates the stored input with truncations and boundary flips, then
        counts how many variants still produce the original signature. This is
        a lightweight stand-in for richer condition search (thread scheduling,
        allocator pressure) and never mutates stored artifacts.
        """
        from .artifacts import ArtifactStore
        from .mutation import rng_for
        from .targets.base import Outcome

        try:
            data = ArtifactStore(self.ws).get_bytes(crash.input_sha256)
        except FileNotFoundError:
            return {"triggered": False, "tried": 0, "hit": 0,
                    "reason": "input artifact missing"}

        target = targets.create(crash.target)
        expected = crash.signature
        rng = rng_for(int(sha256_text(crash.id)[:8], 16), 0)
        hit = tried = 0
        candidates: list[bytes] = []
        if len(data) > 2:
            for frac in (2, 3):
                candidates.append(data[:len(data) // frac])
        positions = {rng.randrange(len(data)) for _ in range(4)}
        for pos in sorted(positions):
            flipped = bytearray(data)
            flipped[pos] ^= 0xFF
            candidates.append(bytes(flipped))
        for candidate in candidates[:variants]:
            if not candidate:
                continue
            tried += 1
            res = target.execute(candidate)
            sig = res.diagnostics.signature \
                if (res.outcome in (Outcome.CRASH, Outcome.ABNORMAL)
                    and res.diagnostics) else ""
            if sig == expected:
                hit += 1
        return {"triggered": hit > 0, "tried": tried, "hit": hit}
