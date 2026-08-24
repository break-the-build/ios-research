"""IPSW build-to-build symbol patch-diffing.

Compares ``nm``-style symbol tables extracted from two builds to locate patched
code and prioritize reproduction campaigns. Everything here is offline and
deterministic: symbol tables are plain-text artifacts the researcher supplies;
no firmware images are unpacked and no network access occurs.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .clock import now_iso
from .errors import NotFoundError
from .ids import make_id
from .workspace import Workspace


# --- parsing -----------------------------------------------------------------
def parse_nm_symbols_with_skipped(text: str) -> tuple[dict[str, dict], int]:
    """Parse nm-style lines and return ``(symbols, skipped_line_count)``.

    Lines look like ``<addr_hex> [<size_hex>] <type_char> <name>``; the size
    field is optional. Blank lines and ``#`` comments are ignored. Malformed
    lines are skipped and counted rather than fatal.
    """
    symbols: dict[str, dict] = {}
    skipped = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entry = _parse_line(line)
        if entry is None:
            skipped += 1
            continue
        symbols[entry["name"]] = entry
    return symbols, skipped


def _parse_line(line: str) -> dict[str, Any] | None:
    parts = line.split(None, 3)
    try:
        if len(parts) == 4:
            addr, size = int(parts[0], 16), int(parts[1], 16)
            type_char, name = parts[2], parts[3].strip()
        elif len(parts) == 3:
            addr, size = int(parts[0], 16), 0
            type_char, name = parts[1], parts[2].strip()
        else:
            return None
    except ValueError:
        return None
    if not name:
        return None
    return {"addr": addr, "size": size, "type": type_char, "name": name}


def parse_nm_symbols(text: str) -> dict[str, dict]:
    """Parse nm-style symbol text into ``{name: entry}``."""
    return parse_nm_symbols_with_skipped(text)[0]


# --- diffing -----------------------------------------------------------------
def diff_symbols(a: dict, b: dict) -> dict:
    """Classify symbol changes between builds ``a`` and ``b`` by name."""
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    modified = []
    for name in sorted(set(a) & set(b)):
        old, new = a[name], b[name]
        if old["addr"] == new["addr"] and old["size"] == new["size"]:
            continue
        delta = new["size"] - old["size"]
        confidence = round(min(1.0, abs(delta) / max(1, old["size"])), 2)
        modified.append({
            "name": name,
            "old_size": old["size"],
            "new_size": new["size"],
            "size_delta": delta,
            "confidence": confidence,
        })
    return {"added": added, "removed": removed, "modified": modified}


# --- prioritization ----------------------------------------------------------
_SCORE_MODIFIED_REACHABLE = 80
_SCORE_MODIFIED = 40
_SCORE_ADDED_REACHABLE = 70
_SCORE_ADDED = 30
_SCORE_REMOVED_REACHABLE = 20
_SCORE_REMOVED = 10


def prioritize(diff: dict, reachable: set[str]) -> list[dict]:
    """Rank changed symbols for reproduction campaigns.

    Reachable symbols rank far higher than unreachable ones; within the same
    reachability class, modified symbols outweigh added ones, which outweigh
    removed ones, with modification confidence breaking ties upward.
    """
    entries: list[dict] = []
    for name in diff.get("added", []):
        entries.append({
            "name": name,
            "classes": ["added"] + (["reachable"] if name in reachable else []),
            "score": (_SCORE_ADDED_REACHABLE if name in reachable
                      else _SCORE_ADDED),
            "confidence": None,
        })
    for name in diff.get("removed", []):
        entries.append({
            "name": name,
            "classes": ["removed"] + (["reachable"] if name in reachable else []),
            "score": (_SCORE_REMOVED_REACHABLE if name in reachable
                      else _SCORE_REMOVED),
            "confidence": None,
        })
    for mod in diff.get("modified", []):
        name = mod["name"]
        hit = name in reachable
        boost = int(30 * mod.get("confidence", 0.0))
        entries.append({
            "name": name,
            "classes": ["modified"] + (["reachable"] if hit else []),
            "score": ((_SCORE_MODIFIED_REACHABLE if hit else _SCORE_MODIFIED)
                      + boost),
            "confidence": mod.get("confidence", 0.0),
        })
    entries.sort(key=lambda e: (-e["score"], e["name"]))
    return entries


def load_reachable_names(text: str) -> set[str]:
    """Load a reachability list: one symbol name per line, ``#`` comments."""
    names: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        names.add(line)
    return names


# --- store -------------------------------------------------------------------
@dataclass
class NdayDiff:
    id: str
    name: str
    created_at: str
    stats: dict[str, int]
    diff: dict[str, Any]
    plan: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NdayStore:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def _rel(self, nday_id: str) -> str:
        return f"ndays/{nday_id}.json"

    def save(self, rec: NdayDiff) -> None:
        self.ws.write_json(self._rel(rec.id), rec.to_dict())

    def get(self, nday_id: str) -> NdayDiff:
        rel = self._rel(nday_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"nday diff '{nday_id}' not found")
        return NdayDiff(**self.ws.read_json(rel))

    def list(self) -> list[NdayDiff]:
        out = [NdayDiff(**rec) for rec in self.ws.list_json("ndays")]
        return sorted(out, key=lambda r: (r.created_at, r.id))


# --- engine ------------------------------------------------------------------
def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise NotFoundError(f"cannot read file '{path}': {exc}") from exc


class NdayEngine:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.store = NdayStore(workspace)

    def create_diff(self, name: str, path_a: str, path_b: str) -> NdayDiff:
        sym_a = parse_nm_symbols(_read_text(path_a))
        sym_b = parse_nm_symbols(_read_text(path_b))
        result = diff_symbols(sym_a, sym_b)
        stats = {
            "added": len(result["added"]),
            "removed": len(result["removed"]),
            "modified": len(result["modified"]),
            "total": (len(result["added"]) + len(result["removed"])
                      + len(result["modified"])),
        }
        rec = NdayDiff(
            id=make_id("nday", name, "".join(sorted(sym_a)),
                       "".join(sorted(sym_b))),
            name=name, created_at=now_iso(), stats=stats, diff=result)
        self.store.save(rec)
        return rec

    def prioritize(self, diff_id: str, reachable_path: str) -> NdayDiff:
        rec = self.store.get(diff_id)
        reachable = load_reachable_names(_read_text(reachable_path))
        rec.plan = {"reachable_count": len(reachable),
                    "ranked": prioritize(rec.diff, reachable)}
        self.store.save(rec)
        return rec

    def campaign(self, diff_id: str, reachable_path: str) -> NdayDiff:
        rec = self.prioritize(diff_id, reachable_path)
        rec.plan["recommended"] = [e["name"]
                                   for e in rec.plan["ranked"][:3]]
        self.store.save(rec)
        return rec
