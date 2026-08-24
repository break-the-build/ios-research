"""ThreadSanitizer report ingestion and scheduling-perturbation hooks (#70).

Parses TSan report text into normalized race records, deduplicates them by an
ordered pc-pair signature, and validates the scheduler-perturbation modes a
fuzz campaign may apply between cases. Parsing is deliberately defensive:
blocks we only partially recognize still yield usable records with stable
signatures.

Nothing here executes a toolchain or touches a live process; it reads report
text and stores JSON (offline, CI-safe).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from typing import Sequence

from .clock import now_iso
from .errors import NotFoundError, StateError, ValidationError
from .ids import make_id
from .workspace import Workspace, validate_component

# A race block starts here; blocks run until the next start line.
_BLOCK_START_RE = re.compile(r"^WARNING:\s*ThreadSanitizer:", re.IGNORECASE)
_KIND_RE = re.compile(
    r"WARNING:\s*ThreadSanitizer:\s*"
    r"(?P<kind>[A-Za-z][A-Za-z \-]*?)\s*(?:\(|$)")
_FRAME_RE = re.compile(
    r"^\s*#\d+\s+0x(?P<pc>[0-9a-fA-F]+)\s+in\s+(?P<rest>.+?)\s*$")
# TSan separates the two involved stacks with headers like
# "Stack of thread T2:" / "Previous write of size 4 ... by thread T2:".
_STACK_SPLIT_RE = re.compile(r"^\s*(Previous|Stack of thread)")
_SUMMARY_LINE_RE = re.compile(r"^\s*summary:\s*(?P<rest>.+?)\s*$", re.IGNORECASE)

PERTURB_MODES = ("yield", "priority", "affinity", "random-delay")


def parse_tsan(text: str) -> list[dict]:
    """Parse ThreadSanitizer report text into normalized race dicts.

    Each ``WARNING: ThreadSanitizer: <kind> (...)`` block becomes one dict
    with ``kind``, normalized ``pc1``/``pc2`` (first frame of each stack),
    symbol lists ``stack1``/``stack2`` and the block's ``summary`` line.
    """
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in (text or "").splitlines():
        if _BLOCK_START_RE.match(line):
            if current is not None:
                blocks.append(current)
            current = [line]
        elif current is not None:
            current.append(line)
    if current is not None:
        blocks.append(current)

    import ios_research.targets.asan as asan

    races: list[dict] = []
    for block in blocks:
        kind_m = _KIND_RE.search(block[0])
        kind = kind_m.group("kind").strip().lower() if kind_m else "unknown"
        stack1: list[str] = []
        stack2: list[str] = []
        pc1 = ""
        pc2 = ""
        summary = ""
        markers_seen = 0
        for line in block[1:]:
            summary_m = _SUMMARY_LINE_RE.match(line)
            if summary_m and not summary:
                summary = summary_m.group("rest")
                continue
            if _STACK_SPLIT_RE.match(line):
                markers_seen += 1
                continue
            frame = _FRAME_RE.match(line)
            if not frame:
                continue
            pc = asan._norm_addr(frame.group("pc"))
            symbol = asan._extract_symbol(frame.group("rest"))
            # Frames before the second stack marker belong to stack1; frames
            # after it to stack2. With no marker at all every frame stays in
            # stack1 (defensive single-stack blocks remain usable).
            if markers_seen < 2:
                if not stack1:
                    pc1 = pc
                stack1.append(symbol)
            else:
                if not stack2:
                    pc2 = pc
                stack2.append(symbol)
        races.append({
            "kind": kind,
            "pc1": pc1,
            "pc2": pc2,
            "stack1": stack1,
            "stack2": stack2,
            "summary": summary,
        })
    return races


def race_signature(race: dict) -> str:
    """Ordered pc-pair digest: stable for identical reports, distinct otherwise."""
    material = f"{race.get('pc1', '')}|{race.get('pc2', '')}"
    return "tsan_" + hashlib.sha256(material.encode()).hexdigest()[:16]


def _race_from_dict(data: dict) -> RaceRecord:
    """Build a record from persisted JSON with a stable error on drift."""
    try:
        return RaceRecord(**data)
    except TypeError:
        raise StateError(
            "race record is corrupt or from an incompatible version",
            details={"keys": sorted(data)}) from None


@dataclass
class RaceRecord:
    id: str
    target: str
    kind: str
    signature: str
    pc1: str
    pc2: str
    stack1: list = field(default_factory=list)
    stack2: list = field(default_factory=list)
    count: int = 1
    first_seen: str = ""
    last_seen: str = ""
    status: str = "new"
    sample_input_sha256: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class RaceStore:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def _rel(self, race_id: str) -> str:
        return f"races/{race_id}.json"

    def get(self, race_id: str) -> RaceRecord:
        validate_component(race_id, what="race id")
        rel = self._rel(race_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"race '{race_id}' not found")
        return _race_from_dict(self.ws.read_json(rel))

    def save(self, race: RaceRecord) -> None:
        self.ws.write_json(self._rel(race.id), race.to_dict())

    def list(self, *, kind: str | None = None) -> list[RaceRecord]:
        out = [_race_from_dict(rec) for rec in self.ws.list_json("races")]
        if kind:
            out = [r for r in out if r.kind == kind]
        return sorted(out, key=lambda r: (-r.count, r.id))

    def record(self, target: str, race: dict,
               *, sample_input_sha256: str = "") -> RaceRecord:
        """Record (or dedupe) one parsed race within this store.

        Dedup key is the race signature: repeated sightings increment ``count``
        on the existing record rather than creating a new one.
        """
        signature = race_signature(race)
        race_id = make_id("race", signature)
        rel = self._rel(race_id)
        if self.ws.path(rel).exists():
            existing = self.get(race_id)
            existing.count += 1
            existing.last_seen = now_iso()
            self.save(existing)
            return existing
        now = now_iso()
        rec = RaceRecord(
            id=race_id, target=target, kind=race.get("kind", "unknown"),
            signature=signature, pc1=race.get("pc1", ""),
            pc2=race.get("pc2", ""), stack1=list(race.get("stack1", [])),
            stack2=list(race.get("stack2", [])),
            first_seen=now, last_seen=now,
            sample_input_sha256=sample_input_sha256 or "")
        self.save(rec)
        return rec


def validate_modes(modes: Sequence[str]) -> tuple[str, ...]:
    """Dedupe (order-preserving) and validate perturbation mode names."""
    out: list[str] = []
    for mode in modes or ():
        if mode not in PERTURB_MODES:
            raise ValidationError(
                f"unknown scheduling-perturbation mode '{mode}'; valid modes: "
                f"{', '.join(PERTURB_MODES)}")
        if mode not in out:
            out.append(mode)
    return tuple(out)


def import_report(store: RaceStore, text: str, *, target: str = "unknown",
                  sample_input_sha256: str = "") -> dict:
    """Parse one report and record every race; returns stable counters."""
    races = parse_tsan(text)
    recorded = 0
    for race in races:
        rec = store.record(target, race,
                           sample_input_sha256=sample_input_sha256)
        if rec.count == 1:
            recorded += 1
    return {"races": len(races), "recorded": recorded,
            "duplicates": len(races) - recorded}
