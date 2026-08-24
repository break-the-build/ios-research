"""LLM-in-the-loop mutation: proposal ingestion for fuzz campaigns.

An external generator (typically an LLM) writes candidate inputs as JSONL:
one ``{"input_hex": "...", "note": "..."}`` object per line. The fuzz engine
consumes proposals in place of mutation for a bounded number of cases, tags
their lineage, and records per-round crash summaries back on the session so
the next generation round can be conditioned on what crashed.

Proposals are untrusted *data*: they are hex-decoded, size-bounded and passed
through the target's optional ``repair`` hook. They are never executed as
code. Consumption is resumable: a raw line cursor on the session makes
pause/resume reproduce the exact same proposal stream.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterator

from .errors import NotFoundError

DEFAULT_MAX_PROPOSAL_BYTES = 1_048_576
MAX_ROUNDS_KEPT = 20


@dataclass(frozen=True)
class Proposal:
    input_hex: str
    note: str = ""
    next_line: int = 0     # raw file line index AFTER this proposal

    @property
    def data(self) -> bytes:
        return bytes.fromhex(self.input_hex)


def empty_stats() -> dict:
    """Fresh per-session stats dict for LLM-in-the-loop mutation."""
    return {"rounds": [], "proposals_used": 0, "proposals_invalid": 0,
            "fallback_iterations": 0}


def summarize_round(round_no: int, new_crash_signatures: list[str]) -> dict:
    """Crash-aware feedback summary for one proposal round."""
    return {"round": round_no,
            "new_crashes": sorted(new_crash_signatures)[:MAX_ROUNDS_KEPT]}


def validate_proposal_bytes(data: bytes, *,
                            max_bytes: int = DEFAULT_MAX_PROPOSAL_BYTES
                            ) -> bytes | None:
    """None when the decoded proposal must be rejected (empty or oversized)."""
    if not data or len(data) > max_bytes:
        return None
    return data


def repair_with_target(data: bytes, target) -> bytes:
    """Run the target's optional repair hook; failures keep the raw bytes."""
    repair = getattr(target, "repair", None)
    if not callable(repair):
        return data
    try:
        repaired = repair(data)
        return data if not isinstance(repaired, (bytes, bytearray)) \
            else bytes(repaired)
    except Exception:  # a broken hook must not break the campaign
        return data


class FileProposalSource:
    """Read proposals from a JSONL file, tracking the raw line cursor."""

    def __init__(self, path: str):
        self.path = path
        try:
            with open(path, encoding="utf-8") as fh:
                self._lines = fh.read().splitlines()
        except OSError as exc:
            raise NotFoundError(
                f"cannot read proposals file: {exc}") from exc

    def proposals_from(self, start_line: int = 0
                       ) -> Iterator[tuple[int, Proposal | None]]:
        """Yield ``(line_index, Proposal|None)`` for lines >= ``start_line``.

        ``None`` proposals are malformed lines (bad JSON, missing/invalid
        hex); the caller counts them. ``line_index`` is the 0-based raw line
        number, letting the engine persist an exact resume cursor.
        """
        for index in range(max(0, start_line), len(self._lines)):
            raw = self._lines[index].strip()
            if not raw:
                yield index + 1, None
                continue
            try:
                obj = json.loads(raw)
                hex_value = str(obj["input_hex"])
                note = str(obj.get("note", ""))
                bytes.fromhex(hex_value)  # validity check only
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                yield index + 1, None
                continue
            yield index + 1, Proposal(input_hex=hex_value, note=note,
                                      next_line=index + 1)
