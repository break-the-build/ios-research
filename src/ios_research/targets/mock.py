"""A deterministic, intentionally-buggy mock parser target.

This target simulates a small binary record parser with a set of *deterministic*
defects. It exists so the whole research pipeline (fuzz -> crash -> triage ->
analysis -> report) can be exercised in CI without any real device or unsafe
code. No native memory is actually corrupted; outcomes are computed from the
input bytes.

Mock record format::

    offset 0..4   magic  = b"MOCK"
    offset 4      version (u8)
    offset 5      rtype   (u8)
    offset 6..8   declared_length (u16 big-endian)
    offset 8..    payload

Deterministic defect rules are documented inline in :meth:`_run`.
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics

MAGIC = b"MOCK"
_MODULE = "MockParser"


class MockParserTarget(Target):
    target_id = "mock:parser"
    kind = "parser"
    description = "Deterministic mock binary record parser (CI-safe)"
    formats = ("mock-record",)
    mock = True

    def seeds(self) -> list[bytes]:
        return [MAGIC + bytes([1, 1]) + (2).to_bytes(2, "big") + b"ok"]

    def structure_mutate(self, data: bytes, rng):
        from . import _structure  # lazy import to avoid cycle
        return _structure.mock_record(data, rng)

    def _crash(self, data: bytes, classification: str,
               symbols: list[str], detail: str) -> ExecResult:
        diag = diagnostics.build(data, classification, _MODULE, symbols)
        return ExecResult(outcome=Outcome.CRASH, detail=detail,
                          duration_ms=1, diagnostics=diag)

    def _run(self, data: bytes) -> ExecResult:
        # Non-conforming inputs are cleanly rejected (not a defect).
        if len(data) < 8 or data[:4] != MAGIC:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail="bad magic or short header", duration_ms=1)

        version = data[4]
        rtype = data[5]
        declared_length = int.from_bytes(data[6:8], "big")
        payload = data[8:]

        # Rule 1: declared length longer than the actual payload => OOB read.
        if declared_length > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["parse_record", "copy_payload", "read_bytes"],
                f"declared_length={declared_length} exceeds payload={len(payload)}")

        # Rule 2: record type 0xFF dispatches through a null handler pointer.
        if rtype == 0xFF:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["parse_record", "dispatch_handler"],
                "record type 0xFF has no registered handler (null dispatch)")

        # Rule 3: 'free' marker (0xDE) followed by a 'use' marker (0xAD).
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["parse_record", "release_node", "use_node"],
                "node used after release marker")

        # Rule 4: version 0 with non-empty payload => integer stride underflow.
        if version == 0 and payload:
            return self._crash(
                data, "INTEGER_ERROR",
                ["parse_record", "compute_stride"],
                "stride computed from version 0 underflows")

        # Rule 5: payload masquerading as a different tagged type (0x7F 'T').
        if payload[:2] == b"\x7fT":
            return self._crash(
                data, "TYPE_CONFUSION",
                ["parse_record", "reinterpret_node"],
                "payload reinterpreted as incompatible node type")

        # Rule 6: an oversized declared record simulates a slow path => timeout.
        if declared_length >= 0xF000:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="oversized record exceeded time budget",
                              duration_ms=1000)

        # Rule 7: reserved record type triggers an assertion (abnormal exit).
        if rtype == 0x7E:
            return self._crash(
                data, "ASSERTION",
                ["parse_record", "assert_invariant"],
                "internal invariant assertion failed")

        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail="record parsed", duration_ms=1)


class MockParserV2Target(MockParserTarget):
    """A second 'version' of the mock parser for differential testing.

    Relative to v1 it *fixes* two defects (null-dispatch on record type 0xFF and
    the reserved-type assertion) and *introduces* one regression (a new
    out-of-bounds write when ``version == 2``). This produces both fixes and
    regressions when diffed against v1 over the same corpus.
    """

    target_id = "mock:parser-v2"
    description = "Deterministic mock parser, version 2 (CI-safe)"

    def _run(self, data: bytes) -> ExecResult:
        if len(data) < 8 or data[:4] != MAGIC:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail="bad magic or short header", duration_ms=1)
        version = data[4]
        rtype = data[5]
        payload = data[8:]

        # Regression introduced in v2: version 2 with payload -> OOB write.
        if version == 2 and payload:
            return self._crash(
                data, "OUT_OF_BOUNDS_WRITE",
                ["parse_record", "write_field", "store_bytes"],
                "v2 regression: unchecked write for version 2 records")

        # Fixed in v2: record type 0xFF and reserved type 0x7E are now handled.
        if rtype in (0xFF, 0x7E):
            return ExecResult(outcome=Outcome.ACCEPTED,
                              detail="record parsed (v2 handles reserved types)",
                              duration_ms=1)

        return super()._run(data)
