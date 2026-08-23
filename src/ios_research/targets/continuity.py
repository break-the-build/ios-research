"""Mock Continuity beacon record-parser research targets (handoff/findmy/hotspot).

Mock parser targets following the audio-module contract: deterministic,
CI-safe, and exercising the standard ``prepare/execute/collect/cleanup``
lifecycle. Privacy boundary: structural analysis of *synthetic* beacon
records only — no tracking, triangulation, or reporting of third-party
devices, and no broadcasting from real radios.

Normalized mock record (after each target's magic bytes)::

    [declared_length u16 BE][rec_type u8][rec_flags u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# record-type tags that trigger deterministic defect paths
_NULL_TYPE = 0x00        # null activity-record dereference
_CONFUSION_TYPE = 0xC0   # record reinterpreted as incompatible announcement type
_ASSERT_TYPE = 0x7E      # record invariant assertion


class ContinuityTarget(Target):
    kind = "continuity"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = ("mock beacon record parser; synthetic records only, "
                     "no device tracking")
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 0])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.continuity(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        rec_type = body[2]
        rec_flags = body[3]
        payload = body[4:]
        return {"declared": declared, "type": rec_type,
                "flags": rec_flags, "payload": payload}

    def _crash(self, data, classification, symbols, detail):
        module = f"{self.format_name}Parser"
        diag = diagnostics.build(data, classification, module, symbols)
        return ExecResult(outcome=Outcome.CRASH, detail=detail,
                          duration_ms=1, diagnostics=diag)

    def _run(self, data: bytes) -> ExecResult:
        fields = self._extract(data)
        if fields is None:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail=f"not a valid {self.format_name} record",
                              duration_ms=1)

        declared = fields["declared"]
        rec_type = fields["type"]
        rec_flags = fields["flags"]
        payload = fields["payload"]

        if declared >= 0xF000:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="declared record length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["decode_beacon_record", "walk_fields", "read_field_body"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if rec_type == _NULL_TYPE:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["decode_beacon_record", "lookup_activity", "deref_activity"],
                "record type 0 dereferences a null activity record")
        if rec_flags & 0x02:
            return self._crash(
                data, "INTEGER_ERROR",
                ["decode_beacon_record", "scale_field_offsets", "mul_by_flags"],
                "flag-derived field multiplier causes offset arithmetic overflow")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["decode_beacon_record", "reclaim_buffer", "use_buffer"],
                "announcement buffer used after reclaim")
        if rec_type == _CONFUSION_TYPE:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["decode_beacon_record", "reinterpret_record"],
                "beacon record reinterpreted as incompatible announcement type")
        if rec_type == _ASSERT_TYPE:
            return self._crash(
                data, "ASSERTION",
                ["decode_beacon_record", "assert_record_invariant"],
                "beacon record invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} record decoded",
                          duration_ms=1)


class HandoffRecordTarget(ContinuityTarget):
    target_id = "continuity:handoff"
    format_name = "C_HOF"
    description = "Mock Handoff activity-record parser (CI-safe)"
    formats = ("handoff",)
    magic = b"CHOF"


class FindMyAdvTarget(ContinuityTarget):
    target_id = "continuity:findmy-adv"
    format_name = "C_FMY"
    description = "Mock Find My-style advertisement format parser (CI-safe, synthetic)"
    formats = ("findmy-adv",)
    magic = b"CFMY"


class HotspotTlvTarget(ContinuityTarget):
    target_id = "continuity:hotspot-tlv"
    format_name = "C_HTL"
    description = "Mock instant-hotspot negotiation TLV parser (CI-safe)"
    formats = ("hotspot-tlv",)
    magic = b"CHTL"


CONTINUITY_TARGETS = {
    "continuity:handoff": HandoffRecordTarget,
    "continuity:findmy-adv": FindMyAdvTarget,
    "continuity:hotspot-tlv": HotspotTlvTarget,
}
