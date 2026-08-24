"""Mock PQ3-style ratchet session-transcript research targets (handshake/rekey).

Mock parser targets following the audio-module contract: deterministic,
CI-safe, and exercising the standard ``prepare/execute/collect/cleanup``
lifecycle. All transcripts are **synthetic, researcher-authored** byte
sequences; parsing is verify-only structure validation. There is **no
decryption, no key extraction, and no third-party traffic analysis** of any
kind — real iMessage/PQ3 sessions are never touched.

Normalized mock transcript message (after each target's magic bytes)::

    [declared_length u16 BE][epoch u16 BE][msg_type u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# message-type tags that trigger deterministic defect paths
_NULL_TYPE = 0x00        # null epoch-state dereference
_CONFUSION_TYPE = 0xC0   # message reinterpreted as incompatible handshake state
_ASSERT_TYPE = 0x7E      # epoch ordering invariant assertion


class Pq3Target(Target):
    kind = "pq3"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = "mock ratchet transcript parser; synthetic vectors only"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([0, 1, 1])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.pq3(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 5 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        epoch = int.from_bytes(body[2:4], "big")
        msg_type = body[4]
        payload = body[5:]
        return {"declared": declared, "epoch": epoch, "msg_type": msg_type,
                "payload": payload}

    def _crash(self, data, classification, symbols, detail):
        module = f"{self.format_name}Parser"
        diag = diagnostics.build(data, classification, module, symbols)
        return ExecResult(outcome=Outcome.CRASH, detail=detail,
                          duration_ms=1, diagnostics=diag)

    def _run(self, data: bytes) -> ExecResult:
        fields = self._extract(data)
        if fields is None:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail=f"not a valid {self.format_name} transcript",
                              duration_ms=1)

        declared = fields["declared"]
        epoch = fields["epoch"]
        msg_type = fields["msg_type"]
        payload = fields["payload"]

        if declared >= 0xF000:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="declared transcript length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["advance_session", "copy_transcript", "read_msg_body"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if msg_type == _NULL_TYPE:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["advance_session", "lookup_epoch_state", "deref_state"],
                "message type 0 dereferences a null epoch state")
        if epoch == 0xFFFF:
            return self._crash(
                data, "INTEGER_ERROR",
                ["advance_session", "bump_epoch", "epoch_overflow"],
                "epoch counter wraps past maximum in ratchet state")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["advance_session", "free_stale_state", "use_state"],
                "stale epoch state used after release (replay)")
        if msg_type == _CONFUSION_TYPE:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["advance_session", "reinterpret_message"],
                "message reinterpreted as incompatible handshake state")
        if msg_type == _ASSERT_TYPE:
            return self._crash(
                data, "ASSERTION",
                ["advance_session", "assert_epoch_invariant"],
                "epoch ordering invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} message advanced session",
                          duration_ms=1)


class HandshakeTarget(Pq3Target):
    target_id = "pq3:handshake"
    format_name = "PQ_HS"
    description = "Mock PQ3-style initial-handshake transcript parser (CI-safe)"
    formats = ("handshake",)
    magic = b"PQHS"


class RekeyTarget(Pq3Target):
    target_id = "pq3:rekey"
    format_name = "PQ_RK"
    description = "Mock PQ3-style rekey/epoch-transition transcript parser (CI-safe)"
    formats = ("rekey",)
    magic = b"PQRK"


PQ3_TARGETS = {
    "pq3:handshake": HandshakeTarget,
    "pq3:rekey": RekeyTarget,
}
