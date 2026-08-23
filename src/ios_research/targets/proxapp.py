"""Mock proximity application-protocol research targets (#111).

HAP-style TLV8 session records, RTSP/SDP-style option negotiation,
multipeer-session frame envelopes, and vCard streams — modeled as bytes-only
parsers following the bluetooth-module contract: deterministic, CI-safe, and
exercising the standard ``prepare/execute/collect/cleanup`` lifecycle.

Boundary: mock parse targets only. No connections to third-party
accessories/speakers/displays, no RF transmission/injection, no HomeKit
controller actions against real homes.

Normalized mock record (after each target's magic bytes)::

    [declared u16 BE][tlv_type u8][tlv_flags u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# TLV-type tags that trigger deterministic defect paths
_NULL_TYPE = 0x00        # null method-handler dereference
_CONFUSION_TYPE = 0xC0   # frame reinterpreted as incompatible session state
_ASSERT_TYPE = 0x7E      # session-state invariant assertion


class ProxAppTarget(Target):
    kind = "proxapp"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = ("mock proximity protocol parser; "
                     "no real accessory connections")
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 0])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.proxapp(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        tlv_type = body[2]
        tlv_flags = body[3]
        payload = body[4:]
        return {"declared": declared, "type": tlv_type,
                "flags": tlv_flags, "payload": payload}

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
        payload = fields["payload"]

        if declared >= 0xF000:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="declared frame length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["decode_session", "walk_tlvs", "read_tlv_value"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["flags"] & 0x01:
            return self._crash(
                data, "OUT_OF_BOUNDS_WRITE",
                ["decode_session", "copy_tlv_value"],
                "flag-directed TLV copy runs past buffer end during "
                "session decode")
        if fields["type"] == _NULL_TYPE:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["decode_session", "lookup_method", "deref_handler"],
                "TLV type 0 dereferences a null method handler")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["decode_session", "release_session_key", "use_session_key"],
                "session buffer used after release during rekey")
        if fields["type"] == _CONFUSION_TYPE:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["decode_session", "reinterpret_frame"],
                "frame reinterpreted as incompatible session state")
        if fields["type"] == _ASSERT_TYPE:
            return self._crash(
                data, "ASSERTION",
                ["decode_session", "assert_state_invariant"],
                "session-state invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} frame decoded",
                          duration_ms=1)


class HapTlvTarget(ProxAppTarget):
    target_id = "proxapp:hap-tlv"
    format_name = "PA_HAP"
    description = "Mock HomeKit HAP-style TLV8 session-record parser (CI-safe)"
    formats = ("hap-tlv",)
    magic = b"PHAP"


class AirplayNegoTarget(ProxAppTarget):
    target_id = "proxapp:airplay-nego"
    format_name = "PA_ARP"
    description = ("Mock RTSP/SDP-style option negotiation record parser "
                   "(CI-safe)")
    formats = ("airplay-nego",)
    magic = b"PARP"


class MpcFrameTarget(ProxAppTarget):
    target_id = "proxapp:mpc-frame"
    format_name = "PA_MPC"
    description = "Mock multipeer-session frame envelope parser (CI-safe)"
    formats = ("mpc-frame",)
    magic = b"PMPC"


class PbapVcardTarget(ProxAppTarget):
    target_id = "proxapp:pbap-vcard"
    format_name = "PA_PBA"
    description = ("Mock phonebook/message-access vCard-stream record parser "
                   "(CI-safe)")
    formats = ("pbap-vcard",)
    magic = b"PPBA"


PROXAPP_TARGETS = {
    "proxapp:hap-tlv": HapTlvTarget,
    "proxapp:airplay-nego": AirplayNegoTarget,
    "proxapp:mpc-frame": MpcFrameTarget,
    "proxapp:pbap-vcard": PbapVcardTarget,
}
