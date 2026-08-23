"""Mock Wi-Fi management-frame parser research targets (beacon/probe/action).

Mock parser targets following the audio-module contract: deterministic,
CI-safe, and exercising the standard ``prepare/execute/collect/cleanup``
lifecycle. They only *parse bytes* and report normalized outcomes. No RF
transmission, no injection, no association with real networks.

Normalized mock management frame (after each target's magic bytes)::

    [declared_length u16 BE][frame_subtype u8][ie_count u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# frame-subtype tags that trigger deterministic defect paths
_CONFUSION_SUBTYPE = 0xC0  # management reinterpreted as control-frame state
_ASSERT_SUBTYPE = 0x7E     # element-parse invariant assertion


class WifiTarget(Target):
    kind = "wifi"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = "mock Wi-Fi frame parser; no radio or network access"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 2])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.wifi(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        subtype = body[2]
        ie_count = body[3]
        payload = body[4:]
        return {"declared": declared, "subtype": subtype,
                "ie_count": ie_count, "payload": payload}

    def _crash(self, data, classification, symbols, detail):
        module = f"{self.format_name}Parser"
        diag = diagnostics.build(data, classification, module, symbols)
        return ExecResult(outcome=Outcome.CRASH, detail=detail,
                          duration_ms=1, diagnostics=diag)

    def _run(self, data: bytes) -> ExecResult:
        fields = self._extract(data)
        if fields is None:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail=f"not a valid {self.format_name} frame",
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
                ["parse_management_frame", "walk_elements", "read_ie_body"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["ie_count"] == 0:
            return self._crash(
                data, "INTEGER_ERROR",
                ["parse_management_frame", "scale_element_offsets",
                 "div_by_ie_count"],
                "information-element count 0 causes divide-by-zero when "
                "scaling element offsets")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["parse_management_frame", "reclaim_frame", "use_frame"],
                "management frame buffer used after reclaim")
        if fields["subtype"] == _CONFUSION_SUBTYPE:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["parse_management_frame", "reinterpret_frame"],
                "management frame reinterpreted as control-frame state")
        if fields["subtype"] == _ASSERT_SUBTYPE:
            return self._crash(
                data, "ASSERTION",
                ["parse_management_frame", "assert_element_invariant"],
                "information-element invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} frame decoded", duration_ms=1)


class BeaconTarget(WifiTarget):
    target_id = "wifi:beacon"
    format_name = "BEACON"
    description = "Mock 802.11 beacon frame parser (CI-safe)"
    formats = ("beacon",)
    magic = b"BCON"


class ProbeRespTarget(WifiTarget):
    target_id = "wifi:probe-resp"
    format_name = "PROBE_RESP"
    description = "Mock 802.11 probe-response frame parser (CI-safe)"
    formats = ("probe-resp",)
    magic = b"PRSP"


class ActionTarget(WifiTarget):
    target_id = "wifi:action"
    format_name = "ACTION"
    description = "Mock 802.11 action-frame parser (CI-safe)"
    formats = ("action",)
    magic = b"ACTN"


WIFI_TARGETS = {
    "wifi:beacon": BeaconTarget,
    "wifi:probe-resp": ProbeRespTarget,
    "wifi:action": ActionTarget,
}
