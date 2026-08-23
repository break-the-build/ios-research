"""Mock Wi-Fi Aware frame-parser research targets (publish/subscribe/data-path).

Mock parser targets following the audio-module contract: deterministic,
CI-safe, and exercising the standard ``prepare/execute/collect/cleanup``
lifecycle. They only *parse bytes* and report normalized outcomes. No RF
transmission, no injection, and no association with real networks.

Normalized mock frame (after each target's magic bytes)::

    [declared_length u16 BE][attr_id u8][tlv_count u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# attribute tags that trigger deterministic defect paths
_RECLAIM_MARKER = b"\xde\xad"  # reclaimed-buffer marker -> use-after-free
_CONFUSION_ATTR = 0xC0         # attribute reinterpreted as incompatible state
_ASSERT_ATTR = 0x7E            # discovery invariant assertion


class WifiAwareTarget(Target):
    kind = "wifiaware"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = "mock Wi-Fi Aware frame parser; no radio or network access"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 3])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.wifiaware(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        attr_id = body[2]
        tlv_count = body[3]
        payload = body[4:]
        return {"declared": declared, "attr_id": attr_id,
                "tlv_count": tlv_count, "payload": payload}

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
                ["parse_discovery_frame", "walk_attributes", "read_attr_body"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["tlv_count"] == 0:
            return self._crash(
                data, "INTEGER_ERROR",
                ["parse_discovery_frame", "scale_attr_offsets",
                 "div_by_tlv_count"],
                "TLV count 0 causes divide-by-zero when scaling attribute "
                "offsets")
        if _RECLAIM_MARKER in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["parse_discovery_frame", "reclaim_frame", "use_frame"],
                "frame buffer used after reclaim during service discovery")
        if fields["attr_id"] == _CONFUSION_ATTR:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["parse_discovery_frame", "reinterpret_attribute"],
                "attribute reinterpreted as incompatible discovery state")
        if fields["attr_id"] == _ASSERT_ATTR:
            return self._crash(
                data, "ASSERTION",
                ["parse_discovery_frame", "assert_attr_invariant"],
                "attribute invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} frame decoded",
                          duration_ms=1)


class PublishTarget(WifiAwareTarget):
    target_id = "wifiaware:publish"
    format_name = "WAP_PUB"
    description = "Mock Wi-Fi Aware publish/discovery frame parser (CI-safe)"
    formats = ("publish",)
    magic = b"WAPU"


class SubscribeTarget(WifiAwareTarget):
    target_id = "wifiaware:subscribe"
    format_name = "WAP_SUB"
    description = "Mock Wi-Fi Aware subscribe frame parser (CI-safe)"
    formats = ("subscribe",)
    magic = b"WASB"


class DatapathTarget(WifiAwareTarget):
    target_id = "wifiaware:datapath"
    format_name = "WAP_DP"
    description = "Mock Wi-Fi Aware data-path negotiation frame parser (CI-safe)"
    formats = ("datapath",)
    magic = b"WADP"


WIFIAWARE_TARGETS = {
    "wifiaware:publish": PublishTarget,
    "wifiaware:subscribe": SubscribeTarget,
    "wifiaware:datapath": DatapathTarget,
}
