"""Mock Bluetooth frame-parser research targets (BLE adv / L2CAP / GATT).

Mock parser targets following the audio-module contract: deterministic,
CI-safe, and exercising the standard ``prepare/execute/collect/cleanup``
lifecycle. They only *parse bytes* and report normalized outcomes. No RF
transmission, no pairing, no Bluetooth controller or device access.

Normalized mock frame (after each target's magic bytes)::

    [declared_length u16 BE][pkt_type u8][handle_flags u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# packet-type tags that trigger deterministic defect paths
_NULL_TYPE = 0x00        # null connection-handle dereference
_CONFUSION_TYPE = 0xC0   # PDU reinterpreted as incompatible state
_ASSERT_TYPE = 0x7E      # controller invariant assertion


class BluetoothTarget(Target):
    kind = "bluetooth"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = "mock Bluetooth frame parser; no radio or device access"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 0])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.bluetooth(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        pkt_type = body[2]
        flags = body[3]
        payload = body[4:]
        return {"declared": declared, "type": pkt_type, "flags": flags,
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
                ["reassemble_frame", "copy_payload", "read_pdu_body"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["type"] == _NULL_TYPE:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["reassemble_frame", "lookup_handle", "deref_connection"],
                "packet type 0 dereferences a null connection handle")
        if fields["flags"] & 0x01:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["reassemble_frame", "release_fragment", "use_fragment"],
                "fragment buffer used after release during reassembly")
        if fields["type"] == _CONFUSION_TYPE:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["reassemble_frame", "reinterpret_pdu"],
                "PDU reinterpreted as incompatible link-layer state")
        if fields["type"] == _ASSERT_TYPE:
            return self._crash(
                data, "ASSERTION",
                ["reassemble_frame", "assert_controller_invariant"],
                "controller invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} frame decoded", duration_ms=1)


class BtleAdvTarget(BluetoothTarget):
    target_id = "bluetooth:btle-adv"
    format_name = "BTLE_ADV"
    description = "Mock BLE advertising-channel PDU parser (CI-safe)"
    formats = ("btle-adv",)
    magic = b"BTAD"


class L2capTarget(BluetoothTarget):
    target_id = "bluetooth:l2cap"
    format_name = "L2CAP"
    description = "Mock L2CAP signaling-frame parser (CI-safe)"
    formats = ("l2cap",)
    magic = b"L2CS"


class GattTarget(BluetoothTarget):
    target_id = "bluetooth:gatt"
    format_name = "GATT"
    description = "Mock GATT attribute-protocol frame parser (CI-safe)"
    formats = ("gatt",)
    magic = b"GATP"


BLUETOOTH_TARGETS = {
    "bluetooth:btle-adv": BtleAdvTarget,
    "bluetooth:l2cap": L2capTarget,
    "bluetooth:gatt": GattTarget,
}
