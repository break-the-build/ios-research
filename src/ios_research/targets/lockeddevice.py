"""Mock locked-device surface parser targets (#86).

Physical-access entry-point profiles: deterministic, CI-safe mock parsers for
inputs a *locked* device still processes — lockdownd-style USB service
requests, MFi/iAP2-style accessory authentication challenge blobs, and
lockscreen notification payload render records. They follow the audio-module
contract and exercise the standard ``prepare/execute/collect/cleanup``
lifecycle.

Safety: they only *parse bytes* and report normalized outcomes. No passcode or
biometric guessing, no rate-limit abuse, no data extraction, no persistence,
and no access to any real device or accessory — mock byte parsing only.

Normalized mock locked-device record (after each format's magic bytes)::

    [declared_length u16 BE][record_type u8][flags u8][payload...]

One shared defect model is reached through three independent front-ends.
Module names deliberately carry taxonomy keywords (``lockdownd``, ``usb``,
``lockscreen``, ``notification``) so #58/#84 flag mapping proposes the
physical-access bounty category from stored evidence.
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# record-type tags that trigger deterministic defect paths
_CONFUSION_RECORD = 0xC0  # request reinterpreted as a privileged record type
_ASSERT_RECORD = 0x7E     # session-invariant assertion


class LockedDeviceTarget(Target):
    kind = "locked-device"
    mock = True
    magic = b""
    format_name = ""
    module_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = ("mock locked-device surface parser; no device, "
                     "accessory, passcode, or data-access operations")
        d["entry_point"] = "physical-access"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 0])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.locked_device(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        record_type = body[2]
        flags = body[3]
        payload = body[4:]
        return {"declared": declared, "record_type": record_type,
                "flags": flags, "payload": payload}

    def _crash(self, data, classification, symbols, detail):
        diag = diagnostics.build(data, classification,
                                 self.module_name, symbols)
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
                              detail="declared record length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["parse_record", "read_tlv_value", "copy_field"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["flags"] & 0x80 and b"\x00" not in payload:
            return self._crash(
                data, "INTEGER_ERROR",
                ["parse_record", "scale_session_index", "div_by_zero_pad"],
                "compressed flag with no zero terminator divides by zero "
                "when scaling the session index")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["parse_record", "release_session_buffer", "use_buffer"],
                "session buffer used after release during re-key")
        if fields["record_type"] == _CONFUSION_RECORD:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["parse_record", "reinterpret_privileged_type"],
                "untrusted record reinterpreted as privileged record type")
        if fields["record_type"] == _ASSERT_RECORD:
            return self._crash(
                data, "ASSERTION",
                ["parse_record", "assert_session_invariant"],
                "session invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} record parsed",
                          duration_ms=1)


class LockdowndTarget(LockedDeviceTarget):
    target_id = "lockeddevice:lockdownd"
    format_name = "LOCKDOWN"
    module_name = "LockdowndParser"
    description = ("Mock lockdownd-style USB service-request parser "
                   "(CI-safe; physical-access profile)")
    formats = ("lockdownd",)
    magic = b"LCKD"


class MfiAuthTarget(LockedDeviceTarget):
    target_id = "lockeddevice:mfi-auth"
    format_name = "MFI_AUTH"
    module_name = "USBMfiAuthParser"
    description = ("Mock MFi/iAP2 accessory auth-challenge parser "
                   "(CI-safe; physical-access profile)")
    formats = ("mfi-auth",)
    magic = b"MFI2"


class NotificationTarget(LockedDeviceTarget):
    target_id = "lockeddevice:notification"
    format_name = "NOTIFICATION"
    module_name = "LockscreenNotificationParser"
    description = ("Mock lockscreen notification payload renderer-record "
                   "parser (CI-safe; physical-access profile)")
    formats = ("notification",)
    magic = b"NTFY"


LOCKED_DEVICE_TARGETS = {
    "lockeddevice:lockdownd": LockdowndTarget,
    "lockeddevice:mfi-auth": MfiAuthTarget,
    "lockeddevice:notification": NotificationTarget,
}
