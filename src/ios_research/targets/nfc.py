"""Mock NFC/NDEF record parser research targets (ndef/iso-dep/tag-command).

Mock parser targets following the audio-module contract: deterministic,
CI-safe, and exercising the standard ``prepare/execute/collect/cleanup``
lifecycle. They only *parse bytes* and report normalized outcomes. No RF
field interaction, no tag hardware access.

Normalized mock NDEF-style message (after each target's magic bytes)::

    [declared_length u16 BE][record_tnf u8][id_length u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# TNF (type-name field) tags that trigger deterministic defect paths
_EMPTY_TNF = 0x00         # empty record; must not carry an ID
_UNKNOWN_TNF = 0x06       # unknown TNF reinterpreted as a known type


class NfcTarget(Target):
    kind = "nfc"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = "mock NFC record parser; no tag hardware or RF access"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 0])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.nfc(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        tnf = body[2]
        id_length = body[3]
        payload = body[4:]
        return {"declared": declared, "tnf": tnf,
                "id_length": id_length, "payload": payload}

    def _crash(self, data, classification, symbols, detail):
        module = f"{self.format_name}Parser"
        diag = diagnostics.build(data, classification, module, symbols)
        return ExecResult(outcome=Outcome.CRASH, detail=detail,
                          duration_ms=1, diagnostics=diag)

    def _run(self, data: bytes) -> ExecResult:
        fields = self._extract(data)
        if fields is None:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail=f"not a valid {self.format_name} message",
                              duration_ms=1)

        declared = fields["declared"]
        payload = fields["payload"]

        if declared >= 0xF000:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="declared message length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["parse_ndef_message", "walk_records", "read_record_body"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["tnf"] == _EMPTY_TNF and fields["id_length"] != 0:
            return self._crash(
                data, "ASSERTION",
                ["parse_ndef_message", "assert_record_invariant"],
                "empty TNF record must not carry a non-zero ID length")
        if fields["tnf"] == _UNKNOWN_TNF:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["parse_ndef_message", "reinterpret_record"],
                "unknown-TNF record reinterpreted as a known record type")
        if fields["id_length"] > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_WRITE",
                ["parse_ndef_message", "copy_record_id"],
                f"id_length={fields['id_length']} exceeds "
                f"payload={len(payload)} during ID copy")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} message decoded",
                          duration_ms=1)


class NdefTarget(NfcTarget):
    target_id = "nfc:ndef"
    format_name = "NDEF"
    description = "Mock NFC NDEF message parser (CI-safe)"
    formats = ("ndef",)
    magic = b"NDEF"


class IsoDepTarget(NfcTarget):
    target_id = "nfc:isodep"
    format_name = "ISO_DEP"
    description = "Mock ISO-DEP transport frame parser (CI-safe)"
    formats = ("isodep",)
    magic = b"ISDP"


class TagCommandTarget(NfcTarget):
    target_id = "nfc:tagcmd"
    format_name = "TAG_CMD"
    description = "Mock tag command/response APDU parser (CI-safe)"
    formats = ("tagcmd",)
    magic = b"TAGC"


NFC_TARGETS = {
    "nfc:ndef": NdefTarget,
    "nfc:isodep": IsoDepTarget,
    "nfc:tagcmd": TagCommandTarget,
}
