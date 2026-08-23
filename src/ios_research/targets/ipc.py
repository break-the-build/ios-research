"""Mock IPC trust-boundary payload-envelope research targets (#107).

Trust-boundary decode profiles (#107): deterministic, CI-safe mock parsers for
payload envelopes of the kind that cross a process boundary — share/action
extension payloads, document-provider items, and App Intents donations.

Safety boundary: this module *models decode paths* that cross process
boundaries; the envelope templates are intended for authorized
researcher-owned apps only. No permission mechanics and no TCC interaction —
decode modeling only; the mock targets parse bytes and report normalized
outcomes without touching XPC, app extensions, or any real IPC transport.
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# item-type tags that trigger deterministic defect paths
_NULL_TYPE = 0x00        # null extension-endpoint dereference
_CONFUSION_TYPE = 0xC0   # item reinterpreted as incompatible schema


class IpcTarget(Target):
    kind = "ipc"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = ("mock trust-boundary payload parser; "
                     "decode modeling only")
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 2])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.ipc(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        item_type = body[2]
        item_count = body[3]
        payload = body[4:]
        return {"declared": declared, "item_type": item_type,
                "item_count": item_count, "payload": payload}

    def _crash(self, data, classification, symbols, detail):
        module = f"{self.format_name}Parser"
        diag = diagnostics.build(data, classification, module, symbols)
        return ExecResult(outcome=Outcome.CRASH, detail=detail,
                          duration_ms=1, diagnostics=diag)

    def _run(self, data: bytes) -> ExecResult:
        fields = self._extract(data)
        if fields is None:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail=f"not a valid {self.format_name} envelope",
                              duration_ms=1)

        declared = fields["declared"]
        payload = fields["payload"]

        if declared >= 0xF000:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="declared envelope length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["decode_envelope", "walk_items", "read_item_body"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["item_count"] > 8:
            # fixed-size item-table overflow (table-bounds flavor)
            return self._crash(
                data, "OUT_OF_BOUNDS_WRITE",
                ["decode_envelope", "build_item_table"],
                f"item_count={fields['item_count']} exceeds fixed table "
                f"bounds during index write")
        if fields["item_type"] == _NULL_TYPE:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["decode_envelope", "resolve_extension", "deref_endpoint"],
                "item type 0 dereferences a null extension endpoint")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["decode_envelope", "release_attachment", "use_attachment"],
                "attachment buffer used after release during decode")
        if fields["item_type"] == _CONFUSION_TYPE:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["decode_envelope", "reinterpret_item"],
                "envelope item reinterpreted as incompatible payload schema")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} envelope decoded",
                          duration_ms=1)


class SharePayloadTarget(IpcTarget):
    target_id = "ipc:share-payload"
    format_name = "IPC_SHR"
    description = "Mock share/action extension payload-envelope parser (CI-safe)"
    formats = ("share-payload",)
    magic = b"ISHR"


class DocProviderTarget(IpcTarget):
    target_id = "ipc:docprovider-item"
    format_name = "IPC_DPR"
    description = "Mock document-provider item-envelope parser (CI-safe)"
    formats = ("docprovider-item",)
    magic = b"IDPR"


class IntentDonationTarget(IpcTarget):
    target_id = "ipc:intent-donation"
    format_name = "IPC_INT"
    description = "Mock App Intents donation payload-envelope parser (CI-safe)"
    formats = ("intent-donation",)
    magic = b"IINT"


IPC_TARGETS = {
    "ipc:share-payload": SharePayloadTarget,
    "ipc:docprovider-item": DocProviderTarget,
    "ipc:intent-donation": IntentDonationTarget,
}
