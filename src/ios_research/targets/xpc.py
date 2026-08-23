"""Mock XPC/Mach message-schema research targets (dictionary/array/endpoint shapes).

Boundary: this module is *local chain-tail discovery tooling*. It only parses
in-memory byte strings shaped like researcher-captured XPC/Mach message
schemas. v1 never sends messages to system daemons; the only daemon-adjacent
surface is an offline corpus-seed importer (`target xpc harvest`) that reads a
researcher-exported JSON schema file and emits deterministic seed bytes.

Normalized mock message (after each target's magic bytes)::

    [declared_length u16 BE][entry_type u8][entry_count u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# entry-type tags that trigger deterministic defect paths
_NULL_ENTRY_TYPE = 0x00     # null connection-context dereference
_CONFUSION_ENTRY_TYPE = 0xC0  # wrong-type value in a typed dictionary slot


class XpcTarget(Target):
    kind = "xpc"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = "mock message-schema parser; no messages sent to system daemons"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 2])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.xpc(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        entry_type = body[2]
        entry_count = body[3]
        payload = body[4:]
        return {"declared": declared, "entry_type": entry_type,
                "entry_count": entry_count, "payload": payload}

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
                ["decode_message", "walk_entries", "read_entry_data"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["entry_type"] == _NULL_ENTRY_TYPE:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["decode_message", "resolve_connection", "deref_context"],
                "entry type 0 dereferences a null connection context")
        if fields["entry_count"] == 0:
            return self._crash(
                data, "INTEGER_ERROR",
                ["decode_message", "scale_table_offsets", "div_by_entries"],
                "entry count 0 causes divide-by-zero scaling dictionary table offsets")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["decode_message", "release_dict", "use_dict"],
                "dictionary buffer used after release during decode")
        if fields["entry_type"] == _CONFUSION_ENTRY_TYPE:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["decode_message", "coerce_value"],
                "wrong-type value substituted into typed dictionary slot")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} message decoded", duration_ms=1)


class DictTarget(XpcTarget):
    target_id = "xpc:dict"
    format_name = "X_DCT"
    description = "Mock XPC dictionary-schema message parser (CI-safe)"
    formats = ("dict",)
    magic = b"XDIC"


class ArrayTarget(XpcTarget):
    target_id = "xpc:array"
    format_name = "X_ARR"
    description = "Mock XPC array-schema message parser (CI-safe)"
    formats = ("array",)
    magic = b"XARR"


class EndpointTarget(XpcTarget):
    target_id = "xpc:endpoint"
    format_name = "X_EPT"
    description = "Mock Mach endpoint-wrapper message parser (CI-safe)"
    formats = ("endpoint",)
    magic = b"XEPT"


XPC_TARGETS = {
    "xpc:dict": DictTarget,
    "xpc:array": ArrayTarget,
    "xpc:endpoint": EndpointTarget,
}
