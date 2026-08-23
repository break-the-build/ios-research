"""Mock filesystem-client research targets (exFAT volume / SMB2 response).

Mock parser targets following the audio-module contract: deterministic,
CI-safe, and exercising the standard ``prepare/execute/collect/cleanup``
lifecycle. They only *parse bytes* and report normalized outcomes, and
they provide loopback templates only: nothing mounts against hosts or
devices not owned by the researcher, and no live network file-service
traffic is generated.

Normalized mock response (after each target's magic bytes)::

    [declared_length u16 BE][struct_class u8][cluster_flags u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# structure-class tags that trigger deterministic defect paths
_NULL_CLASS = 0x00       # null boot-sector record dereference
_CONFUSION_CLASS = 0xC0  # response reinterpreted as incompatible state


class FsClientTarget(Target):
    kind = "fsclient"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = ("mock filesystem-client parser; bytes-only, "
                     "loopback templates only")
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 0])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.fsclient(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        struct_class = body[2]
        cluster_flags = body[3]
        payload = body[4:]
        return {"declared": declared, "struct_class": struct_class,
                "cluster_flags": cluster_flags, "payload": payload}

    def _crash(self, data, classification, symbols, detail):
        module = f"{self.format_name}Parser"
        diag = diagnostics.build(data, classification, module, symbols)
        return ExecResult(outcome=Outcome.CRASH, detail=detail,
                          duration_ms=1, diagnostics=diag)

    def _run(self, data: bytes) -> ExecResult:
        fields = self._extract(data)
        if fields is None:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail=f"not a valid {self.format_name} response",
                              duration_ms=1)

        declared = fields["declared"]
        payload = fields["payload"]

        if declared >= 0xF000:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="declared response length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["parse_response", "walk_structures", "read_record_body"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["struct_class"] == _NULL_CLASS:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["parse_response", "mount_volume", "deref_boot_sector"],
                "structure class 0 dereferences a null boot-sector record")
        if fields["cluster_flags"] & 0x01:
            return self._crash(
                data, "INTEGER_ERROR",
                ["parse_response", "compute_chain_length", "div_by_clusters"],
                "cluster count zero causes divide-by-zero computing chain length")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["parse_response", "release_buffer", "use_buffer"],
                "volume buffer used after release during reparse")
        if fields["struct_class"] == _CONFUSION_CLASS:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["parse_response", "reinterpret_structure"],
                "response structure reinterpreted as incompatible filesystem state")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} response parsed",
                          duration_ms=1)


class ExfatVolTarget(FsClientTarget):
    target_id = "fsclient:exfat-vol"
    format_name = "FS_XFA"
    description = "Mock exFAT volume-structure parser (CI-safe)"
    formats = ("exfat-vol",)
    magic = b"FXFA"


class Smb2RespTarget(FsClientTarget):
    target_id = "fsclient:smb2-resp"
    format_name = "FS_MB2"
    description = "Mock SMB2 response-PDU structure parser (CI-safe)"
    formats = ("smb2-resp",)
    magic = b"FSM2"


FSCLIENT_TARGETS = {
    "fsclient:exfat-vol": ExfatVolTarget,
    "fsclient:smb2-resp": Smb2RespTarget,
}
