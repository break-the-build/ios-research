"""Mock communication-message parser research targets (SMS/MIME/link-preview).

Network zero-click entry-point profiles (#85): deterministic, CI-safe mock
parsers for message-envelope structures of the kind that reach a device with
no user interaction — SMS/MMS/RCS-style part framing, MIME multipart trees,
and link-preview metadata records. They follow the audio-module contract and
exercise the standard ``prepare/execute/collect/cleanup`` lifecycle.

Safety: they only *parse bytes* and report normalized outcomes. No message
transmission, no account or identifier targeting, no carrier or network
interaction — localhost/mock delivery to researcher-owned harnesses only.

Normalized mock message envelope (after each format's magic bytes)::

    [declared_length u16 BE][part_count u8][encoding u8][payload...]

One shared defect model is reached through three independent front-ends, so a
single root cause surfaces across formats (the "one bug, N surfaces" shape
real message pipelines exhibit).
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# encoding tags that trigger deterministic defect paths
_CONFUSION_ENCODING = 0xC0  # charset decoder state reinterpreted
_ASSERT_ENCODING = 0x7E     # part-assembly invariant assertion


class MessagingTarget(Target):
    kind = "messaging"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = ("mock communication-message parser; no messaging "
                     "transport, account, or network access")
        d["entry_point"] = "network-zero-click"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 1])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.messaging(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        part_count = body[2]
        encoding = body[3]
        payload = body[4:]
        return {"declared": declared, "part_count": part_count,
                "encoding": encoding, "payload": payload}

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
                              detail="declared assembly length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["parse_message", "walk_parts", "read_part_body"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["part_count"] == 0:
            return self._crash(
                data, "INTEGER_ERROR",
                ["parse_message", "scale_part_offsets", "div_by_part_count"],
                "part count 0 causes divide-by-zero when scaling part offsets")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["parse_message", "release_assembly_buffer", "use_buffer"],
                "message assembly buffer used after release")
        if fields["encoding"] == _CONFUSION_ENCODING:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["parse_message", "reinterpret_decoder_state"],
                "charset decoder state reinterpreted as incompatible type")
        if fields["encoding"] == _ASSERT_ENCODING:
            return self._crash(
                data, "ASSERTION",
                ["parse_message", "assert_part_invariant"],
                "part-assembly invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} envelope decoded",
                          duration_ms=1)


class SmsTarget(MessagingTarget):
    target_id = "messaging:sms"
    format_name = "SMS"
    description = ("Mock SMS/MMS-style message-envelope parser "
                   "(CI-safe; zero-click profile)")
    formats = ("sms",)
    magic = b"SMST"


class MimeTarget(MessagingTarget):
    target_id = "messaging:mime"
    format_name = "MIME"
    description = ("Mock MIME multipart message parser "
                   "(CI-safe; zero-click profile)")
    formats = ("mime",)
    magic = b"MIME"


class LinkPreviewTarget(MessagingTarget):
    target_id = "messaging:link-preview"
    format_name = "LINK_PREVIEW"
    description = ("Mock link-preview metadata record parser "
                   "(CI-safe; zero-click profile)")
    formats = ("link-preview",)
    magic = b"LNKP"


MESSAGING_TARGETS = {
    "messaging:sms": SmsTarget,
    "messaging:mime": MimeTarget,
    "messaging:link-preview": LinkPreviewTarget,
}
