"""Mock lockscreen voice-assistant record-parser research targets (#114).

Mock parser targets for Siri-suggestion and CallKit call-intent *records*:
deterministic, CI-safe, and exercising the standard
``prepare/execute/collect/cleanup`` lifecycle.

HARD BOUNDARY: these targets parse **text/intent records only**. They NEVER
activate a microphone or perform audio capture of any kind, and they contain
no passcode or biometric mechanics. See SECURITY.md for the framework's
capability boundary.

Normalized mock record (after each target's magic bytes)::

    [declared_length u16 BE][rec_class u8][rec_flags u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# record-class tags that trigger deterministic defect paths
_NULL_CLASS = 0x00       # null caller-metadata dereference
_CONFUSION_CLASS = 0xC0  # record reinterpreted as incompatible render state


class VoiceAssistTarget(Target):
    kind = "voiceassist"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = ("mock intent-record parser; text records only, never "
                     "activates microphone or audio capture")
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 0])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.voiceassist(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        rec_class = body[2]
        rec_flags = body[3]
        payload = body[4:]
        return {"declared": declared, "class": rec_class,
                "flags": rec_flags, "payload": payload}

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
        rec_class = fields["class"]
        rec_flags = fields["flags"]
        payload = fields["payload"]

        if declared >= 0xF000:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="declared record length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["render_record", "walk_fields", "read_field_data"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if rec_class == _NULL_CLASS:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["render_record", "resolve_caller", "deref_metadata"],
                "record class 0 dereferences null caller metadata")
        if rec_flags & 0x10:
            return self._crash(
                data, "INTEGER_ERROR",
                ["render_record", "layout_strings", "mul_by_flag"],
                "localized-string count multiplier causes layout offset overflow")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["render_record", "release_string", "use_string"],
                "localized-string buffer used after release during render")
        if rec_class == _CONFUSION_CLASS:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["render_record", "reinterpret_record"],
                "intent record reinterpreted as incompatible render state")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} record rendered",
                          duration_ms=1)


class SiriSuggestionTarget(VoiceAssistTarget):
    target_id = "voiceassist:siri-suggestion"
    format_name = "VA_SIR"
    description = ("Mock Siri-suggestion record-shape parser "
                   "(CI-safe, text records only)")
    formats = ("siri-suggestion",)
    magic = b"VSIR"


class CallkitIntentTarget(VoiceAssistTarget):
    target_id = "voiceassist:callkit-intent"
    format_name = "VA_CKI"
    description = ("Mock CallKit call-intent metadata-record parser "
                   "(CI-safe, text records only)")
    formats = ("callkit-intent",)
    magic = b"VCKI"


VOICEASSIST_TARGETS = {
    "voiceassist:siri-suggestion": SiriSuggestionTarget,
    "voiceassist:callkit-intent": CallkitIntentTarget,
}
