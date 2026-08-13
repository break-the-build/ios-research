"""Mock audio-processing research targets (WAV/MP3/AAC/ALAC).

These are the first "real module" targets: deterministic, CI-safe mock parsers
for audio container/codec headers. They exercise the same
``prepare/execute/collect/cleanup`` interface as every other target.

Safety: these targets only *parse bytes* and report normalized outcomes. They do
not activate a microphone or camera, bypass permissions, or perform any device
access. A real authorized research device can later be attached behind this same
interface (see the module docstring in docs/PROMPT-03-audio-module.md).

Normalized mock audio container (after each format's magic bytes)::

    [declared_length u16 BE][channels u8][codec u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# codec tags that trigger deterministic defect paths
_CONFUSION_CODEC = 0xC0
_ASSERT_CODEC = 0x7E


class AudioTarget(Target):
    kind = "audio"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = "mock audio parser; no device sensors are accessed"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([2, 1])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.audio(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        channels = body[2]
        codec = body[3]
        payload = body[4:]
        return {"declared": declared, "channels": channels,
                "codec": codec, "payload": payload}

    def _crash(self, data, classification, symbols, detail):
        module = f"{self.format_name}Parser"
        diag = diagnostics.build(data, classification, module, symbols)
        return ExecResult(outcome=Outcome.CRASH, detail=detail,
                          duration_ms=1, diagnostics=diag)

    def _run(self, data: bytes) -> ExecResult:
        fields = self._extract(data)
        if fields is None:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail=f"not a valid {self.format_name} header",
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
                ["decode_frame", "copy_samples", "read_pcm"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["channels"] == 0:
            return self._crash(
                data, "INTEGER_ERROR",
                ["decode_frame", "deinterleave", "div_by_channels"],
                "channel count 0 causes divide-by-zero in deinterleave")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["decode_frame", "release_buffer", "use_buffer"],
                "sample buffer used after release")
        if fields["codec"] == _CONFUSION_CODEC:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["decode_frame", "reinterpret_codec"],
                "payload reinterpreted as incompatible codec state")
        if fields["codec"] == _ASSERT_CODEC:
            return self._crash(
                data, "ASSERTION",
                ["decode_frame", "assert_codec_invariant"],
                "codec invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} frame decoded", duration_ms=1)


class WavTarget(AudioTarget):
    target_id = "audio:wav"
    format_name = "WAV"
    description = "Mock WAV/RIFF audio parser (CI-safe)"
    formats = ("wav",)
    magic = b"RIFF"


class Mp3Target(AudioTarget):
    target_id = "audio:mp3"
    format_name = "MP3"
    description = "Mock MP3 audio parser (CI-safe)"
    formats = ("mp3",)
    magic = b"ID3\x04"


class AacTarget(AudioTarget):
    target_id = "audio:aac"
    format_name = "AAC"
    description = "Mock AAC/ADTS audio parser (CI-safe)"
    formats = ("aac",)
    magic = b"\xff\xf1"


class AlacTarget(AudioTarget):
    target_id = "audio:alac"
    format_name = "ALAC"
    description = "Mock ALAC/CAF audio parser (CI-safe)"
    formats = ("alac",)
    magic = b"caff"


AUDIO_TARGETS = {
    "audio:wav": WavTarget,
    "audio:mp3": Mp3Target,
    "audio:aac": AacTarget,
    "audio:alac": AlacTarget,
}
