"""Mock document-importer parser research targets (zip/OOXML/font/PDF form).

Mock parser targets following the audio-module contract: deterministic,
CI-safe, and exercising the standard ``prepare/execute/collect/cleanup``
lifecycle. They only *parse bytes* and report normalized outcomes. No
quarantine or launch behavior is simulated, and no document code paths are
executed beyond those normalized outcomes.

Normalized mock container (after each target's magic bytes)::

    [declared_length u16 BE][part_class u8][part_flags u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# part-class tags that trigger deterministic defect paths
_NULL_CLASS = 0x00       # null content-stream dereference
_CONFUSION_CLASS = 0xC0  # document part reinterpreted as incompatible state
_ASSERT_CLASS = 0x7E     # document-part invariant assertion

# part-flag bit that triggers a flag-derived integer error
_INTEGER_FLAG = 0x04


class DocImportTarget(Target):
    kind = "docimp"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = "mock document-importer parser; bytes-only"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 0])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.docimp(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        part_class = body[2]
        part_flags = body[3]
        payload = body[4:]
        return {"declared": declared, "part_class": part_class,
                "part_flags": part_flags, "payload": payload}

    def _crash(self, data, classification, symbols, detail):
        module = f"{self.format_name}Parser"
        diag = diagnostics.build(data, classification, module, symbols)
        return ExecResult(outcome=Outcome.CRASH, detail=detail,
                          duration_ms=1, diagnostics=diag)

    def _run(self, data: bytes) -> ExecResult:
        fields = self._extract(data)
        if fields is None:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail=f"not a valid {self.format_name} document",
                              duration_ms=1)

        declared = fields["declared"]
        part_class = fields["part_class"]
        part_flags = fields["part_flags"]
        payload = fields["payload"]

        if declared >= 0xF000:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="declared part length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["import_document", "walk_parts", "read_part_body"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if part_class == _NULL_CLASS:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["import_document", "resolve_part", "deref_stream"],
                "part class 0 dereferences a null content stream")
        if part_flags & _INTEGER_FLAG:
            return self._crash(
                data, "INTEGER_ERROR",
                ["import_document", "expand_part_table", "mul_by_flags"],
                "flag-derived table multiplier causes offset arithmetic overflow")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["import_document", "release_part", "use_part"],
                "part buffer used after release during import")
        if part_class == _CONFUSION_CLASS:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["import_document", "reinterpret_part"],
                "document part reinterpreted as incompatible schema state")
        if part_class == _ASSERT_CLASS:
            return self._crash(
                data, "ASSERTION",
                ["import_document", "assert_part_invariant"],
                "document-part invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} part imported",
                          duration_ms=1)


class ZipArchiveTarget(DocImportTarget):
    target_id = "docimp:zip-archive"
    format_name = "DOC_ZIP"
    description = "Mock archive central-directory structure parser (CI-safe)"
    formats = ("zip-archive",)
    magic = b"DZIP"


class OoxmlPartTarget(DocImportTarget):
    target_id = "docimp:ooxml-part"
    format_name = "DOC_OOX"
    description = "Mock OOXML part-graph relationship parser (CI-safe)"
    formats = ("ooxml-part",)
    magic = b"DOOX"


class FontTableTarget(DocImportTarget):
    target_id = "docimp:font"
    format_name = "DOC_FNT"
    description = "Mock font table-directory/glyph-bounds structure parser (CI-safe)"
    formats = ("font",)
    magic = b"DFNT"


class PdfformTarget(DocImportTarget):
    target_id = "docimp:pdfform"
    format_name = "DOC_PFF"
    description = "Mock PDF AcroForm field-stack structure parser (CI-safe)"
    formats = ("pdfform",)
    magic = b"DPFF"


DOCIMP_TARGETS = {
    "docimp:zip-archive": ZipArchiveTarget,
    "docimp:ooxml-part": OoxmlPartTarget,
    "docimp:font": FontTableTarget,
    "docimp:pdfform": PdfformTarget,
}
