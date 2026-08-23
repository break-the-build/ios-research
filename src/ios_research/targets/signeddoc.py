"""Mock signed-identity-document research targets (profile / provision /
receipt / pkpass).

Mock parser targets following the bluetooth-module contract: deterministic,
CI-safe, and exercising the standard ``prepare/execute/collect/cleanup``
lifecycle. They only *parse bytes* and report normalized outcomes. Boundary:
verify-only structural parsing of synthetic documents; no private-key
material, no signing oracle, no interaction with Apple validation services.

Normalized mock document (after each target's magic bytes)::

    [declared_length u16 BE][asn1_class u8][der_flags u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# ASN.1 class tags that trigger deterministic defect paths
_NULL_CLASS = 0x00        # class 0 dereferences an empty certificate chain
_CONFUSION_CLASS = 0xC0   # OID arc reinterpreted as incompatible class
_ASSERT_CLASS = 0x7E      # SET-OF ordering invariant assertion

_INDEFINITE_FLAG = 0x08   # indefinite-length DER edge -> length arithmetic
_UAF_MARKER = b"\xde\xad"  # released SET-OF buffer reused


class SignedDocTarget(Target):
    kind = "signeddoc"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = "mock signed-document parser; verify-only, synthetic documents"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 0])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.signeddoc(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        asn1_class = body[2]
        der_flags = body[3]
        payload = body[4:]
        return {"declared": declared, "asn1_class": asn1_class,
                "der_flags": der_flags, "payload": payload}

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
        payload = fields["payload"]

        if declared >= 0xF000:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="declared document length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["parse_signed_doc", "walk_tlv", "read_der_body"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["asn1_class"] == _NULL_CLASS:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["parse_signed_doc", "resolve_cert", "deref_chain"],
                "class 0 dereferences an empty certificate chain")
        if fields["der_flags"] & _INDEFINITE_FLAG:
            return self._crash(
                data, "INTEGER_ERROR",
                ["parse_signed_doc", "decode_length",
                 "indefinite_length_arithmetic"],
                "indefinite-length DER edge causes length arithmetic overflow")
        if _UAF_MARKER in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["parse_signed_doc", "release_set", "use_set"],
                "SET-OF buffer used after release during canonicalization")
        if fields["asn1_class"] == _CONFUSION_CLASS:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["parse_signed_doc", "reinterpret_oid"],
                "OID arc reinterpreted as incompatible ASN.1 class")
        if fields["asn1_class"] == _ASSERT_CLASS:
            return self._crash(
                data, "ASSERTION",
                ["parse_signed_doc", "assert_set_invariant"],
                "SET-OF ordering invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} document verified structurally",
                          duration_ms=1)


class ProfileDocTarget(SignedDocTarget):
    target_id = "signeddoc:profile"
    format_name = "SD_PRO"
    description = "Mock configuration-profile CMS envelope structure parser (CI-safe)"
    formats = ("profile",)
    magic = b"SPRO"


class ProvisionDocTarget(SignedDocTarget):
    target_id = "signeddoc:provision"
    format_name = "SD_PRV"
    description = "Mock provisioning-profile entitlement record parser (CI-safe)"
    formats = ("provision",)
    magic = b"SPRV"


class ReceiptDocTarget(SignedDocTarget):
    target_id = "signeddoc:receipt"
    format_name = "SD_RCP"
    description = "Mock StoreKit-style receipt ASN.1 container parser (CI-safe)"
    formats = ("receipt",)
    magic = b"SRCP"


class PkpassDocTarget(SignedDocTarget):
    target_id = "signeddoc:pkpass"
    format_name = "SD_KPS"
    description = "Mock wallet-pass manifest/signature co-validation record parser (CI-safe)"
    formats = ("pkpass",)
    magic = b"SKPS"


SIGNEDDOC_TARGETS = {
    "signeddoc:profile": ProfileDocTarget,
    "signeddoc:provision": ProvisionDocTarget,
    "signeddoc:receipt": ReceiptDocTarget,
    "signeddoc:pkpass": PkpassDocTarget,
}
