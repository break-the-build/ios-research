"""Deterministic identifier generation.

Identifiers are derived from stable inputs (kind + seed material) so that
reproducible experiments produce reproducible IDs. This is central to the
framework's determinism guarantees.
"""

from __future__ import annotations

from .hashing import sha256_text

_PREFIXES = {
    "experiment": "exp",
    "device": "dev",
    "target": "tgt",
    "corpus": "cor",
    "testcase": "tc",
    "crash": "crash",
    "analysis": "an",
    "report": "rep",
    "diff": "diff",
    "research": "res",
    "artifact": "art",
    "matrix": "mtx",
    "oracle": "ora",
    "evidence": "evd",
    "seqrun": "seq",
    "obstrace": "obs",
    "campaign": "camp",
}


def make_id(kind: str, *parts: str, length: int = 12) -> str:
    """Return a deterministic id of the form ``<prefix>_<hash>``.

    The hash is derived from ``kind`` plus all ``parts``; identical inputs always
    yield the same id.
    """
    prefix = _PREFIXES.get(kind, kind[:3])
    material = "|".join([kind, *[str(p) for p in parts]])
    return f"{prefix}_{sha256_text(material)[:length]}"
