"""Artifact tracking.

An *artifact* is any content-addressed file produced by the framework (a
testcase, a crash input, a diagnostics blob, a report). Artifacts are stored by
SHA-256 so identical content is stored once and every reference is verifiable.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict

from .clock import now_iso
from .hashing import sha256_bytes
from .workspace import Workspace


@dataclass
class Artifact:
    id: str
    kind: str
    sha256: str
    size: int
    path: str
    created_at: str

    def to_dict(self) -> dict:
        return asdict(self)


class ArtifactStore:
    """Content-addressed store under ``artifacts/`` in the workspace."""

    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def put(self, data: bytes, *, kind: str) -> Artifact:
        digest = sha256_bytes(data)
        rel = f"artifacts/{digest[:2]}/{digest}.bin"
        if not self.ws.path(rel).exists():
            self.ws.write_bytes(rel, data)
        artifact = Artifact(
            id=f"art_{digest[:12]}",
            kind=kind,
            sha256=digest,
            size=len(data),
            path=rel,
            created_at=now_iso(),
        )
        self.ws.write_json(f"artifacts/index/{digest}.json", artifact.to_dict())
        return artifact

    def get_bytes(self, sha256: str) -> bytes:
        return self.ws.read_bytes(f"artifacts/{sha256[:2]}/{sha256}.bin")

    def exists(self, sha256: str) -> bool:
        return self.ws.path(f"artifacts/{sha256[:2]}/{sha256}.bin").exists()
