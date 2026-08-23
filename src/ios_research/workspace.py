"""Workspace model: the on-disk layout for a research workspace.

A workspace holds all state for reproducible research: configuration,
experiments, devices, targets, corpora, crashes, artifacts, reports and logs.
Operations are designed to be resumable — state lives on disk as JSON.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .errors import NotFoundError, ValidationError

WORKSPACE_DIRNAME = ".ios-research"

SUBDIRS = (
    "config",
    "experiments",
    "devices",
    "targets",
    "corpus",
    "fuzz",
    "crashes",
    "artifacts",
    "reports",
    "analysis",
    "diffs",
    "research",
    "harnesses",
    "spoints",
    "matrices",
    "advisories",
    "logs",
)

MARKER_FILE = "workspace.json"


class Workspace:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()

    # -- discovery ---------------------------------------------------------
    @classmethod
    def locate(cls, start: Path | None = None) -> "Workspace | None":
        """Walk upward from ``start`` looking for an initialized workspace."""
        current = Path(start or Path.cwd()).resolve()
        for candidate in [current, *current.parents]:
            marker = candidate / WORKSPACE_DIRNAME / MARKER_FILE
            if marker.exists():
                return cls(candidate / WORKSPACE_DIRNAME)
        return None

    @classmethod
    def require(cls, start: Path | None = None) -> "Workspace":
        ws = cls.locate(start)
        if ws is None:
            raise NotFoundError(
                "no ios-research workspace found; run 'ios-research init' first")
        return ws

    # -- lifecycle ---------------------------------------------------------
    @property
    def initialized(self) -> bool:
        return (self.root / MARKER_FILE).exists()

    def init(self, *, framework_version: str, created_at: str,
             force: bool = False) -> dict[str, Any]:
        if self.initialized and not force:
            raise ValidationError(f"workspace already initialized at {self.root}")
        self.root.mkdir(parents=True, exist_ok=True)
        for sub in SUBDIRS:
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        marker = {
            "framework": "ios-research",
            "framework_version": framework_version,
            "created_at": created_at,
            "schema_version": 1,
        }
        self.write_json(MARKER_FILE, marker)
        return marker

    # -- paths -------------------------------------------------------------
    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def dir(self, name: str) -> Path:
        if name not in SUBDIRS:
            raise ValidationError(f"unknown workspace subdir: {name}")
        return self.root / name

    # -- json helpers ------------------------------------------------------
    def write_json(self, rel: str, obj: Any) -> Path:
        dest = self.root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        tmp.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n",
                       encoding="utf-8")
        os.replace(tmp, dest)  # atomic write to avoid artifact corruption
        return dest

    def read_json(self, rel: str) -> Any:
        dest = self.root / rel
        if not dest.exists():
            raise NotFoundError(f"missing workspace file: {rel}")
        return json.loads(dest.read_text(encoding="utf-8"))

    def write_bytes(self, rel: str, data: bytes) -> Path:
        dest = self.root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, dest)
        return dest

    def read_bytes(self, rel: str) -> bytes:
        dest = self.root / rel
        if not dest.exists():
            raise NotFoundError(f"missing workspace file: {rel}")
        return dest.read_bytes()

    def list_json(self, subdir: str) -> list[dict[str, Any]]:
        """Load every ``*.json`` record directly under ``subdir`` (sorted)."""
        out: list[dict[str, Any]] = []
        base = self.dir(subdir)
        if not base.exists():
            return out
        for child in sorted(base.glob("*.json")):
            out.append(json.loads(child.read_text(encoding="utf-8")))
        return out
