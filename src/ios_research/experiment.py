"""Experiment model and store.

Every meaningful operation happens inside an *experiment*, which stamps the
target, device, OS version, framework version and configuration hash so results
are reproducible and auditable. Experiments persist as JSON and are resumable.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from . import __version__
from .clock import now_iso
from .errors import NotFoundError
from .ids import make_id
from .workspace import Workspace, validate_component

# Experiment lifecycle states.
CREATED = "created"
RUNNING = "running"
PAUSED = "paused"
COMPLETED = "completed"
FAILED = "failed"


@dataclass
class Experiment:
    id: str
    created_at: str
    target: str
    device: str
    os_version: str
    framework_version: str
    config_hash: str
    seed: int = 0
    status: str = CREATED
    params: dict[str, Any] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ExperimentStore:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def _rel(self, exp_id: str) -> str:
        return f"experiments/{exp_id}.json"

    def create(self, *, target: str, device: str, os_version: str,
               config_hash: str, seed: int = 0,
               params: dict[str, Any] | None = None) -> Experiment:
        created_at = now_iso()
        exp_id = make_id("experiment", target, device, os_version,
                         config_hash, str(seed), created_at)
        exp = Experiment(
            id=exp_id,
            created_at=created_at,
            target=target,
            device=device,
            os_version=os_version,
            framework_version=__version__,
            config_hash=config_hash,
            seed=seed,
            params=params or {},
            updated_at=created_at,
        )
        self.save(exp)
        return exp

    def save(self, exp: Experiment) -> None:
        exp.updated_at = now_iso()
        self.ws.write_json(self._rel(exp.id), exp.to_dict())

    def get(self, exp_id: str) -> Experiment:
        validate_component(exp_id, what="experiment id")
        rel = self._rel(exp_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"experiment '{exp_id}' not found")
        return Experiment(**self.ws.read_json(rel))

    def list(self) -> list[Experiment]:
        return [Experiment(**d) for d in self.ws.list_json("experiments")]
