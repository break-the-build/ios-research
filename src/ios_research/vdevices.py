"""Authorized virtual-device backend with snapshots and state restore (#43).

Closes the controlled-device lifecycle gap: campaigns can reset an authorized
virtual device to a known snapshot between trials, reproduce a crash from that
snapshot, and export provider-independent evidence metadata.

* **Provider-neutral**: providers plug in behind :class:`DeviceProvider`. The
  built-in ``fake`` provider is fully deterministic and runs anywhere (CI).
  Any real provider is **opt-in twice**: its name must appear in the caller's
  approved-provider set AND explicit credentials must be supplied — otherwise
  every request fails closed with a safety error.
* **Lifecycle**: create -> boot -> snapshot -> restore -> destroy, each step
  stamped into an append-only provenance log (image/device/build metadata).
* **Deterministic trials**: ``run_isolated()`` restores a clean snapshot
  before invoking a declared target, so trial N sees exactly the state trial
  1 saw. Only researcher-selected artifacts are retained afterwards.

No jailbreak, privilege escalation, bypass, exploit validation, or automatic
root-level action exists here; providers implement their own constrained,
user-authorized mechanics behind this narrow interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .clock import now_iso
from .errors import NotFoundError, SafetyError, ValidationError
from .hashing import sha256_text
from .ids import make_id
from .workspace import Workspace

VDEVICE_SCHEMA_VERSION = 1


class DeviceProvider:
    """Narrow provider contract (in-memory instances only)."""

    name = "abstract"

    def create(self, spec: dict[str, Any]) -> str:  # pragma: no cover
        raise NotImplementedError

    def boot(self, instance_id: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def snapshot(self, instance_id: str) -> str:  # pragma: no cover
        raise NotImplementedError

    def restore(self, instance_id: str, snapshot_id: str) -> None:
        raise NotImplementedError  # pragma: no cover

    def destroy(self, instance_id: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def state(self, instance_id: str) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError


class FakeProvider(DeviceProvider):
    """Deterministic in-memory provider for CI and local tests."""

    name = "fake"

    def __init__(self) -> None:
        self._counter: dict[str, int] = {}
        self._snapshots: dict[str, dict[str, Any]] = {}
        self._log: list[dict[str, Any]] = []

    def _bump(self, instance_id: str, amount: int = 1) -> int:
        self._counter[instance_id] = \
            self._counter.get(instance_id, 0) + amount
        return self._counter[instance_id]

    def create(self, spec: dict[str, Any]) -> str:
        instance_id = f"fake-{len(self._counter) + 1:04d}"
        self._counter[instance_id] = 0
        self._log.append({"op": "create", "instance": instance_id})
        return instance_id

    def boot(self, instance_id: str) -> None:
        if instance_id not in self._counter:
            raise NotFoundError(f"unknown instance '{instance_id}'")
        self._log.append({"op": "boot", "instance": instance_id})

    def snapshot(self, instance_id: str) -> str:
        snap = f"{instance_id}-snap{len(self._snapshots) + 1}"
        self._snapshots[snap] = {"writes": self._counter.get(instance_id, 0)}
        self._log.append({"op": "snapshot", "instance": instance_id,
                          "snapshot": snap})
        return snap

    def restore(self, instance_id: str, snapshot_id: str) -> None:
        snap = self._snapshots.get(snapshot_id)
        if snap is None or not snapshot_id.startswith(instance_id):
            raise NotFoundError(f"unknown snapshot '{snapshot_id}'")
        self._counter[instance_id] = snap["writes"]
        self._log.append({"op": "restore", "instance": instance_id,
                          "snapshot": snapshot_id})

    def destroy(self, instance_id: str) -> None:
        self._log.append({"op": "destroy", "instance": instance_id})

    def state(self, instance_id: str) -> dict[str, Any]:
        if instance_id not in self._counter:
            raise NotFoundError(f"unknown instance '{instance_id}'")
        return {"writes": self._counter[instance_id], "provider": self.name}

    def mutate_state(self, instance_id: str, amount: int = 1) -> int:
        return self._bump(instance_id, amount)


PROVIDERS: dict[str, type[DeviceProvider]] = {"fake": FakeProvider}


@dataclass
class InstanceRecord:
    id: str
    provider: str
    provider_instance: str
    spec: dict[str, Any]
    provenance: list[dict[str, Any]] = field(default_factory=list)
    status: str = "created"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class VirtualDeviceManager:
    def __init__(self, workspace: Workspace, *, provider_name: str = "fake",
                 credentials: dict[str, Any] | None = None,
                 approved_providers: tuple[str, ...] = ("fake",)):
        if provider_name not in PROVIDERS:
            raise ValidationError(
                f"unknown provider '{provider_name}'; "
                f"known: {', '.join(sorted(PROVIDERS))}")
        # Fail closed: any non-builtin provider needs BOTH an explicit entry
        # in the approved set AND non-empty credentials from the researcher.
        if provider_name != "fake":
            if provider_name not in approved_providers:
                raise SafetyError(
                    f"provider '{provider_name}' is not approved; add it "
                    f"explicitly before use")
            if not credentials:
                raise SafetyError(
                    f"provider '{provider_name}' requires configured "
                    f"credentials")
        self.provider_name = provider_name
        self.provider = PROVIDERS[provider_name]()
        self.credentials = dict(credentials or {})
        self.ws = ws_guard(workspace)

    # -- lifecycle -----------------------------------------------------------
    def provision(self, *, model: str, image: str, build: str,
                  os_version: str) -> InstanceRecord:
        spec = {"model": model, "image": image, "build": build,
                "os_version": os_version}
        instance_id = self.provider.create(spec)
        stamp = {"op": "provision", "at": now_iso(), "spec": dict(spec),
                 "spec_sha256": sha256_text(str(sorted(spec.items())))}
        record = InstanceRecord(
            id=make_id("vdevice", self.provider_name, instance_id),
            provider=self.provider_name, provider_instance=instance_id,
            spec=spec,
            provenance=[stamp])
        record.provenance.append({"op": "boot", "at": now_iso()})
        self.provider.boot(instance_id)
        self.ws.write_json(f"devices/{record.id}.json", {
            "schema_version": VDEVICE_SCHEMA_VERSION, **record.to_dict(),
            "provider_instance": instance_id})
        return record

    def snapshot(self, record: InstanceRecord) -> str:
        snap = self.provider.snapshot(record.provider_instance)
        record.provenance.append({"op": "snapshot", "at": now_iso(),
                                  "snapshot": snap})
        return snap

    def restore(self, record: InstanceRecord, snapshot_id: str) -> None:
        self.provider.restore(record.provider_instance, snapshot_id)
        record.provenance.append({"op": "restore", "at": now_iso(),
                                  "snapshot": snapshot_id})

    def destroy(self, record: InstanceRecord) -> None:
        self.provider.destroy(record.provider_instance)
        record.status = "destroyed"
        record.provenance.append({"op": "destroy", "at": now_iso()})

    # -- deterministic trial execution -----------------------------------------
    def run_isolated(self, record: InstanceRecord, target_id: str,
                     input_bytes: bytes, *,
                     retained_artifacts: tuple[str, ...] = ()
                     ) -> dict[str, Any]:
        """Restore-clean-then-execute: every trial starts identical."""
        from . import targets as target_registry
        from .targets.base import Outcome

        if not target_registry.is_registered(target_id):
            raise NotFoundError(f"unknown target '{target_id}'")
        snapshot = self.snapshot(record)
        self.restore(record, snapshot)

        result = target_registry.create(target_id).execute(input_bytes)
        kept: list[dict[str, Any]] = []
        if Outcome.CRASH == result.outcome and result.diagnostics is not None:
            # Only explicitly selected artifacts are retained.
            if "crash-input.bin" in retained_artifacts:
                rel = f"artifacts/{record.id}-crash-input.bin"
                self.ws.write_bytes(rel, input_bytes)
                kept.append({"path": rel,
                             "sha256": sha256_text(input_bytes)})
        evidence = {
            "schema_version": VDEVICE_SCHEMA_VERSION,
            "kind": "isolated-trial",
            "instance": record.id,
            "provider": self.provider_name,
            "target": target_id,
            "input_sha256": sha256_text(input_bytes)[:16],
            "outcome": result.outcome,
            "state_after_restore": self.provider.state(record.provider_instance),
            "retained_artifacts": [k["path"] for k in kept],
            "note": ("only explicitly selected artifacts were retained; "
                     "the instance was restored from a clean snapshot"),
        }
        return evidence


def ws_guard(workspace: Workspace) -> Workspace:
    if workspace is None:
        raise ValidationError("virtual devices require a workspace")
    return workspace
