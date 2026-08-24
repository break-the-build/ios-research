"""Virtual-device backend: fake provider lifecycle, snapshots, isolation (#43)."""

from __future__ import annotations

import pytest

from ios_research.errors import NotFoundError, SafetyError, ValidationError
from ios_research.vdevices import (
    FakeProvider, VirtualDeviceManager, PROVIDERS)


def _manager(workspace, **kwargs):
    return VirtualDeviceManager(workspace, **kwargs)


def _provision(manager):
    return manager.provision(model="VirtualPhone", image="ios-17.4.img",
                             build="21X217", os_version="17.4")


def test_fail_closed_without_approval_or_credentials(workspace):
    # Register a real-but-external provider to exercise the approval gate.
    PROVIDERS["cloud-x-test"] = FakeProvider
    try:
        with pytest.raises(SafetyError, match="not approved"):
            _manager(workspace, provider_name="cloud-x-test",
                     approved_providers=("fake",))
        with pytest.raises(SafetyError, match="credentials"):
            _manager(workspace, provider_name="cloud-x-test",
                     approved_providers=("fake", "cloud-x-test"),
                     credentials=None)
        with pytest.raises(ValidationError):
            _manager(workspace, provider_name="warp-drive")
    finally:
        PROVIDERS.pop("cloud-x-test", None)
    assert "fake" in PROVIDERS


def test_fake_provider_full_lifecycle_with_provenance(workspace):
    manager = _manager(workspace)
    record = _provision(manager)
    assert record.provider == "fake"
    ops = [step["op"] for step in record.provenance]
    assert ops[:2] == ["provision", "boot"]
    snap = manager.snapshot(record)
    manager.restore(record, snap)
    manager.destroy(record)
    assert record.status == "destroyed"
    assert [s["op"] for s in record.provenance][-3:] == [
        "snapshot", "restore", "destroy"]
    # Provenance stamps carry build/image metadata.
    stamp = record.provenance[0]
    assert stamp["spec"]["build"] == "21X217"
    persisted = workspace.path(f"devices/{record.id}.json")
    assert persisted.is_file()


def test_restore_returns_known_state_between_trials(workspace):
    manager = _manager(workspace)
    provider = manager.provider          # the manager's own provider
    record = manager.provision(model="M", image="i", build="b",
                               os_version="1")
    raw = record.provider_instance
    snapshot = manager.snapshot(record)

    # Trial 1 mutates device state (writes), then the harness restores.
    provider.mutate_state(raw, 3)
    assert provider.state(raw)["writes"] == 3
    manager.restore(record, snapshot)
    assert provider.state(raw)["writes"] == 0   # clean again


def test_run_isolated_is_deterministic_across_trials(workspace):
    manager = _manager(workspace)
    record = _provision(manager)
    evidence_a = manager.run_isolated(record, "mock:parser", b"MOCK\x01\x01\x00\x02ok")
    evidence_b = manager.run_isolated(record, "mock:parser", b"MOCK\x01\x01\x00\x02ok")
    assert evidence_a["outcome"] == evidence_b["outcome"]
    assert evidence_a["state_after_restore"] == \
        {"writes": 0, "provider": "fake"}
    assert evidence_a["retained_artifacts"] == []   # nothing selected


def test_only_selected_artifacts_retained(workspace):
    manager = _manager(workspace)
    record = _provision(manager)
    crashing = b"MOCK\x01\xff\x00\x00"
    evidence = manager.run_isolated(
        record, "mock:parser", crashing,
        retained_artifacts=("crash-input.bin",))
    assert len(evidence["retained_artifacts"]) == 1
    stored = workspace.path(evidence["retained_artifacts"][0])
    assert stored.is_file()

    # Without explicit selection nothing is kept.
    record2 = _provision(manager)
    strict = manager.run_isolated(record2, "mock:parser", crashing)
    assert strict["retained_artifacts"] == []


def test_snapshot_from_other_instance_rejected(workspace):
    manager = _manager(workspace)
    one = _provision(manager)
    two = _provision(manager)
    snap = manager.snapshot(one)
    with pytest.raises(NotFoundError):
        manager.restore(two, snap)


def test_unknown_target_in_isolated_run(workspace):
    manager = _manager(workspace)
    record = _provision(manager)
    with pytest.raises(NotFoundError):
        manager.run_isolated(record, "ghost:target", b"x")
