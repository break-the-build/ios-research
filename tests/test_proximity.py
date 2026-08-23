"""Host-side proximity parser harness profile tests (#63)."""

from __future__ import annotations

import pytest

from ios_research.errors import ValidationError
from ios_research.proximity import (
    PROXIMITY_PROFILES, ProximityEngine, catalog, enabled_from_config,
    resolve,
)


def test_catalog_lists_all_profiles_deterministically():
    first = catalog()
    second = catalog()
    assert first == second
    ids = [p["id"] for p in first]
    assert ids == sorted(PROXIMITY_PROFILES)
    assert all(p["runnable"] for p in first)      # mock-backed, registered
    assert all(not p["enabled"] for p in first)   # opt-in by default


def test_catalog_reports_missing_surfaces():
    entries = catalog(registered=lambda tid: tid != "bluetooth:gatt")
    ble_gatt = next(p for p in entries if p["id"] == "ble-gatt-attributes")
    assert ble_gatt["runnable"] is False
    assert ble_gatt["missing_surfaces"] == ["bluetooth:gatt"]


def test_resolve_enforces_opt_in_gating():
    with pytest.raises(ValidationError, match="opt-in"):
        resolve("ble-advertising-metadata", enabled=set())
    spec = resolve("ble-advertising-metadata",
                   enabled={"ble-advertising-metadata"})
    assert spec["surfaces"] == ["bluetooth:btle-adv"]


def test_resolve_rejects_unknown_and_unregistered():
    with pytest.raises(ValidationError, match="unknown proximity profile"):
        resolve("radio-teleport", enabled={"radio-teleport"})
    with pytest.raises(ValidationError, match="unregistered"):
        resolve("ble-gatt-attributes", enabled={"ble-gatt-attributes"},
                registered=lambda tid: False)


def test_enabled_from_config_reads_layered_config(workspace):
    workspace.path("config/config.json").parent.mkdir(parents=True,
                                                      exist_ok=True)
    workspace.write_json("config/config.json", {
        "proximity": {"enabled_profiles": ["ble-advertising-metadata",
                                           "not-a-profile"]}})
    from ios_research.config import Config
    config = Config(workspace.read_json("config/config.json"))
    assert enabled_from_config(config) == {"ble-advertising-metadata"}


def test_config_get_supports_dotted_keys(workspace):
    workspace.write_json("config/config.json", {
        "proximity": {"enabled_profiles": ["nfc-ndef-metadata"]}})
    from ios_research.config import Config
    config = Config(workspace.read_json("config/config.json"))
    assert enabled_from_config(config) == {"nfc-ndef-metadata"}


def test_smoke_executes_all_surfaces_and_persists(workspace):
    engine = ProximityEngine(workspace)
    record = engine.smoke(profile_id="wifi-management-metadata",
                          enabled={"wifi-management-metadata"},
                          max_cases=5)
    assert record["kind"] == "proximity-smoke"
    assert len(record["surfaces"]) == 3
    assert all(s["executed"] > 0 for s in record["surfaces"])
    assert record["totals"]["executed"] == \
        sum(s["executed"] for s in record["surfaces"])
    assert workspace.path(f"analysis/{record['id']}.json").is_file()
    assert record["out_of_scope"]


def test_smoke_requires_enablement(workspace):
    with pytest.raises(ValidationError, match="opt-in"):
        ProximityEngine(workspace).smoke(profile_id="nfc-ndef-metadata")


def test_smoke_is_bounded(workspace):
    engine = ProximityEngine(workspace)
    record = engine.smoke(profile_id="ble-advertising-metadata",
                          enabled={"ble-advertising-metadata"},
                          max_cases=1000)
    assert record["totals"]["executed"] <= 50


# --- CLI ----------------------------------------------------------------------

def test_proximity_cli_roundtrip(workspace):
    from ios_research.cli import main
    ws = ["--workspace", str(workspace.root)]
    assert main([*ws, "proximity", "list", "--json"]) == 0
    # Disabled profile is refused (VALIDATION = exit 4).
    code = main([*ws, "proximity", "smoke", "ble-advertising-metadata",
                 "--json"])
    assert code == 4
    # Explicit opt-in runs clean.
    code = main([*ws, "proximity", "smoke", "ble-advertising-metadata",
                 "--enable", "--json"])
    assert code == 0
