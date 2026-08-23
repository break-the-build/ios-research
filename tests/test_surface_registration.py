"""Coverage tests (#115): every target family registers into the inventory."""

from __future__ import annotations

from ios_research.surface import (
    ENTRY_POINTS,
    KIND_SURFACE_MAP,
    SURFACE_KINDS,
)
from ios_research.targets import list_targets

# Families that predate the surface inventory and stay unregistered.
_LEGACY_KINDS = {"mock", "mac", "ios-device", "abstract"}


def _registered_kinds() -> set[str]:
    return {t["id"].split(":", 1)[0] for t in list_targets()}


def test_every_registered_kind_maps_into_inventory_vocabulary():
    for kind in _registered_kinds() - _LEGACY_KINDS:
        reg = KIND_SURFACE_MAP.get(kind)
        assert reg, f"target kind '{kind}' is missing from KIND_SURFACE_MAP"
        assert reg["surface_kind"] in SURFACE_KINDS, kind
        assert set(reg["entry_points"]) <= set(ENTRY_POINTS), kind


def test_surface_registration_accessor_round_trips():
    from ios_research.surface import surface_registration_for
    reg = surface_registration_for("netip")
    assert reg == {"surface_kind": "framework-parser",
                   "entry_points": ["network"]}
    assert surface_registration_for("no-such-family") is None


def test_every_mock_target_declares_a_safety_note():
    for t in list_targets():
        if not t.get("mock"):
            continue
        text = f"{t.get('note', '')} {t.get('description', '')}".lower()
        assert "mock" in text or "no " in text, \
            f"{t['id']} lacks a safety/no-access declaration"


def test_new_families_have_taxonomy_keyword_coverage():
    """Zero-click/proximity/physical families must propose candidates."""
    from ios_research.targetflags import DEFAULT_TAXONOMY
    keywords = [k for flag in DEFAULT_TAXONOMY for k in flag["keywords"]]
    for prefix in ("netip:", "wifiaware:", "continuity:", "proxapp:",
                   "xpc:", "ipc:", "fsclient:", "voiceassist:"):
        assert any(prefix in kw or kw in prefix for kw in keywords), prefix
