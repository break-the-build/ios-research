"""Host-side harness profiles for wireless-proximity parser surfaces (#63).

Apple's wireless-proximity category ($1M) begins with data reaching an
Apple-designed radio. Full radio research needs specialized hardware and is
out of scope; the achievable subset today is **host-side**: exercising the
application-processor parse paths that consume proximity-adjacent metadata
(BLE advertising/L2CAP/GATT structures, Wi-Fi management frames, NFC/ NDEF
records) through registered harness targets.

This module is a **catalog + gating layer**, not a radio tool:

* profiles map proximity categories to registered harness target ids,
* every profile is **opt-in** — listing shows profiles as disabled until
  explicitly enabled for an invocation (``--enable``) or via workspace config
  (``proximity.enabled_profiles``),
* a bounded smoke run proves each mapped target executes its seeds safely
  in-process (no RF transmission, no injection, no pairing, no baseband).

Explicitly out of scope (safety boundary): RF transmission, over-the-air
injection, pairing or pushing to other devices, and baseband/firmware
research tooling. Host parse-path fuzzing of researcher-owned machines only.
"""

from __future__ import annotations

from typing import Any

from . import targets
from .clock import now_iso
from .errors import ValidationError
from .hashing import sha256_text
from .ids import make_id
from .targets.base import Outcome
from .workspace import Workspace

PROXIMITY_SCHEMA_VERSION = 1
MAX_SMOKE_CASES_PER_SURFACE = 50

# Application-processor parse surfaces adjacent to wireless proximity.
# Every mapped target must be a registered harness target; mock-backed
# profiles are CI-safe by construction, real-harness variants stay opt-in
# behind their own build requirements.
PROXIMITY_PROFILES: dict[str, dict[str, Any]] = {
    "ble-advertising-metadata": {
        "label": "BLE advertising metadata parsing",
        "radio_family": "bluetooth",
        "surfaces": ["bluetooth:btle-adv"],
        "scope": "host-side application-processor parse path only",
    },
    "ble-l2cap-signaling": {
        "label": "BLE L2CAP signaling frame parsing",
        "radio_family": "bluetooth",
        "surfaces": ["bluetooth:l2cap"],
        "scope": "host-side application-processor parse path only",
    },
    "ble-gatt-attributes": {
        "label": "GATT attribute-protocol parsing",
        "radio_family": "bluetooth",
        "surfaces": ["bluetooth:gatt"],
        "scope": "host-side application-processor parse path only",
    },
    "wifi-management-metadata": {
        "label": "Wi-Fi management frame metadata parsing",
        "radio_family": "wifi",
        "surfaces": ["wifi:beacon", "wifi:probe-resp", "wifi:action"],
        "scope": "host-side application-processor parse path only",
    },
    "nfc-ndef-metadata": {
        "label": "NFC/NDEF record parsing",
        "radio_family": "nfc",
        "surfaces": ["nfc:ndef", "nfc:isodep", "nfc:tagcmd"],
        "scope": "host-side application-processor parse path only",
    },
}

OUT_OF_SCOPE = (
    "no RF transmission, no over-the-air injection, no pairing or pushing "
    "to other devices, no baseband/firmware research tooling; host "
    "application-processor parse paths on researcher-owned machines only",
)


def catalog(enabled: set[str] | None = None,
            registered: callable = None) -> list[dict[str, Any]]:
    """Deterministic catalog view; ``enabled``/registration state per profile."""
    enabled = enabled or set()
    registered = registered or targets.is_registered
    out = []
    for profile_id in sorted(PROXIMITY_PROFILES):
        spec = PROXIMITY_PROFILES[profile_id]
        missing = [s for s in spec["surfaces"] if not registered(s)]
        out.append({
            "id": profile_id,
            "label": spec["label"],
            "radio_family": spec["radio_family"],
            "surfaces": list(spec["surfaces"]),
            "missing_surfaces": missing,
            "runnable": not missing,
            "enabled": profile_id in enabled,
            "scope": spec["scope"],
        })
    return out


def resolve(profile_id: str, *, enabled: set[str] | None = None,
            registered: callable = None) -> dict[str, Any]:
    """Resolve one profile, enforcing opt-in and registration gating."""
    if profile_id not in PROXIMITY_PROFILES:
        raise ValidationError(
            f"unknown proximity profile '{profile_id}'; known: "
            f"{', '.join(sorted(PROXIMITY_PROFILES))}")
    enabled = enabled or set()
    registered = registered or targets.is_registered
    spec = PROXIMITY_PROFILES[profile_id]
    if profile_id not in enabled:
        raise ValidationError(
            f"profile '{profile_id}' is not enabled; proximity profiles are "
            f"opt-in per invocation (--enable) or via workspace config "
            f"(proximity.enabled_profiles)")
    missing = [s for s in spec["surfaces"] if not registered(s)]
    if missing:
        raise ValidationError(
            f"profile '{profile_id}' has unbuilt/unregistered surfaces: "
            f"{', '.join(missing)}")
    return spec


def enabled_from_config(config) -> set[str]:
    """Read opt-in profile ids from layered workspace config (if any)."""
    value = config.get("proximity.enabled_profiles") if config else None
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return set()
    return {str(item) for item in value if str(item) in PROXIMITY_PROFILES}


class ProximityEngine:
    """Runs bounded smoke executions over a profile's harness surfaces."""

    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def smoke(self, *, profile_id: str, enabled: set[str] | None = None,
              max_cases: int = MAX_SMOKE_CASES_PER_SURFACE) -> dict[str, Any]:
        spec = resolve(profile_id, enabled=enabled)
        max_cases = max(1, min(int(max_cases),
                               MAX_SMOKE_CASES_PER_SURFACE))
        surfaces = []
        totals = {"executed": 0, "accepted": 0, "rejected": 0,
                  "crash": 0, "abnormal": 0, "timeout": 0}
        for target_id in spec["surfaces"]:
            target = targets.create(target_id)
            seeds = target.seeds()
            outcomes: dict[str, int] = {}
            executed = 0
            for index in range(min(max_cases, max(1, len(seeds)))):
                data = seeds[index % len(seeds)] if seeds else b"\x00"
                result = target.execute(data)
                outcomes[result.outcome] = \
                    outcomes.get(result.outcome, 0) + 1
                executed += 1
            totals["executed"] += executed
            for key in ("accepted", "rejected", "crash", "abnormal",
                        "timeout"):
                totals[key] += outcomes.get(key, 0)
            surfaces.append({
                "target": target_id,
                "seeds": len(seeds),
                "executed": executed,
                "outcomes": outcomes,
            })
        smoke_id = make_id("proxdmoke", profile_id,
                           sha256_text(str(sorted(totals.items()))),
                           now_iso())
        record = {
            "id": smoke_id,
            "kind": "proximity-smoke",
            "created_at": now_iso(),
            "schema_version": PROXIMITY_SCHEMA_VERSION,
            "profile": profile_id,
            "max_cases_per_surface": max_cases,
            "surfaces": surfaces,
            "totals": totals,
            "out_of_scope": list(OUT_OF_SCOPE),
            "note": ("smoke runs prove host-side harness executability only; "
                     "they are not coverage, exploitability, or eligibility "
                     "evidence"),
        }
        self.ws.write_json(f"analysis/{smoke_id}.json", record)
        return record
