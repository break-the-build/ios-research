"""Attack-surface inventory and bounty-EV campaign prioritization (#61).

Reward expected value varies by orders of magnitude across Apple's bounty
entry points (network->kernel $2M vs. browser content $10K). This module turns
a researcher-supplied **system snapshot** — a read-only inventory of local
attack surfaces gathered with public information on an authorized machine —
into a deterministic, ranked campaign plan so limited fuzzing budget flows to
the highest-value categories first.

Design constraints:

* **Snapshot-driven** — the framework classifies and ranks what the researcher
  collected; it performs no probing of other systems, no privilege
  escalation, and no bypass tooling.
* **Deterministic** — identical snapshot + weights + config hash produce an
  identical ranking (stable tie-breaks by surface id).
* **Honest** — surfaces that cannot be classified to a reward tier are marked
  ``unknown`` instead of guessed; every ranking records its inputs.

Ranking model (all factors are data, never code paths):

    ev_score = reward_tier * reachability * novelty_yield * feasibility * saturation

where ``reward_tier`` is derived from the Target Flag taxonomy (#58) by
matching a surface's entry points and endpoint hint, ``novelty_yield``
defaults to the novel ratio of the latest advisory scan (#59), and
``saturation`` down-ranks surfaces already covered by a previous plan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .clock import now_iso
from .errors import ValidationError
from .hashing import config_hash
from .ids import make_id
from .targetflags import load_taxonomy
from .workspace import Workspace

SURFACE_SCHEMA_VERSION = 1

# Bounty entry points a surface may expose (aligned with Apple's public
# category taxonomy; 'unknown' keeps unclassifiable surfaces honest).
ENTRY_POINTS = (
    "network", "network-user-interaction", "wireless-proximity",
    "physical-access", "app-sandbox", "browser", "pcc-network",
    "macos-gatekeeper", "macos-tcc",
)
SURFACE_KINDS = (
    "iokit-user-client", "mach-service", "xpc-service", "launchd-daemon",
    "framework-parser", "other",
)

# Target-kind registration (#115): maps each fuzzing-target family onto the
# inventory vocabulary so new families enter the EV prioritizer with a
# defensible surface kind and entry-point classification. Legacy families
# (mock/mac/ios-device) predate the inventory and are intentionally absent.
KIND_SURFACE_MAP = {
    "audio": {"surface_kind": "framework-parser",
              "entry_points": ["network-user-interaction"]},
    "bluetooth": {"surface_kind": "framework-parser",
                  "entry_points": ["wireless-proximity"]},
    "wifi": {"surface_kind": "framework-parser",
             "entry_points": ["wireless-proximity"]},
    "nfc": {"surface_kind": "framework-parser",
            "entry_points": ["wireless-proximity"]},
    "netip": {"surface_kind": "framework-parser", "entry_points": ["network"]},
    "wifiaware": {"surface_kind": "framework-parser",
                  "entry_points": ["wireless-proximity"]},
    "pq3": {"surface_kind": "framework-parser", "entry_points": ["network"]},
    "continuity": {"surface_kind": "framework-parser",
                   "entry_points": ["wireless-proximity"]},
    "ipc": {"surface_kind": "xpc-service", "entry_points": ["app-sandbox"]},
    "xpc": {"surface_kind": "xpc-service", "entry_points": ["app-sandbox"]},
    "docimp": {"surface_kind": "framework-parser",
               "entry_points": ["network-user-interaction"]},
    "signeddoc": {"surface_kind": "framework-parser",
                  "entry_points": ["network-user-interaction"]},
    "proxapp": {"surface_kind": "framework-parser",
                "entry_points": ["wireless-proximity"]},
    "fsclient": {"surface_kind": "framework-parser",
                 "entry_points": ["physical-access"]},
    "geo": {"surface_kind": "framework-parser",
            "entry_points": ["network-user-interaction"]},
    "voiceassist": {"surface_kind": "framework-parser",
                    "entry_points": ["physical-access"]},
    # Families from parallel workstreams, registered for completeness.
    "messaging": {"surface_kind": "framework-parser",
                  "entry_points": ["network"]},
    "lockeddevice": {"surface_kind": "framework-parser",
                     "entry_points": ["physical-access"]},
    "mach": {"surface_kind": "mach-service",
             "entry_points": ["network"]},
}


def surface_registration_for(kind: str) -> dict[str, Any] | None:
    """Return the inventory registration for a target kind, or ``None``."""
    reg = KIND_SURFACE_MAP.get(kind)
    return dict(reg) if reg else None

# Endpoint classes mapped from taxonomy outcomes for tier matching.
_KERNEL_OUTCOMES = {"kernel-control"}
_CORRUPTION_OUTCOMES = {
    "userspace-code-execution", "app-processor-control",
    "webcontent-sandbox-escape", "web-content-code-execution",
    "pcc-code-execution",
}
_DATA_OUTCOMES = {"sensitive-data-access", "gatekeeper-bypass", "tcc-capture"}

REQUIRED_SURFACE_FIELDS = ("id", "kind")


@dataclass
class Surface:
    """One inventoried attack surface from a system snapshot."""

    id: str
    kind: str
    name: str = ""
    entry_points: list[str] = field(default_factory=list)
    endpoint_hint: str = ""          # kernel | userspace | unknown
    reachability: float = 0.5        # 0..1 researcher estimate
    feasibility: float = 0.5         # 0..1 harness feasibility estimate
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_snapshot(data: Any) -> dict[str, Any]:
    """Validate a snapshot document into a normalized inventory."""
    if not isinstance(data, dict) or not isinstance(data.get("surfaces"),
                                                    list):
        raise ValidationError(
            "snapshot must be an object with a 'surfaces' array")
    if not data["surfaces"]:
        raise ValidationError("snapshot requires at least one surface")
    system = data.get("system")
    if not isinstance(system, dict) or not str(system.get("device_id", "")).strip():
        raise ValidationError("snapshot requires system.device_id provenance")

    surfaces: list[Surface] = []
    seen: set[str] = set()
    for index, item in enumerate(data["surfaces"]):
        if not isinstance(item, dict):
            raise ValidationError(f"surface {index} must be an object")
        missing = [f for f in REQUIRED_SURFACE_FIELDS
                   if not str(item.get(f, "")).strip()]
        if missing:
            raise ValidationError(
                f"surface {index} missing fields: {', '.join(missing)}")
        sid = str(item["id"])
        if sid in seen:
            raise ValidationError(f"duplicate surface id: {sid}")
        seen.add(sid)
        kind = str(item["kind"])
        if kind not in SURFACE_KINDS:
            raise ValidationError(
                f"surface '{sid}' has unknown kind '{kind}'; "
                f"known: {', '.join(SURFACE_KINDS)}")
        entry_points = [str(e) for e in item.get("entry_points", [])]
        bad = [e for e in entry_points if e not in ENTRY_POINTS]
        if bad:
            raise ValidationError(
                f"surface '{sid}' has unknown entry points: {', '.join(bad)}")
        endpoint_hint = str(item.get("endpoint_hint", "unknown"))
        if endpoint_hint not in ("kernel", "userspace", "unknown"):
            raise ValidationError(
                f"surface '{sid}' endpoint_hint must be kernel|userspace|unknown")

        def _ratio(key: str) -> float:
            value = item.get(key, 0.5)
            if not isinstance(value, (int, float)) or not 0.0 <= value <= 1.0:
                raise ValidationError(
                    f"surface '{sid}' {key} must be a number in [0, 1]")
            return float(value)

        surfaces.append(Surface(
            id=sid, kind=kind, name=str(item.get("name", "")),
            entry_points=entry_points, endpoint_hint=endpoint_hint,
            reachability=_ratio("reachability") if "reachability" in item else 0.5,
            feasibility=_ratio("feasibility") if "feasibility" in item else 0.5,
            notes=str(item.get("notes", "")),
        ))
    return {"system": system, "surfaces": [s.to_dict() for s in surfaces]}


def _reward_tier(surface: dict[str, Any], taxonomy: dict[str, Any]) -> int | None:
    """Best matching reward hint from the flag taxonomy, or None.

    Classification requires an explicit endpoint hint and at least one entry
    point; anything less stays ``None`` rather than being guessed.
    """
    entry_points = surface.get("entry_points") or []
    hint = surface.get("endpoint_hint")
    if not entry_points or hint == "unknown":
        return None
    wants_kernel = hint == "kernel"
    allowed_outcomes = (_KERNEL_OUTCOMES if wants_kernel
                        else _CORRUPTION_OUTCOMES | _DATA_OUTCOMES)
    hints: list[int] = []
    for flag in taxonomy["flags"]:
        if flag["entry_point"] not in entry_points:
            continue
        if flag["outcome"] in allowed_outcomes:
            hints.append(int(flag.get("reward_hint", 0)))
    return max(hints) if hints else None


class SurfaceEngine:
    """Ingests snapshots and produces ranked campaign plans."""

    def __init__(self, workspace: Workspace):
        self.ws = workspace

    # persistence ----------------------------------------------------------
    def _rel(self, plan_id: str) -> str:
        return f"analysis/{plan_id}.json"

    def get(self, plan_id: str) -> dict[str, Any]:
        record = self.ws.read_json(self._rel(plan_id))
        if record.get("kind") != "surface-plan":
            raise ValidationError(f"'{plan_id}' is not a surface plan")
        return record

    def list(self) -> list[dict[str, Any]]:
        out = []
        for record in self.ws.list_json("analysis"):
            if record.get("kind") == "surface-plan":
                out.append(record)
        return out

    # ingest ---------------------------------------------------------------
    def ingest(self, path: str) -> dict[str, Any]:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValidationError(f"cannot read snapshot: {exc}") from exc
        inventory = parse_snapshot(data)
        inventory_id = make_id("surfaceinv", inventory["system"]["device_id"],
                               *[s["id"] for s in inventory["surfaces"]])
        record = {"id": inventory_id, "kind": "surface-inventory",
                  "created_at": now_iso(),
                  "schema_version": SURFACE_SCHEMA_VERSION, **inventory}
        self.ws.write_json(f"analysis/{inventory_id}.json", record)
        return record

    # planning ---------------------------------------------------------------
    @staticmethod
    def _latest_novelty_yield(workspace: Workspace) -> float:
        """Novel ratio from the most recent advisory scan artifact, if any."""
        scans = [r for r in workspace.list_json("analysis")
                 if r.get("kind") == "novelty-scan"]
        if not scans:
            return 0.5  # neutral prior when no scan exists
        latest = max(scans, key=lambda r: r["created_at"])
        counts = latest.get("counts", {})
        total = sum(counts.values())
        if not total:
            return 0.5
        return counts.get("novel", 0) / total

    def plan(self, *, inventory_id: str, previous_plan_id: str | None = None,
             novelty_yield: float | None = None,
             saturation_penalty: float = 0.5) -> dict[str, Any]:
        inventory = self.ws.read_json(f"analysis/{inventory_id}.json")
        if inventory.get("kind") != "surface-inventory":
            raise ValidationError(
                f"'{inventory_id}' is not a surface inventory")

        if novelty_yield is None:
            novelty_yield = self._latest_novelty_yield(self.ws)
            yield_source = ("advisory-scan" if scans_exist(self.ws)
                            else "neutral-prior")
        else:
            yield_source = "explicit"
        if not 0.0 <= novelty_yield <= 1.0:
            raise ValidationError("novelty_yield must be in [0, 1]")

        taxonomy = load_taxonomy(self.ws)
        saturated: set[str] = set()
        if previous_plan_id:
            previous = self.get(previous_plan_id)
            saturated = {row["surface_id"]
                         for row in previous.get("ranked_surfaces", [])}

        rows: list[dict[str, Any]] = []
        unknown_tier = 0
        for surface in inventory["surfaces"]:
            tier = _reward_tier(surface, taxonomy)
            if tier is None:
                unknown_tier += 1
                tier_value, tier_classified = 0.0, False
            else:
                tier_value, tier_classified = float(tier), True
            factor_saturation = saturation_penalty \
                if surface["id"] in saturated else 1.0
            score = (tier_value * surface["reachability"]
                     * novelty_yield * surface["feasibility"]
                     * factor_saturation)
            rows.append({
                "surface_id": surface["id"],
                "kind": surface["kind"],
                "entry_points": surface["entry_points"],
                "endpoint_hint": surface["endpoint_hint"],
                "reward_tier": tier,
                "tier_classified": tier_classified,
                "reachability": surface["reachability"],
                "feasibility": surface["feasibility"],
                "saturated": surface["id"] in saturated,
                "ev_score": round(score, 6),
            })
        # Stable ordering: score desc, then surface id asc.
        rows.sort(key=lambda r: (-r["ev_score"], r["surface_id"]))

        weights_hash = config_hash({
            "inventory_id": inventory_id,
            "novelty_yield": round(novelty_yield, 6),
            "saturation_penalty": saturation_penalty,
            "previous_plan_id": previous_plan_id,
            "taxonomy_sha256": taxonomy["sha256"],
        })
        plan_id = make_id("surfaceplan", weights_hash)
        result = {
            "id": plan_id,
            "kind": "surface-plan",
            "created_at": now_iso(),
            "schema_version": SURFACE_SCHEMA_VERSION,
            "weights_hash": weights_hash,
            "inventory_id": inventory_id,
            "previous_plan_id": previous_plan_id,
            "inputs": {
                "novelty_yield_source": yield_source,
                "novelty_yield": round(novelty_yield, 6),
                "saturation_penalty": saturation_penalty,
                "taxonomy_sha256": taxonomy["sha256"],
            },
            "ranked_surfaces": rows,
            "summary": {
                "surfaces": len(rows),
                "unclassified": unknown_tier,
                "top_surface": rows[0]["surface_id"] if rows else None,
            },
            "note": ("rankings are research-planning guidance only; they do "
                     "not assert exploitability, eligibility, or reward"),
        }
        self.ws.write_json(self._rel(plan_id), result)
        return result


def scans_exist(workspace: Workspace) -> bool:
    return any(r.get("kind") == "novelty-scan"
               for r in workspace.list_json("analysis"))
