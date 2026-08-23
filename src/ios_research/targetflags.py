"""Apple Target Flag taxonomy mapping and flag-aware evidence checklists (#58).

Apple confirms exploitability objectively with *Target Flags* and pays the
stated reward when a required flag is demonstrated. This module encodes the
public taxonomy as local, versioned data and derives *candidate* flags from
stored analysis evidence.

Candidate flags are hypotheses for researcher confirmation. The framework
never asserts that a flag is achieved, never assigns eligibility or reward
amounts, and never interacts with Apple systems, Target Flag infrastructure,
or privileged device capabilities.
"""

from __future__ import annotations

import json
from typing import Any

from .errors import ValidationError
from .hashing import canonical_json, sha256_text

TAXONOMY_VERSION = 1
OVERRIDE_RELPATH = "config/target-flags.json"

# Analysis indicator levels that can support a memory-corruption outcome.
_CORRUPTION_INDICATORS = {
    "CONTROLLED_MEMORY_ACCESS_INDICATOR",
    "CODE_EXECUTION_INDICATOR",
}

# Evidence elements a researcher must retain to substantiate a flag claim.
# Each maps onto a concrete readiness check in ``bounty.BountyReadiness``.
_EVIDENCE = (
    "reproducible_crash",      # successful reproduction result recorded
    "minimized_input",         # minimized triggering input retained
    "build_provenance",        # non-placeholder affected component/version
    "matrix_confirmation",     # device/OS/build matrix run attached (#37)
    "primitive_indicator",     # analysis indicator supports the outcome class
    "demonstration_refs",      # researcher-supplied demonstration references
)

DEFAULT_TAXONOMY: list[dict[str, Any]] = [
    {"id": "network-zero-click-kernel", "label": "Kernel control via network attack without user interaction",
     "entry_point": "network", "outcome": "kernel-control", "reward_hint": 2000000,
     "keywords": ["kernel", "iokit", "xnu"], "indicators": _CORRUPTION_INDICATORS,
     "evidence_required": ["reproducible_crash", "minimized_input", "build_provenance",
                           "matrix_confirmation", "primitive_indicator"]},
    {"id": "network-zero-click-userspace", "label": "User-space control via network attack without user interaction",
     "entry_point": "network", "outcome": "userspace-code-execution", "reward_hint": 350000,
     "keywords": ["daemon", "mdns", "network"], "indicators": _CORRUPTION_INDICATORS,
     "evidence_required": ["reproducible_crash", "minimized_input", "build_provenance",
                           "primitive_indicator"]},
    {"id": "network-one-click-kernel", "label": "Kernel control via network attack after user interaction",
     "entry_point": "network-user-interaction", "outcome": "kernel-control", "reward_hint": 1000000,
     "keywords": ["kernel", "iokit", "xnu"], "indicators": _CORRUPTION_INDICATORS,
     "evidence_required": ["reproducible_crash", "minimized_input", "build_provenance",
                           "matrix_confirmation", "primitive_indicator"]},
    {"id": "proximity-radio-app-processor", "label": "Application-processor control via wireless proximity attack",
     "entry_point": "wireless-proximity", "outcome": "app-processor-control", "reward_hint": 1000000,
     "keywords": ["bluetooth", "wifi", "wlan", "awdl", "airdrop", "proximity"],
     "indicators": _CORRUPTION_INDICATORS,
     "evidence_required": ["reproducible_crash", "minimized_input", "build_provenance",
                           "matrix_confirmation", "primitive_indicator"]},
    {"id": "physical-access-sensitive-data", "label": "Sensitive user data access from a locked device",
     "entry_point": "physical-access", "outcome": "sensitive-data-access", "reward_hint": 500000,
     "keywords": ["lockscreen", "keychain", "data-protection"],
     "indicators": set(), "evidence_required":
         ["reproducible_crash", "minimized_input", "build_provenance", "demonstration_refs"]},
    {"id": "app-sandbox-escape-kernel", "label": "Kernel control from a sandboxed app",
     "entry_point": "app-sandbox", "outcome": "kernel-control", "reward_hint": 500000,
     "keywords": ["iokit", "kernel", "sandbox"],
     "indicators": _CORRUPTION_INDICATORS,
     "evidence_required": ["reproducible_crash", "minimized_input", "build_provenance",
                           "matrix_confirmation", "primitive_indicator"]},
    {"id": "app-sandbox-escape-sensitive-data", "label": "Sensitive user data access from a sandboxed app",
     "entry_point": "app-sandbox", "outcome": "sensitive-data-access", "reward_hint": 100000,
     "keywords": ["sandbox", "container", "tcc"],
     "indicators": set(), "evidence_required":
         ["reproducible_crash", "minimized_input", "build_provenance", "demonstration_refs"]},
    {"id": "browser-kernel-control", "label": "Kernel control via Safari webpage navigation",
     "entry_point": "browser", "outcome": "kernel-control", "reward_hint": 1000000,
     "keywords": ["webkit", "javascriptcore", "safari"],
     "indicators": _CORRUPTION_INDICATORS,
     "evidence_required": ["reproducible_crash", "minimized_input", "build_provenance",
                           "matrix_confirmation", "primitive_indicator"]},
    {"id": "webcontent-sandbox-escape", "label": "WebContent sandbox escape via Safari webpage navigation",
     "entry_point": "browser", "outcome": "webcontent-sandbox-escape", "reward_hint": 300000,
     "keywords": ["webkit", "webcontent", "webprocess"],
     "indicators": _CORRUPTION_INDICATORS,
     "evidence_required": ["reproducible_crash", "minimized_input", "build_provenance",
                           "primitive_indicator"]},
    {"id": "web-content-code-execution", "label": "Code execution within the WebContent process",
     "entry_point": "browser", "outcome": "web-content-code-execution", "reward_hint": 10000,
     "keywords": ["javascriptcore", "webcontent", "webkit"],
     "indicators": _CORRUPTION_INDICATORS,
     "evidence_required": ["reproducible_crash", "minimized_input", "build_provenance"]},
    {"id": "macos-gatekeeper-bypass", "label": "Gatekeeper quarantined-file check bypass (macOS)",
     "entry_point": "macos-gatekeeper", "outcome": "gatekeeper-bypass", "reward_hint": 100000,
     "keywords": ["gatekeeper", "quarantine", "launchservices"],
     "indicators": set(),
     "evidence_required": ["demonstration_refs", "build_provenance"]},
    {"id": "macos-tcc-capture", "label": "TCC Target Flag capture (macOS)",
     "entry_point": "macos-tcc", "outcome": "tcc-capture", "reward_hint": 10000,
     "keywords": ["tcc", "privacy", "photos", "contacts"],
     "indicators": set(),
     "evidence_required": ["reproducible_crash", "build_provenance", "demonstration_refs"]},
    {"id": "macos-sandbox-escape", "label": "App Sandbox escape demonstrated on macOS only",
     "entry_point": "app-sandbox", "outcome": "sandbox-escape-macos", "reward_hint": 5000,
     "keywords": ["sandbox", "appsandbox"],
     "indicators": _CORRUPTION_INDICATORS,
     "evidence_required": ["reproducible_crash", "minimized_input", "build_provenance"]},
    {"id": "pcc-request-code-execution", "label": "Unsigned code execution within the Apple PCC software image",
     "entry_point": "pcc-network", "outcome": "pcc-code-execution", "reward_hint": 1000000,
     "keywords": ["pcc", "private-cloud-compute"],
     "indicators": _CORRUPTION_INDICATORS,
     "evidence_required": ["reproducible_crash", "minimized_input", "build_provenance",
                           "matrix_confirmation", "primitive_indicator"]},
]


def load_taxonomy(workspace=None) -> dict[str, Any]:
    """Load the effective taxonomy: workspace override or built-in default.

    The override file is optional, researcher-authored JSON of the shape
    ``{"version": int, "flags": [ ... ]}``. It lets deployments track Apple's
    published taxonomy without code changes; its content hash pins whichever
    taxonomy was in force for an experiment or evidence pack.
    """
    source = "builtin"
    flags = DEFAULT_TAXONOMY
    version = TAXONOMY_VERSION
    if workspace is not None and workspace.path(OVERRIDE_RELPATH).exists():
        try:
            data = json.loads(workspace.path(OVERRIDE_RELPATH).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValidationError(f"invalid target-flag override: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("flags"), list):
            raise ValidationError("target-flag override must contain a 'flags' array")
        if not isinstance(data.get("version"), int):
            raise ValidationError("target-flag override must declare an integer 'version'")
        flags, version, source = data["flags"], data["version"], "workspace-override"

    validated = []
    seen: set[str] = set()
    for index, flag in enumerate(flags):
        if not isinstance(flag, dict):
            raise ValidationError(f"target flag {index} must be an object")
        missing = [k for k in ("id", "label", "entry_point", "outcome",
                               "evidence_required") if not flag.get(k)]
        if missing:
            raise ValidationError(
                f"target flag {index} missing fields: {', '.join(missing)}")
        unknown = [e for e in flag["evidence_required"] if e not in _EVIDENCE]
        if unknown:
            raise ValidationError(
                f"target flag '{flag['id']}' has unknown evidence elements: "
                f"{', '.join(sorted(unknown))}")
        if flag["id"] in seen:
            raise ValidationError(f"duplicate target flag id: {flag['id']}")
        seen.add(flag["id"])
        entry = dict(flag)
        entry.setdefault("keywords", [])
        entry.setdefault("indicators", [])
        entry["indicators"] = sorted(set(entry["indicators"]))
        validated.append(entry)

    body = {"version": version, "flags": [
        {k: f[k] for k in sorted(f)} for f in validated]}
    return {"taxonomy_version": version, "source": source,
            "sha256": sha256_text(canonical_json(body)), "flags": validated}


def get_flag(taxonomy: dict[str, Any], flag_id: str) -> dict[str, Any] | None:
    for flag in taxonomy["flags"]:
        if flag["id"] == flag_id:
            return flag
    return None


def candidates_for(crash: dict[str, Any], analysis: dict[str, Any],
                   taxonomy: dict[str, Any]) -> list[dict[str, Any]]:
    """Propose candidate target flags from stored evidence.

    Deterministic and conservative: a candidate requires either a matching
    component keyword or an exploitability indicator listed for the flag. When
    no rule matches, no candidate is proposed rather than guessing. Output is
    a hypothesis list only — never an assertion of achievement.
    """
    diag_modules = (crash.get("diagnostics") or {}).get("modules") or []
    component = str(diag_modules[0] if diag_modules
                    else crash.get("target", "")).lower()
    haystack = " ".join([
        component,
        str(crash.get("target", "")).lower(),
        str(analysis.get("likely_affected_component", "")).lower(),
    ])
    indicator = analysis.get("exploitability_classification", "")
    proposals: list[dict[str, Any]] = []
    for flag in taxonomy["flags"]:
        keyword_hit = any(k in haystack for k in flag["keywords"])
        indicator_hit = bool(flag["indicators"]) and indicator in flag["indicators"]
        if not (keyword_hit or indicator_hit):
            continue
        confidence = "MEDIUM" if (keyword_hit and indicator_hit) else "LOW"
        rationale = []
        if keyword_hit:
            rationale.append(f"component matches keywords for '{flag['id']}'")
        if indicator_hit:
            rationale.append(f"analysis indicator '{indicator}' is listed for "
                             f"'{flag['id']}'")
        proposals.append({"flag_id": flag["id"], "confidence": confidence,
                          "rationale": rationale})
    proposals.sort(key=lambda p: p["flag_id"])
    return proposals


def summarize_candidates(candidates: list[dict[str, Any]]) -> list[str]:
    return [c["flag_id"] for c in candidates]
