"""macOS reward-category verification oracles (#62).

macOS carries dedicated bounty lines — Gatekeeper quarantined-file bypass,
TCC Target Flag capture, and macOS-only App Sandbox escape. This module turns
*researcher-supplied observation records* into structured verdicts that state
whether the recorded evidence demonstrates one of those specific rewarded
outcomes, so qualifying evidence is captured and classified consistently.

These are **pure classifiers over supplied evidence**: they read JSON records
the researcher collected on a machine they own (system logs, assessment
outcomes, handle observations) and produce deterministic verdicts. They do
not perform privileged operations, suppress consent prompts, automate any
bypass, or touch machines the researcher does not own.

Every verdict separates *observation* from *claim*: an oracle can state that
recorded evidence is consistent with an outcome; it never asserts that an
exploit exists or that Apple would award a category.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .clock import now_iso
from .errors import ValidationError
from .hashing import sha256_text
from .ids import make_id
from .workspace import Workspace

ORACLE_SCHEMA_VERSION = 1

# TCC resources commonly protected by consent prompts (subset).
_TCC_RESOURCES = {"photos", "contacts", "calendar", "reminders", "camera",
                  "microphone", "location", "full-disk-access", "accessibility"}

_CONSENT_VALUES = {"granted", "denied", "none"}


def _load_evidence(path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"cannot read evidence: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError("evidence must be a JSON object")
    return data


@dataclass
class Verdict:
    oracle: str
    classification: str
    observed: list[str]
    missing_for_claim: list[str]
    claim_separation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "oracle": self.oracle,
            "classification": self.classification,
            "observed": self.observed,
            "missing_for_claim": self.missing_for_claim,
            "claim_separation": self.claim_separation,
        }


def tcc_oracle(evidence: dict[str, Any]) -> Verdict:
    """Classify TCC capture evidence (Target Flag category, macOS)."""
    resource = str(evidence.get("resource", "")).lower()
    access = evidence.get("access_event")
    if resource not in _TCC_RESOURCES:
        raise ValidationError(
            f"unknown TCC resource '{resource}'; known: "
            f"{', '.join(sorted(_TCC_RESOURCES))}")
    if not isinstance(access, dict):
        raise ValidationError("evidence requires an 'access_event' object")
    consent = str(access.get("consent", "")).lower()
    if consent not in _CONSENT_VALUES:
        raise ValidationError(
            f"access_event.consent must be one of {sorted(_CONSENT_VALUES)}")

    observed = [f"resource={resource}", f"consent={consent}"]
    if evidence.get("sandboxed_app") is True:
        observed.append("unsandboxed=false (App Sandbox in use)")
    else:
        observed.append("unsandboxed=true (no App Sandbox detected)")

    if consent == "none":
        classification = "capture-evidence"
        missing = ["researcher-confirmed absence of prompt (screenshot/log)",
                   "second-run reproducibility note"]
        if evidence.get("sandboxed_app") is True:
            classification = "capture-evidence-sandboxed"
            missing.insert(0, "app-sandbox containment proof for the process")
    elif consent == "denied":
        classification = "no-capture-denied-path"
        missing = []
    else:
        classification = "no-capture-consented"
        missing = []
    return Verdict(
        oracle="tcc",
        classification=classification,
        observed=observed,
        missing_for_claim=missing,
        claim_separation=(
            "An observation that evidence is consistent with a TCC capture; "
            "not an assertion that a Target Flag was achieved."))


def gatekeeper_oracle(evidence: dict[str, Any]) -> Verdict:
    """Classify Gatekeeper quarantine-check bypass evidence (macOS)."""
    source = str(evidence.get("download_source", "")).lower()
    quarantine = evidence.get("quarantine_bit") is True
    assessment = evidence.get("assessment")
    if not isinstance(assessment, dict):
        raise ValidationError("evidence requires an 'assessment' object")
    result = str(assessment.get("result", "")).lower()
    if result not in ("opened", "blocked"):
        raise ValidationError("assessment.result must be 'opened' or 'blocked'")

    observed = [f"download_source={source or 'unknown'}",
                f"quarantine_bit={str(quarantine).lower()}",
                f"assessment_result={result}"]
    checks = [str(c) for c in assessment.get("checks_encountered", [])]
    observed.append(f"checks_encountered={','.join(checks) or 'none'}")

    opened_with_quarantine = result == "opened" and quarantine
    safari_provenance = source == "safari"

    if opened_with_quarantine and safari_provenance:
        classification = "full-bypass-evidence"
        missing = ["Safari download provenance record for the exact file",
                   "re-test on current public macOS build"]
    elif opened_with_quarantine:
        classification = "limited-interaction-evidence"
        missing = ["interaction transcript (installer/drag flows)",
                   "re-test on current public macOS build"]
    else:
        classification = "compliant-behavior"
        missing = []
    return Verdict(
        oracle="gatekeeper",
        classification=classification,
        observed=observed,
        missing_for_claim=missing,
        claim_separation=(
            "An observation about recorded Gatekeeper assessment outcomes; "
            "not an assertion that a bypass was achieved."))


_SANDBOX_OBSERVATION_TYPES = {
    "file-handle-outside-container",
    "xpc-outside-entitlements",
    "network-bind-unexpected",
    "posix-shm-outside-container",
}
_INSIDE_TYPES = {"file-handle-inside-container", "xpc-within-entitlements"}


def sandbox_escape_oracle(evidence: dict[str, Any]) -> Verdict:
    """Classify App Sandbox escape indicator evidence (macOS-only line)."""
    entitlements = evidence.get("process_entitlements")
    observations = evidence.get("observations")
    if not isinstance(entitlements, list):
        raise ValidationError(
            "evidence requires 'process_entitlements' array (may be empty)")
    if not isinstance(observations, list) or not observations:
        raise ValidationError(
            "evidence requires a non-empty 'observations' array")
    normalized = []
    for index, item in enumerate(observations):
        if not isinstance(item, dict):
            raise ValidationError(f"observation {index} must be an object")
        kind = str(item.get("type", ""))
        if kind in _INSIDE_TYPES:
            continue
        if kind not in _SANDBOX_OBSERVATION_TYPES:
            raise ValidationError(
                f"observation {index} has unknown type '{kind}'; known: "
                f"{', '.join(sorted(_SANDBOX_OBSERVATION_TYPES | _INSIDE_TYPES))}")
        normalized.append(kind)

    outside = sorted(set(normalized))
    observed = [f"entitlement_count={len(entitlements)}"] + \
        [f"outside_container:{kind}" for kind in outside]
    if outside:
        return Verdict(
            oracle="sandbox-escape",
            classification="escape-evidence-indicator",
            observed=observed,
            missing_for_claim=[
                "primitive stability across repeated trials",
                "confirmation that no researcher misconfiguration explains "
                "the observation"],
            claim_separation=(
                "An indicator that recorded observations are consistent with "
                "a sandbox escape primitive; it does not demonstrate or "
                "weaponize one."))
    return Verdict(
        oracle="sandbox-escape",
        classification="contained",
        observed=observed,
        missing_for_claim=[],
        claim_separation=("No outside-container observation was recorded."))


MAC_ORACLES = {"tcc": tcc_oracle,
            "gatekeeper": gatekeeper_oracle,
            "sandbox-escape": sandbox_escape_oracle}


class MacOracleEngine:
    """Runs verification oracles and persists verdict artifacts."""

    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def run(self, *, name: str, evidence_path: str) -> dict[str, Any]:
        if name not in MAC_ORACLES:
            raise ValidationError(
                f"unknown oracle '{name}'; known: {', '.join(sorted(MAC_ORACLES))}")
        verdict = MAC_ORACLES[name](_load_evidence(evidence_path))
        digest = sha256_text(json.dumps(verdict.to_dict(), sort_keys=True))
        record_id = make_id("oracleverdict", name, digest)
        record = {
            "id": record_id,
            "kind": "oracle-verdict",
            "created_at": now_iso(),
            "schema_version": ORACLE_SCHEMA_VERSION,
            **verdict.to_dict(),
        }
        self.ws.write_json(f"analysis/{record_id}.json", record)
        return record
