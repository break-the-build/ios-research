"""Local Apple-bounty submission-readiness checks and evidence-pack export.

This module assesses the completeness of records already present in a research
workspace.  It neither attempts to establish exploitability nor interacts with
Apple systems, Target Flags, devices, accounts, or privileged services.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .errors import ValidationError
from .logging_util import _REDACTED, _REDACT_KEYS
from .report import Report, ReportGenerator


PACK_SCHEMA_VERSION = 1


def load_metadata(path: str | None) -> dict[str, Any]:
    """Load an optional researcher-authored JSON object; never upload it."""
    if path is None:
        return {}
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"invalid researcher metadata: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError("researcher metadata must be a JSON object")
    return value


def redact_value(value: Any) -> Any:
    """Recursively remove values keyed as credentials from an export."""
    if isinstance(value, dict):
        return {str(key): (_REDACTED if str(key).lower() in _REDACT_KEYS
                           else redact_value(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return value


class BountyReadiness:
    """Evidence-only validator for a responsible-disclosure submission draft."""

    def __init__(self, workspace):
        self.ws = workspace
        self.reports = ReportGenerator(workspace)
        self.artifacts = ArtifactStore(workspace)

    def validate(self, report: Report, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        metadata = metadata or {}
        report_validation = self.reports.validate(report)
        crash = self.reports.crashes.get(report.crash_id)
        sections = report.sections
        evidence = report.evidence
        diagnostic_ref = evidence.get("diagnostic_reference", "")
        versions = sections.get("affected_versions", {})
        attestations = metadata.get("attestations", {})
        if not isinstance(attestations, dict):
            attestations = {}

        checks = [
            _check("report_validation", report_validation["valid"],
                   "The existing report passes its evidence and safety validation."),
            _check("reproducible_crash", crash.reproduced is True,
                   "The recorded crash has a successful reproduction result."),
            _check("minimized_input", bool(evidence.get("minimized_sha256")) and
                   self.artifacts.exists(evidence.get("minimized_sha256", "")),
                   "A minimized input artifact is retained locally."),
            _check("diagnostics", bool(diagnostic_ref) and self.ws.path(diagnostic_ref).is_file(),
                   "The referenced diagnostics artifact is retained locally."),
            _check("affected_component", bool(sections.get("affected_component")),
                   "The report identifies an affected component."),
            _check("affected_versions", isinstance(versions, dict) and
                   bool(versions.get("target")) and versions.get("os_version") not in (None, "", "unknown"),
                   "The report records a target and non-placeholder OS version."),
            _check("reproduction_steps", bool(sections.get("reproduction_steps")),
                   "The report includes reproduction steps."),
            _check("authorized_testing_attestation", attestations.get("authorized_testing") is True,
                   "Researcher metadata attests that testing was authorized."),
            _check("researcher_contact", isinstance(metadata.get("contact"), str) and bool(metadata["contact"].strip()),
                   "Researcher metadata supplies a contact for follow-up."),
        ]
        missing = [item["id"] for item in checks if not item["passed"]]
        return {
            "ready": not missing,
            "checklist_version": 1,
            "report_id": report.id,
            "checks": checks,
            "missing": missing,
            "limitations": [
                "Readiness is an evidence-completeness assessment, not a bounty eligibility or severity determination.",
                "The framework does not access Apple systems, Target Flags, or privileged device capabilities.",
            ],
        }

    def pack(self, report: Report, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return deterministic, redacted references to local evidence artifacts."""
        metadata = metadata or {}
        readiness = self.validate(report, metadata)
        evidence = report.evidence
        attachments = [item for item in report.sections.get("attachments", []) if item]
        return redact_value({
            "schema_version": PACK_SCHEMA_VERSION,
            "kind": "apple-bounty-evidence-pack",
            "report_id": report.id,
            "crash_id": report.crash_id,
            "readiness": readiness,
            "report": {
                "title": report.sections.get("title", ""),
                "affected_component": report.sections.get("affected_component", ""),
                "affected_versions": report.sections.get("affected_versions", {}),
                "reproduction_steps": report.sections.get("reproduction_steps", []),
                "evidence": evidence,
                "attachments": attachments,
            },
            "researcher_metadata": metadata,
            "limitations": [
                "Contains references and hashes for locally retained evidence; it does not package exploits or payloads.",
                "No data is transmitted by this export command.",
            ],
        })

    def write_pack(self, report: Report, metadata: dict[str, Any] | None = None,
                   out: str | None = None) -> Path:
        pack = self.pack(report, metadata)
        if out is None:
            path = self.ws.path("reports", report.id, "apple-bounty-evidence.json")
        else:
            path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(pack, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path


def _check(identifier: str, passed: bool, description: str) -> dict[str, Any]:
    return {"id": identifier, "passed": bool(passed), "description": description}
