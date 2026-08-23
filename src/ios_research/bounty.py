"""Local Apple-bounty submission-readiness checks and evidence-pack export.

This module assesses the completeness of records already present in a research
workspace.  It neither attempts to establish exploitability nor interacts with
Apple systems, Target Flags, devices, accounts, or privileged services.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .errors import ValidationError
from .logging_util import _REDACTED, _REDACT_KEYS
from .report import Report, ReportGenerator
from .hashing import sha256_bytes


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

    def _validated_crash_id(self, report: Report) -> str:
        """Reject crafted ids before they reach any workspace path join."""
        crash_id = report.crash_id
        if (not isinstance(crash_id, str) or not crash_id
                or Path(crash_id).is_absolute()
                or Path(crash_id).name != crash_id):
            raise ValidationError(
                "crash id must be a single path component inside the workspace")
        return crash_id

    def validate(self, report: Report, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        metadata = metadata or {}
        report_validation = self.reports.validate(report)
        crash = self.reports.crashes.get(self._validated_crash_id(report))
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
        """Return a deterministic, redacted manifest of validated local evidence."""
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
            "artifacts": self._artifact_manifest(report),
            "researcher_metadata": metadata,
            "limitations": [
                "Contains references and hashes for locally retained evidence; it does not package exploits or payloads.",
                "No data is transmitted by this export command.",
            ],
        })

    def write_pack(self, report: Report, metadata: dict[str, Any] | None = None,
                   out: str | None = None) -> Path:
        """Write a local evidence directory with copied, hash-verified artifacts.

        Only fixed workspace-relative report/crash paths are eligible.  The
        export is intentionally a directory rather than an executable bundle;
        no contents are run, imported, or sent anywhere.
        """
        pack = self.pack(report, metadata)
        if out is None:
            path = self.ws.path("reports", report.id, "apple-bounty-evidence")
        else:
            path = Path(out)
        path.mkdir(parents=True, exist_ok=True)
        for item in pack["artifacts"]:
            source = self._workspace_file(item["source"])
            destination = path / item["archive_path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            if sha256_bytes(destination.read_bytes()) != item["sha256"]:
                raise ValidationError("evidence copy hash verification failed")
        manifest = path / "manifest.json"
        manifest.write_text(json.dumps(pack, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return manifest

    def _artifact_manifest(self, report: Report) -> list[dict[str, Any]]:
        crash_id = report.crash_id
        evidence = report.evidence
        expected = {
            f"crashes/{crash_id}/original-input.bin": evidence.get("input_sha256"),
            f"crashes/{crash_id}/minimized-input.bin": evidence.get("minimized_sha256"),
            f"crashes/{crash_id}/diagnostics/diagnostics.json": None,
            f"crashes/{crash_id}/crash.json": None,
        }
        items = []
        for source, expected_hash in sorted(expected.items()):
            # A report without minimized evidence is already marked incomplete,
            # but its retained original crash input/logs can still be exported.
            if source.endswith("minimized-input.bin") and not expected_hash:
                continue
            file = self._workspace_file(source)
            digest = sha256_bytes(file.read_bytes())
            if expected_hash and digest != expected_hash:
                raise ValidationError(f"evidence hash mismatch: {source}")
            items.append({"source": source, "archive_path": f"evidence/{source}",
                          "sha256": digest, "size": file.stat().st_size})
        return items

    def _workspace_file(self, relative: str) -> Path:
        if not isinstance(relative, str):
            raise ValidationError("evidence path must be a workspace-relative string")
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValidationError("evidence path must stay inside the workspace")
        root = self.ws.root.resolve()
        resolved = (self.ws.root / candidate).resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValidationError("evidence path resolves outside the workspace") from exc
        if not resolved.is_file():
            raise ValidationError(f"required evidence artifact is missing: {relative}")
        return resolved


def _check(identifier: str, passed: bool, description: str) -> dict[str, Any]:
    return {"id": identifier, "passed": bool(passed), "description": description}
