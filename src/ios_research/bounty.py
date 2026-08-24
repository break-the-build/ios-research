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
from .targetflags import candidates_for, get_flag, load_taxonomy


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

    def validate(self, report: Report, metadata: dict[str, Any] | None = None,
                 *, tccutil_output: str | None = None) -> dict[str, Any]:
        metadata = metadata or {}
        self.reports.crashes.ensure_safe_id(report.crash_id)
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

        # Flag-aware readiness (#58): claimed flags get per-element checklists;
        # candidate flags from analysis are surfaced as guidance only.
        taxonomy = load_taxonomy(self.ws)
        analysis = self._analysis_for(crash)
        experiment_params: dict = {}
        exp_id = getattr(crash, "experiment_id", None)
        if exp_id:
            try:
                experiment_params = self.reports.experiments.get(
                    exp_id).params or {}
            except Exception:
                experiment_params = {}
        candidates = (candidates_for(crash.to_dict(), analysis, taxonomy,
                                     experiment_params=experiment_params)
                      if analysis else [])

        # Target Flag capture evidence (#84): recorded only when detection
        # actually fired; supplying tccutil output makes the check binding.
        from .flagcapture import detect_commpage, parse_tccutil_output
        capture = (analysis or {}).get("target_flag_capture") \
            if isinstance(analysis, dict) else None
        if capture is None:
            # Researcher may supply the boot-random commpage contents captured
            # during the PoC run for exact-match (HIGH confidence) checks.
            supplied = metadata.get("commpage_values")
            if isinstance(supplied, dict):
                capture = detect_commpage(
                    getattr(crash, "diagnostics", {}) or {},
                    supplied=supplied)
        tcc = parse_tccutil_output(tccutil_output) \
            if tccutil_output is not None else None
        if capture is not None:
            from .flagcapture import describe as _describe
            checks.append(_check(
                "target_flag_capture", True,
                f"Commpage Target Flag pattern detected in stored "
                f"diagnostics: {_describe(capture)}."))
        elif tcc is not None:
            checks.append(_check(
                "target_flag_capture", bool(tcc["captured"]),
                "tccutil flag check output "
                + ("reports 'modified': TCC Target Flag demonstration "
                   "captured." if tcc["captured"]
                   else "reports no modification; the TCC flag was not "
                        "captured.")))

        claimed = self._claimed_flags(report, metadata, taxonomy)
        check_by_id = {c["id"]: c["passed"] for c in checks}
        for claim in claimed:
            flag = get_flag(taxonomy, claim["flag_id"])
            if flag is None:
                checks.append(_check(
                    f"target_flag:{claim['flag_id']}:known", False,
                    "Claimed target flag is not in the local taxonomy; update "
                    f"the taxonomy data before claiming it."))
                continue
            for element in flag["evidence_required"]:
                passed, description = _flag_element_check(
                    element, crash, report, metadata, check_by_id)
                checks.append(_check(
                    f"target_flag:{claim['flag_id']}:{element}", passed,
                    f"[{claim['flag_id']}] {description}"))

        missing = [item["id"] for item in checks if not item["passed"]]

        # Mitigation-generation mismatch (#87): a non-binding warning over the
        # researcher-supplied matrix evidence; never affects readiness.
        from .mitigation import mismatch_warning
        warnings = []
        matrix_items = metadata.get("matrix_evidence")
        if isinstance(matrix_items, list):
            warning = mismatch_warning(matrix_items)
            if warning:
                warnings.append(warning)

        return {
            "ready": not missing,
            "checklist_version": 1,
            "report_id": report.id,
            "checks": checks,
            "missing": missing,
            "warnings": warnings,
            "target_flags": {
                "taxonomy_version": taxonomy["taxonomy_version"],
                "taxonomy_sha256": taxonomy["sha256"],
                "claimed": [c["flag_id"] for c in claimed],
                **({"delivery": experiment_params["delivery"]}
                   if experiment_params.get("delivery") else {}),
                "candidates": [
                    {"flag_id": c["flag_id"], "confidence": c["confidence"]}
                    for c in candidates],
                "capture": capture,
                "tccutil": tcc,
                "note": ("Candidates are hypotheses from stored evidence; "
                         "claims are researcher-declared and checked against "
                         "their required evidence elements only. This is not "
                         "an eligibility or reward determination."),
            },
            "limitations": [
                "Readiness is an evidence-completeness assessment, not a bounty eligibility or severity determination.",
                "The framework does not access Apple systems, Target Flags, or privileged device capabilities.",
            ],
        }

    @staticmethod
    def _claimed_flags(report: Report, metadata: dict[str, Any],
                       taxonomy: dict[str, Any]) -> list[dict[str, str]]:
        """Researcher-declared flag claims (metadata wins over sections)."""
        raw = metadata.get("target_flags")
        if raw is None:
            raw = report.sections.get("target_flag_claims")
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list):
            return []
        return [{"flag_id": str(item)} for item in raw if str(item).strip()]

    def _analysis_for(self, crash) -> dict[str, Any] | None:
        try:
            if crash.analysis_id:
                stored = self.ws.read_json(f"analysis/{crash.analysis_id}.json")
            else:
                stored = self.ws.read_json(f"crashes/{crash.id}/analysis.json")
            return stored
        except Exception:
            return None

    def pack(self, report: Report, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return a deterministic, redacted manifest of validated local evidence."""
        metadata = metadata or {}
        # A crafted report/crash id must never reach evidence-path construction;
        # fail closed before any store lookup or export step.
        self._safe_component(report.crash_id, "crash id")
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
            # Researcher-recorded artifacts (#38) are listed separately from
            # tool-generated sections so attached evidence stays clearly
            # distinguished from the framework's own analysis.
            "attached_evidence": self._attached_evidence(report),
            "target_flag_guidance": readiness["target_flags"],
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

    @staticmethod
    def _safe_component(value: str, what: str) -> str:
        """Reject ids that are not a single safe path component."""
        if not isinstance(value, str) or not value \
                or Path(value).name != value or value in (".", ".."):
            raise ValidationError(
                f"{what} must be a safe workspace-relative component")
        return value

    def _artifact_manifest(self, report: Report) -> list[dict[str, Any]]:
        crash_id = self._safe_component(report.crash_id, "crash id")
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

    def _attached_evidence(self, report: Report) -> list[dict[str, Any]]:
        """Integrity-verified listing of imported researcher evidence (#38)."""
        try:
            from .evidence import EvidenceStore
            items = EvidenceStore(self.ws).list(report.crash_id)
        except ValidationError:
            return []
        verified = []
        for item in items:
            entry = {key: item[key] for key in
                     ("id", "kind", "sha256", "captured_at", "warnings")
                     if key in item}
            entry["integrity_ok"] = self.ws.path(item["file"]).is_file() and \
                sha256_bytes(
                    self.ws.path(item["file"]).read_bytes()) == item["sha256"]
            verified.append(entry)
        return verified

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


def _flag_element_check(element: str, crash, report: Report,
                        metadata: dict[str, Any],
                        base_checks: dict[str, bool]) -> tuple[bool, str]:
    """Map a taxonomy evidence element onto a concrete local check."""
    if element == "reproducible_crash":
        return (crash.reproduced is True,
                "The recorded crash has a successful reproduction result.")
    if element == "minimized_input":
        return (base_checks.get("minimized_input", False),
                "A minimized input artifact is retained locally.")
    if element == "build_provenance":
        versions = report.sections.get("affected_versions", {})
        ok = isinstance(versions, dict) and bool(versions.get("target")) and \
            versions.get("os_version") not in (None, "", "unknown")
        return (ok, "Non-placeholder affected component/version provenance "
                    "is recorded.")
    if element == "matrix_confirmation":
        matrix = metadata.get("matrix_evidence")
        ok = isinstance(matrix, list) and bool(
            [item for item in matrix if str(item).strip()])
        return (ok, "A device/OS/build matrix confirmation run (#37) is "
                    "referenced in researcher metadata ('matrix_evidence').")
    if element == "primitive_indicator":
        analysis = None
        try:
            analysis = report.sections.get("exploitability_assessment", {})
        except Exception:  # pragma: no cover - sections are always a dict
            analysis = {}
        indicator = analysis.get("indicator", "")
        ok = indicator in ("CONTROLLED_MEMORY_ACCESS_INDICATOR",
                           "CODE_EXECUTION_INDICATOR")
        return (ok, "The stored analysis indicator supports the outcome "
                    "class claimed by this flag.")
    if element == "target_flag_capture":
        # Satisfied by a stored commpage capture detection or captured
        # tccutil output passed via the CLI (#84).
        analysis = None
        try:
            analysis = report.sections.get("exploitability_assessment", {})
        except Exception:  # pragma: no cover - sections are always a dict
            analysis = {}
        stored = (analysis or {}).get("capture")
        ok = bool(stored) or bool(metadata.get("tccutil_captured"))
        return (ok, "A Commpage/TCC Target Flag capture is recorded "
                    "('target_flag_capture' detection or 'tccutil_captured' "
                    "in researcher metadata).")
    if element == "demonstration_refs":
        refs = metadata.get("demonstration_refs")
        ok = isinstance(refs, list) and bool(
            [item for item in refs if str(item).strip()])
        return (ok, "Researcher-supplied demonstration references "
                    "('demonstration_refs') are present.")
    return (False, f"Unknown evidence element: {element}")  # pragma: no cover
