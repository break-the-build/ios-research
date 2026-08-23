"""Vulnerability reporting.

Generates professional, responsible-disclosure reports whose every claim traces
back to experiment artifacts (experiment id, testcase/input hashes, crash
signature, analysis id). Reports are emitted as JSON and Markdown and validated
for missing evidence and unsupported claims.

Reports never contain weaponized exploit code — only reproduction inputs,
diagnostics, and evidence-gated exploitability *indicators*.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .analysis import Analyzer, Analysis
from .clock import now_iso
from .crashes import CrashStore, CrashRecord
from .experiment import ExperimentStore
from .ids import make_id
from .triage import Triage
from .workspace import Workspace, validate_component

# Text that must never appear in a report (weaponization).
_FORBIDDEN_MARKERS = ("shellcode", "rop chain", "ropchain", "payload gadget",
                      "exploit chain")

_REQUIRED_SECTIONS = (
    "title", "executive_summary", "affected_component", "affected_versions",
    "research_environment", "attack_prerequisites", "zero_click_characteristics",
    "triggering_input", "reproduction_steps", "observed_behavior",
    "expected_behavior", "technical_root_cause", "crash_analysis",
    "security_impact", "exploitability_assessment", "regression_results",
    "timeline", "attachments",
)


@dataclass
class Report:
    id: str
    crash_id: str
    created_at: str
    evidence: dict[str, Any] = field(default_factory=dict)
    sections: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReportGenerator:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.crashes = CrashStore(workspace)
        self.analyzer = Analyzer(workspace)
        self.experiments = ExperimentStore(workspace)
        self.triage = Triage(workspace)

    def _rel(self, report_id: str) -> str:
        return f"reports/{report_id}/report.json"

    # lifecycle -----------------------------------------------------------
    def create(self, crash_id: str) -> Report:
        crash = self.crashes.get(crash_id)
        # Complete the evidence before reporting: reproduce and minimize the
        # crash (idempotently) so the report carries a minimized-input artifact
        # and a substantiated reproducibility claim.
        crash = self._ensure_reproduced(crash)
        crash = self._ensure_minimized(crash)
        analysis = self._ensure_analysis(crash)
        experiment = self._maybe_experiment(crash.experiment_id)

        evidence = {
            "experiment_id": crash.experiment_id,
            "crash_id": crash.id,
            "input_sha256": crash.input_sha256,
            "minimized_sha256": crash.minimized_sha256,
            "testcase_hashes": [crash.input_sha256]
            + ([crash.minimized_sha256] if crash.minimized_sha256 else []),
            "crash_signature": crash.signature,
            "analysis_id": analysis.id,
            "diagnostic_reference":
                f"crashes/{crash.id}/diagnostics/diagnostics.json",
        }
        sections = self._sections(crash, analysis, experiment)
        report = Report(id=make_id("report", crash.id), crash_id=crash.id,
                        created_at=now_iso(), evidence=evidence, sections=sections)
        self.ws.write_json(self._rel(report.id), report.to_dict())
        self.ws.write_bytes(f"reports/{report.id}/report.md",
                            render_markdown(report).encode("utf-8"))
        return report

    def get(self, report_id: str) -> Report:
        validate_component(report_id, what="report id")
        rel = self._rel(report_id)
        if not self.ws.path(rel).exists():
            from .errors import NotFoundError
            raise NotFoundError(f"report '{report_id}' not found")
        return Report(**self.ws.read_json(rel))

    def list(self) -> list[Report]:
        base = self.ws.dir("reports")
        out = []
        for manifest in sorted(base.glob("*/report.json")):
            out.append(Report(**self.ws.read_json(
                str(manifest.relative_to(self.ws.root)))))
        return out

    # helpers -------------------------------------------------------------
    def _ensure_reproduced(self, crash: CrashRecord) -> CrashRecord:
        if crash.reproduced is None:
            self.triage.reproduce(crash)
            return self.crashes.get(crash.id)
        return crash

    def _ensure_minimized(self, crash: CrashRecord) -> CrashRecord:
        if crash.minimized_sha256 is None:
            self.triage.minimize(crash)
            return self.crashes.get(crash.id)
        return crash

    def _ensure_analysis(self, crash: CrashRecord) -> Analysis:
        if crash.analysis_id:
            return self.analyzer.get(crash.analysis_id)
        return self.analyzer.analyze(crash)

    def _maybe_experiment(self, experiment_id: str):
        try:
            return self.experiments.get(experiment_id)
        except Exception:
            return None

    def _sections(self, crash: CrashRecord, analysis: Analysis,
                  experiment) -> dict[str, Any]:
        diag = crash.diagnostics
        os_version = experiment.os_version if experiment else "unknown"
        device = experiment.device if experiment else "unknown"
        # Beta release-pair provenance flows from the corpus lineage (#56).
        beta = None
        if experiment is not None:
            from .betadiff import beta_provenance_for_experiment
            beta = beta_provenance_for_experiment(self.ws, experiment)
        delivery = (experiment.params or {}).get("delivery") \
            if experiment is not None else None
        return {
            "title": f"{crash.classification} in {crash.target} "
                     f"({crash.fmt}) processing",
            "executive_summary":
                f"An authorized fuzzing experiment discovered a "
                f"{crash.classification} in the {crash.target} target while "
                f"parsing {crash.fmt} input. The crash is "
                f"{'reproducible' if crash.reproduced else 'not yet confirmed reproducible'} "
                f"and traces to experiment {crash.experiment_id}.",
            "affected_component": analysis.likely_affected_component,
            "affected_versions": {"target": crash.target,
                                  "os_version": os_version, "device": device},
            "research_environment": {
                "framework": "ios-research", "device": device,
                "os_version": os_version, "mock_target": True,
                "note": "discovered against a controlled mock target in CI"},
            "attack_prerequisites":
                "The target must process an attacker-supplied input of the "
                "affected format. No privileged access is assumed.",
            "zero_click_characteristics":
                "If the affected component processes the input automatically "
                "(without user interaction), the issue may be reachable "
                "zero-click; this must be confirmed against a real code path.",
            "triggering_input": {
                "sha256": crash.input_sha256, "size": crash.input_size,
                "minimized_sha256": crash.minimized_sha256},
            "reproduction_steps": [
                f"ios-research crash show {crash.id} --json",
                f"ios-research crash reproduce {crash.id} --json",
                f"ios-research analyze {crash.id} --json",
            ],
            "observed_behavior":
                f"{diag.get('exception_type', 'crash')} "
                f"({diag.get('signal', '')}) at "
                f"{diag.get('faulting_address', 'n/a')}: {crash.detail}",
            "expected_behavior":
                "The input should be rejected or handled safely without a "
                "memory-safety violation or abnormal termination.",
            "technical_root_cause": analysis.root_cause_hypothesis,
            "crash_analysis": {
                "classification": crash.classification,
                "signature": crash.signature,
                "memory_safety": analysis.memory_safety_classification,
                "exception_type": diag.get("exception_type"),
                "access_type": diag.get("access_type"),
                "faulting_address": diag.get("faulting_address"),
                "stack_trace": diag.get("stack_trace", []),
            },
            "security_impact":
                "Memory-safety issue in untrusted-input processing. Impact "
                "beyond a crash requires the exploitability questions below to "
                "be resolved with further authorized research.",
            "exploitability_assessment": {
                "indicator": analysis.exploitability_classification,
                "confidence": analysis.confidence,
                "evidence": analysis.exploitability_evidence,
                "open_questions": analysis.exploitability_questions,
                "note": "Indicators only. No weaponized exploit is provided.",
            },
            "regression_results":
                "See 'ios-research diff' for cross-version behavior; a "
                "regression corpus entry is created on minimization.",
            **({"beta_provenance": {
                "source": "corpus lineage",
                **beta}}
               if beta else {}),
            **({"delivery_provenance": {
                "source": "experiment declaration",
                "delivery": delivery,
                "note": ("Researcher-declared input-delivery channel for the "
                         "captured session; reporting metadata only.")}}
               if delivery else {}),
            "timeline": [{"date": crash.first_seen, "event": "crash discovered"},
                         {"date": now_iso(), "event": "report generated"}],
            "attachments": [
                f"crashes/{crash.id}/original-input.bin",
                f"crashes/{crash.id}/minimized-input.bin"
                if crash.minimized_sha256 else None,
                f"crashes/{crash.id}/diagnostics/diagnostics.json",
            ],
        }

    # validation ----------------------------------------------------------
    def validate(self, report: Report) -> dict[str, Any]:
        issues: list[str] = []

        for section in _REQUIRED_SECTIONS:
            value = report.sections.get(section)
            if value in (None, "", [], {}):
                issues.append(f"missing or empty section: {section}")

        ev = report.evidence
        for key in ("experiment_id", "crash_id", "input_sha256",
                    "crash_signature", "analysis_id"):
            if not ev.get(key):
                issues.append(f"missing evidence: {key}")

        # Evidence artifacts must actually exist.
        from .artifacts import ArtifactStore
        store = ArtifactStore(self.ws)
        if ev.get("input_sha256") and not store.exists(ev["input_sha256"]):
            issues.append("input artifact is missing from the workspace")
        if ev.get("minimized_sha256") and not store.exists(ev["minimized_sha256"]):
            issues.append("referenced minimized artifact is missing")

        # Exploitability claim must match the stored analysis (no overclaiming).
        try:
            analysis = self.analyzer.get(ev.get("analysis_id", ""))
            claim = report.sections.get("exploitability_assessment", {})
            if claim.get("indicator") != analysis.exploitability_classification:
                issues.append("exploitability claim does not match analysis")
        except Exception:
            issues.append("analysis referenced by report is missing")

        # No weaponized content.
        blob = str(report.sections).lower()
        for marker in _FORBIDDEN_MARKERS:
            if marker in blob:
                issues.append(f"forbidden content present: {marker}")

        return {"valid": not issues, "issues": issues,
                "checked_sections": len(_REQUIRED_SECTIONS)}

    def export(self, report: Report, fmt: str = "markdown") -> str:
        if fmt in ("md", "markdown"):
            return render_markdown(report)
        if fmt == "json":
            import json
            return json.dumps(report.to_dict(), indent=2, sort_keys=True)
        from .errors import UsageError
        raise UsageError(f"unknown export format: {fmt}")


def render_markdown(report: Report) -> str:
    """Render a report as a responsible-disclosure Markdown document."""
    s = report.sections
    ev = report.evidence

    def block(title: str, body: Any) -> str:
        if isinstance(body, list):
            body = "\n".join(f"- {x}" for x in body if x is not None)
        elif isinstance(body, dict):
            body = "\n".join(f"- **{k}**: {v}" for k, v in body.items())
        return f"## {title}\n\n{body}\n"

    lines = [
        f"# {s.get('title', 'Vulnerability Report')}",
        "",
        "> Prepared for responsible disclosure (e.g. Apple Product Security, "
        "product-security@apple.com). Authorized research only. "
        "No weaponized exploit code is included.",
        "",
        f"**Report ID:** `{report.id}`  ",
        f"**Crash ID:** `{report.crash_id}`  ",
        f"**Experiment:** `{ev.get('experiment_id')}`  ",
        f"**Crash signature:** `{ev.get('crash_signature')}`",
        "",
        block("Executive Summary", s.get("executive_summary", "")),
        block("Affected Component", s.get("affected_component", "")),
        block("Affected Versions", s.get("affected_versions", {})),
        block("Research Environment", s.get("research_environment", {})),
        block("Attack Prerequisites", s.get("attack_prerequisites", "")),
        block("Zero-click Characteristics", s.get("zero_click_characteristics", "")),
        block("Triggering Input", s.get("triggering_input", {})),
        block("Reproduction Steps", s.get("reproduction_steps", [])),
        block("Observed Behavior", s.get("observed_behavior", "")),
        block("Expected Behavior", s.get("expected_behavior", "")),
        block("Technical Root Cause", s.get("technical_root_cause", "")),
        block("Crash Analysis", s.get("crash_analysis", {})),
        block("Security Impact", s.get("security_impact", "")),
        block("Exploitability Assessment", s.get("exploitability_assessment", {})),
        block("Regression Results", s.get("regression_results", "")),
        block("Timeline", [f"{t['date']}: {t['event']}"
                           for t in s.get("timeline", [])]),
        block("Attachments", s.get("attachments", [])),
        "## Evidence",
        "",
        "\n".join(f"- **{k}**: `{v}`" for k, v in ev.items()),
        "",
    ]
    return "\n".join(lines)
