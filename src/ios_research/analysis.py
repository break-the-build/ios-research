"""Root-cause and exploitability analysis.

Analysis is deliberately conservative and *evidence-gated*: an exploitability
indicator is only assigned when the collected diagnostic evidence supports it.
The framework never produces shellcode, ROP chains, or weaponized exploits — it
produces *indicators* and open questions to guide further authorized research.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .clock import now_iso
from .crashes import CrashStore, CrashRecord
from .ids import make_id
from .triage import Triage
from .workspace import Workspace

# Confidence levels.
UNKNOWN, LOW, MEDIUM, HIGH = "UNKNOWN", "LOW", "MEDIUM", "HIGH"

# Safe exploitability classifications (indicators only).
CRASH_ONLY = "CRASH_ONLY"
CONTROLLED_MEMORY_ACCESS_INDICATOR = "CONTROLLED_MEMORY_ACCESS_INDICATOR"
CONTROLLED_REGISTER_INDICATOR = "CONTROLLED_REGISTER_INDICATOR"
ARBITRARY_READ_INDICATOR = "ARBITRARY_READ_INDICATOR"
ARBITRARY_WRITE_INDICATOR = "ARBITRARY_WRITE_INDICATOR"
CODE_EXECUTION_INDICATOR = "CODE_EXECUTION_INDICATOR"

_MEMORY_SAFETY = {
    "OUT_OF_BOUNDS_READ": "spatial",
    "OUT_OF_BOUNDS_WRITE": "spatial",
    "USE_AFTER_FREE": "temporal",
    "NULL_DEREFERENCE": "null-dereference",
    "TYPE_CONFUSION": "type-confusion",
    "INTEGER_ERROR": "integer",
    "ASSERTION": "logic",
    "TIMEOUT": "resource",
}


@dataclass
class Analysis:
    id: str
    crash_id: str
    signature: str
    root_cause_hypothesis: str
    memory_safety_classification: str
    reproducibility: str
    attacker_controlled_input: bool
    likely_affected_component: str
    security_boundary: str
    exploitability_classification: str
    exploitability_evidence: list[str]
    exploitability_questions: list[str]
    confidence: str
    created_at: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _indicator(crash: CrashRecord, reproduced: bool) -> tuple[str, str, list[str], list[str]]:
    """Return (classification, confidence, evidence, open_questions).

    Conservative and evidence-gated. Stronger indicators (arbitrary read/write,
    code execution) are only reachable with explicit register/PC-control
    evidence, which mock diagnostics do not fabricate.
    """
    diag = crash.diagnostics
    access = diag.get("access_type", "none")
    cls = crash.classification
    evidence: list[str] = [f"classification={cls}",
                           f"access_type={access}",
                           f"reproducible={reproduced}",
                           "input_attacker_controlled=true"]
    questions: list[str] = []
    pc_controlled = bool(diag.get("pc_controlled"))  # never set by mock targets

    if cls == "NULL_DEREFERENCE":
        return CRASH_ONLY, LOW, evidence, [
            "Can the null pointer be made non-null and attacker-controlled?"]

    if cls in ("OUT_OF_BOUNDS_READ", "OUT_OF_BOUNDS_WRITE", "USE_AFTER_FREE",
               "TYPE_CONFUSION"):
        questions = [
            "Is the faulting address attacker-controlled?",
            "Can the access offset/size be influenced by input?",
        ]
        if cls == "USE_AFTER_FREE":
            questions.append(
                "Can the freed object be reallocated with controlled data?")
        if cls == "TYPE_CONFUSION":
            questions.append("Does the confused type expose a virtual dispatch?")
        confidence = MEDIUM if reproduced else LOW
        # Only a *controlled memory access* indicator without PC/register-control
        # evidence. Arbitrary read/write and code execution require more.
        if pc_controlled:  # pragma: no cover - mock never sets this
            return CODE_EXECUTION_INDICATOR, HIGH, evidence + ["pc_controlled=true"], questions
        return CONTROLLED_MEMORY_ACCESS_INDICATOR, confidence, evidence, questions

    if cls == "INTEGER_ERROR":
        return CRASH_ONLY, LOW, evidence, [
            "Does the integer error lead to an out-of-bounds access downstream?"]

    if cls in ("ASSERTION", "TIMEOUT"):
        return CRASH_ONLY, LOW, evidence, [
            "Is this a denial-of-service condition only?"]

    return CRASH_ONLY, UNKNOWN, evidence, [
        "Insufficient evidence to classify exploitability."]


class Analyzer:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.crashes = CrashStore(workspace)
        self.triage = Triage(workspace)

    def _rel(self, analysis_id: str) -> str:
        return f"analysis/{analysis_id}.json"

    def get(self, analysis_id: str) -> Analysis:
        rel = self._rel(analysis_id)
        if not self.ws.path(rel).exists():
            from .errors import NotFoundError
            raise NotFoundError(f"analysis '{analysis_id}' not found")
        return Analysis(**self.ws.read_json(rel))

    def list(self) -> list[Analysis]:
        return [Analysis(**d) for d in self.ws.list_json("analysis")]

    def analyze(self, crash: CrashRecord) -> Analysis:
        # Ensure reproducibility is known (drives confidence).
        if crash.reproduced is None:
            self.triage.reproduce(crash)
            crash = self.crashes.get(crash.id)
        reproduced = bool(crash.reproduced)

        classification, confidence, evidence, questions = _indicator(
            crash, reproduced)
        diag = crash.diagnostics
        component = (diag.get("modules") or [crash.target])[0]

        # Candidate Target Flags are hypotheses derived from the same stored
        # evidence (#58); they never assert a flag is achieved.
        from .targetflags import candidates_for, load_taxonomy
        taxonomy = load_taxonomy(self.ws)
        candidates = candidates_for(crash.to_dict(),
                                    {"exploitability_classification":
                                     classification,
                                     "likely_affected_component": component},
                                    taxonomy)

        analysis = Analysis(
            id=make_id("analysis", crash.id, crash.signature),
            crash_id=crash.id,
            signature=crash.signature,
            root_cause_hypothesis=f"{crash.classification}: {crash.detail}",
            memory_safety_classification=_MEMORY_SAFETY.get(
                crash.classification, "unknown"),
            reproducibility="reproducible" if reproduced else "unconfirmed",
            attacker_controlled_input=True,
            likely_affected_component=component,
            security_boundary="untrusted input processing "
                              "(file/stream parsing on the target)",
            exploitability_classification=classification,
            exploitability_evidence=evidence,
            exploitability_questions=questions,
            confidence=confidence,
            created_at=now_iso(),
            extra={"faulting_address": diag.get("faulting_address"),
                   "exception_type": diag.get("exception_type"),
                   "candidate_target_flags":
                       [c["flag_id"] for c in candidates],
                   "target_flag_taxonomy_sha256": taxonomy["sha256"]},
        )
        self.ws.write_json(self._rel(analysis.id), analysis.to_dict())
        # Convenience copy beside the crash + backlink.
        self.ws.write_json(f"crashes/{crash.id}/analysis.json", analysis.to_dict())
        crash.analysis_id = analysis.id
        self.crashes.save(crash)
        return analysis

    def analyze_batch(self) -> list[Analysis]:
        return [self.analyze(crash) for crash in self.crashes.list()]
