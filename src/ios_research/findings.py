"""Hybrid static-analysis + LLM-style triage for security findings.

Imports SARIF results from static analyzers (CodeQL, Semgrep, ...), enriches
them (CWE extraction, flow context), and adjudicates each finding through a
pluggable *adjudicator*. The default adjudicator is a deterministic heuristic
reviewer — sink/taint/sanitizer signal matching over the finding's message and
on-disk source excerpt — so triage works offline and stays reproducible. An
external LLM reviewer can produce the same verdict JSON; imported verdicts use
the identical schema and audit trail.

Verdicts are advisory: confirmed findings can seed directed fuzzing
objectives; dismissed ones are suppressed but never deleted (full audit).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .clock import now_iso
from .errors import NotFoundError, ValidationError
from .hashing import sha256_text
from .ids import make_id
from .workspace import Workspace

STATUS_PENDING = "pending"
STATUS_CONFIRMED = "confirmed"
STATUS_DISMISSED = "dismissed"

# Sink keywords per CWE family (family -> tuple of lowercase fragments).
_SINKS: dict[str, tuple[str, ...]] = {
    "CWE-78": ("system(", "popen(", "exec(", "subprocess", "os.exec",
               "shell=True"),
    "CWE-89": ("select ", "execute(", "query(", ".raw(", "cursor.",
               "sqlite3."),
    "CWE-22": ("open(", "os.path.join", "sendfile", "readlink", "unlink("),
    "CWE-79": ("innerHTML", "document.write", "dangerouslySetInnerHTML",
               "<script", "render_template_string"),
    "CWE-502": ("pickle.loads", "yaml.load", "marshal.loads", "unserialize"),
    "CWE-611": ("etree.fromstring", "etree.parse", "XMLParser",
                "defusedxml" ),
    "CWE-120": ("memcpy", "strcpy", "sprintf", "gets(", "strcat"),
}

# Taint-source indicators (lowercase substrings).
_SOURCES = ("request.", "request[", "argv", "stdin", "recv", "input(",
            "environ", "params", "payload", "user_input", "getparameter")

# Sanitizer / mitigation indicators that suggest a false positive.
_SANITIZERS = ("sanitize", "escape(", "escapehtml", "quote_plus",
               "parameterized", "placeholder", "allowlist", "allow_list",
               "validate_", "shlex.quote", "int()")

_CWE_RE = re.compile(r"CWE-(\d+)")
# helpUri style used by many tools: .../definitions/78.html
_URI_CWE_RE = re.compile(r"/definitions/(\d+)\.html")
_FAMILY_RE = re.compile(r"^CWE-(\d+)")


def _family(cwe: str) -> str | None:
    m = _FAMILY_RE.match(cwe)
    if not m:
        return None
    num = int(m.group(1))
    for prefix in _SINKS:
        pnum = int(prefix.split("-")[1])
        if abs(pnum - num) <= 1:  # treat adjacent CWE numbers as one family
            return prefix
    return None


@dataclass
class FindingRecord:
    id: str
    tool: str
    rule_id: str
    cwe: str
    severity: str
    file_path: str
    start_line: int
    end_line: int
    message: str
    status: str = STATUS_PENDING
    verdict: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- SARIF import -------------------------------------------------------------
def parse_sarif(text: str) -> list[dict[str, Any]]:
    """Extract normalized findings from a SARIF 2.x document."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"SARIF is not valid JSON: {exc}") from exc
    runs = doc.get("runs") if isinstance(doc, dict) else None
    if not isinstance(runs, list):
        raise ValidationError("not a SARIF document (missing 'runs')")

    out: list[dict[str, Any]] = []
    for run in runs:
        tool = "unknown"
        rules: dict[str, dict[str, Any]] = {}
        driver = (((run.get("tool") or {}).get("driver")) or {})
        tool = driver.get("name") or tool
        for rule in driver.get("rules") or []:
            rid = rule.get("id")
            if rid:
                rules[rid] = rule
        for result in run.get("results") or []:
            rule_id = str(result.get("ruleId") or "")
            rule_meta = rules.get(rule_id, {})
            cwe = ""
            haystack = json.dumps(rule_meta.get("properties") or {}) + \
                str(rule_meta.get("helpUri") or "")
            mcwe = _CWE_RE.search(haystack) or _URI_CWE_RE.search(haystack)
            if mcwe:
                cwe = f"CWE-{mcwe.group(1)}"
            loc = ((result.get("locations") or [{}])[0]
                   .get("physicalLocation") or {})
            art = loc.get("artifactLocation") or {}
            region = loc.get("region") or {}
            out.append({
                "tool": str(tool),
                "rule_id": rule_id,
                "cwe": cwe,
                "severity": str(result.get("level") or "warning"),
                "file_path": str(art.get("uri") or ""),
                "start_line": int(region.get("startLine") or 0),
                "end_line": int(region.get("endLine")
                                or region.get("startLine") or 0),
                "message": str((result.get("message") or {}).get("text") or ""),
            })
    return out


# --- deterministic adjudicator ------------------------------------------------
class HeuristicAdjudicator:
    """Offline stand-in for an LLM reviewer: signal-matching verdicts."""

    name = "heuristic-signals"

    def adjudicate(self, finding: FindingRecord,
                   *, root: Path | None = None) -> dict[str, Any]:
        evidence = self._evidence(finding, root)
        signals = {
            "sink": False, "source": False, "sanitizer": False,
            "flow_in_message": False,
        }
        family = _family(finding.cwe) if finding.cwe else None
        sinks = _SINKS.get(family, ()) if family else \
            tuple(kw for kws in _SINKS.values() for kw in kws)

        blob_evidence = evidence.lower()
        blob_message = finding.message.lower()
        signals["sink"] = any(k in blob_evidence or k in blob_message
                              for k in sinks)
        signals["source"] = any(s in blob_evidence or s in blob_message
                                for s in _SOURCES)
        signals["sanitizer"] = any(s in blob_evidence for s in _SANITIZERS)
        signals["flow_in_message"] = bool(
            re.search(r"(flows?|reaches|taint)", blob_message))

        score = 0
        score += 45 if signals["sink"] else 0
        score += 30 if signals["source"] else 0
        score += 15 if signals["flow_in_message"] else 0
        score -= 55 if signals["sanitizer"] else 0
        score = max(0, min(100, score))

        if signals["sanitizer"]:
            verdict = STATUS_DISMISSED
            rationale = "mitigation signal near the reported path"
        elif score >= 60 or (signals["sink"] and signals["source"]):
            verdict = STATUS_CONFIRMED
            rationale = "sink and taint-source signals present"
        elif score >= 30:
            verdict = STATUS_PENDING
            rationale = "weak signals only; needs manual review"
        else:
            verdict = STATUS_PENDING
            rationale = "insufficient context to adjudicate"

        return {"adjudicator": self.name, "verdict": verdict,
                "confidence": score, "rationale": rationale,
                "signals": signals}

    def _evidence(self, finding: FindingRecord,
                  root: Path | None) -> str:
        path = (root / finding.file_path) if root else Path(finding.file_path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        lines = text.splitlines()
        start = max(0, finding.start_line - 4)
        end = min(len(lines), max(finding.end_line, finding.start_line) + 4)
        return "\n".join(lines[start:end])


# --- store ---------------------------------------------------------------------
class FindingsStore:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def _rel(self, fid: str) -> str:
        return f"findings/{fid}.json"

    def save(self, rec: FindingRecord) -> None:
        self.ws.write_json(self._rel(rec.id), rec.to_dict())

    def get(self, fid: str) -> FindingRecord:
        if not self.ws.path(self._rel(fid)).exists():
            raise NotFoundError(f"finding '{fid}' not found")
        return FindingRecord(**self.ws.read_json(self._rel(fid)))

    def list(self, *, status: str | None = None) -> list[FindingRecord]:
        out = [FindingRecord(**r) for r in self.ws.list_json("findings")]
        if status:
            out = [f for f in out if f.status == status]
        return sorted(out, key=lambda f: (f.file_path, f.rule_id, f.id))


class FindingsPipeline:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.store = FindingsStore(workspace)

    def import_sarif(self, sarif_text: str, *,
                     default_tool: str | None = None,
                     dedupe: bool = True) -> dict[str, Any]:
        parsed = parse_sarif(sarif_text)
        now = now_iso()
        added = skipped = duplicates = 0
        existing = {sha256_text(f"{f.tool}|{f.rule_id}|{f.file_path}|"
                                f"{f.start_line}|{f.message}")
                    for f in self.store.list()}
        for item in parsed:
            tool = default_tool or item["tool"]
            key = sha256_text(f"{tool}|{item['rule_id']}|{item['file_path']}|"
                              f"{item['start_line']}|{item['message']}")
            if dedupe and key in existing:
                duplicates += 1
                continue
            existing.add(key)
            rec = FindingRecord(
                id=make_id("finding", key),
                tool=tool, rule_id=item["rule_id"], cwe=item["cwe"],
                severity=item["severity"], file_path=item["file_path"],
                start_line=item["start_line"], end_line=item["end_line"],
                message=item["message"], status=STATUS_PENDING,
                created_at=now)
            self.store.save(rec)
            added += 1
        return {"imported": added, "skipped_malformed": skipped,
                "duplicates": duplicates, "total_seen": len(parsed)}

    def adjudicate_all(self, *, root: Path | None = None,
                       adjudicator=None) -> list[FindingRecord]:
        adjudicator = adjudicator or HeuristicAdjudicator()
        touched = []
        for rec in self.store.list(status=STATUS_PENDING):
            verdict = adjudicator.adjudicate(rec, root=root)
            rec.verdict = verdict
            rec.status = verdict["verdict"]
            self.store.save(rec)
            touched.append(rec)
        return touched

    def override(self, fid: str, status: str, reason: str = "") -> FindingRecord:
        if status not in (STATUS_CONFIRMED, STATUS_DISMISSED):
            raise ValidationError(
                "override status must be 'confirmed' or 'dismissed'")
        rec = self.store.get(fid)
        rec.status = status
        rec.verdict = {"adjudicator": "manual", "verdict": status,
                       "confidence": 100, "rationale": reason}
        self.store.save(rec)
        return rec

    def objectives(self) -> list[dict[str, Any]]:
        """Confirmed findings as directed-fuzzing objectives."""
        return [{"finding_id": f.id, "cwe": f.cwe, "file": f.file_path,
                 "line": f.start_line, "rule": f.rule_id}
                for f in self.store.list(status=STATUS_CONFIRMED)]
