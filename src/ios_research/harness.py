"""LLM-assisted fuzz harness generation.

Generates candidate fuzz drivers for a registered target, validates them, and
tracks their review state in the workspace. The default provider is a
deterministic template generator derived from the target's own metadata, so
campaigns stay reproducible without network access or model calls. A
:class:`FileProposalProvider` ingests externally produced proposals (e.g. from
an LLM) as JSON, keeping the same validation and audit trail.

Safety: generated code is validated structurally and by ``compile()`` always;
it is *executed* only when an explicit ``--smoke`` opt-in is supplied, only
against the framework's own registered targets, and always inside a disposable
child process (``ios_research.harness_runner``) so an untrusted candidate
cannot corrupt or crash the framework process. Child isolation reduces blast
radius but is not a sandbox; proposals are trusted-input artifacts (SECURITY.md).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any

from . import targets
from .clock import now_iso
from .errors import NotFoundError, ValidationError
from .ids import make_id
from .workspace import Workspace

STATUS_PROPOSED = "proposed"
STATUS_VALIDATED = "validated"
STATUS_ACCEPTED = "accepted"
STATUS_REJECTED = "rejected"

_TRANSITIONS = {
    STATUS_PROPOSED: {STATUS_VALIDATED, STATUS_REJECTED},
    STATUS_VALIDATED: {STATUS_ACCEPTED, STATUS_REJECTED},
    STATUS_ACCEPTED: set(),
    STATUS_REJECTED: set(),
}


# --- providers ---------------------------------------------------------------
class TemplateProvider:
    """Deterministic proposal source built from target metadata."""

    name = "deterministic-template"

    _DRIVER_TMPL = (
        '"""Generated fuzz driver for target {tid} ({kind})."""\n'
        "\n"
        "from ios_research import targets\n"
        "\n"
        "\n"
        "def fuzz(data: bytes) -> str:\n"
        '    """Execute one prepared input against the {tid} target."""\n'
        "{body}"
        "    result = targets.create(\"{tid}\").execute(data)\n"
        "    return result.outcome\n"
    )

    def propose(self, target_desc: dict[str, Any],
                max_candidates: int) -> list[dict[str, str]]:
        tid = target_desc["id"]
        variants = [
            ("whole_buffer",
             "Driver passes the raw buffer straight through to the target.",
             "    prepared = data\n"),
            ("header_fielding",
             "Driver splits a leading header region from the payload so "
             "mutations land in body bytes independently of framing.",
             "    header, payload = data[:8], data[8:]\n"
             "    prepared = header + payload\n"),
            ("dictionary_seeded",
             "Driver substitutes boundary byte values at fixed probe offsets "
             "to reach parser edge cases quickly.",
             "    prepared = bytearray(data or b'\\x00')\n"
             "    for offset in range(0, len(prepared), max(1, len(prepared) // 4)):\n"
             "        prepared[offset] = prepared[offset] & 0xFF ^ 0xFF \\\n"
             "            if prepared[offset] in (0x00, 0xFF) else 0x00\n"
             "    prepared = bytes(prepared)\n"),
        ]
        out = []
        for kind, rationale, body in variants[:max(1, max_candidates)]:
            out.append({
                "kind": kind,
                "rationale": rationale,
                "code": self._DRIVER_TMPL.format(tid=tid, kind=kind, body=body),
            })
        return out[:max_candidates]


class FileProposalProvider:
    """Load proposals written by an external generator (e.g. an LLM).

    The file must contain a JSON array of objects with ``kind``, ``code`` and
    optionally ``rationale``. Proposals are treated as untrusted text: they are
    compiled during validation but never executed unless ``--smoke`` is given.
    """

    name = "file"

    def __init__(self, path: str):
        self.path = path

    def propose(self, target_desc: dict[str, Any],
                max_candidates: int) -> list[dict[str, str]]:
        try:
            raw = json.loads(open(self.path, encoding="utf-8").read())
        except OSError as exc:
            raise NotFoundError(f"cannot read proposals file: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ValidationError(f"proposals file is not valid JSON: {exc}") from exc
        if not isinstance(raw, list):
            raise ValidationError("proposals file must contain a JSON array")
        out = []
        for item in raw[:max_candidates]:
            if not isinstance(item, dict) or not item.get("code"):
                continue
            out.append({
                "kind": str(item.get("kind") or "external"),
                "rationale": str(item.get("rationale") or ""),
                "code": str(item["code"]),
            })
        return out


_PROVIDERS = {
    TemplateProvider.name: TemplateProvider,
}


def create_provider(name: str, *, path: str | None = None):
    if name == FileProposalProvider.name:
        if not path:
            raise ValidationError("the 'file' provider requires --proposals-path")
        return FileProposalProvider(path)
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise ValidationError(
            f"unknown provider '{name}'; known: {', '.join(sorted(_PROVIDERS))}, "
            f"{FileProposalProvider.name}")
    return cls()


# --- validation --------------------------------------------------------------
def validate_code(code: str) -> dict[str, Any]:
    """Structural + syntax validation. Never executes the code."""
    problems: list[str] = []
    if not code or not code.strip():
        problems.append("empty source")
    if "def fuzz(" not in code:
        problems.append("missing entry point 'fuzz('")
    try:
        compile(code, "<generated-harness>", "exec")
    except SyntaxError as exc:
        problems.append(f"syntax error: {exc.msg} (line {exc.lineno})")
    return {"ok": not problems, "problems": problems}


def smoke_run(code: str, target_id: str, *,
              timeout_s: float = 15.0) -> dict[str, Any]:
    """Execute the driver once against a seed input of its own target.

    Generated code is untrusted, so it runs in a disposable child process
    (``ios_research.harness_runner``) instead of this process: a crashing,
    exiting, or state-corrupting candidate cannot take the framework down.
    The child still runs with the researcher's privileges — isolation is not
    a sandbox (see SECURITY.md).
    """
    import os
    import subprocess
    import sys

    request = json.dumps({"code": code, "target_id": target_id})
    env = dict(os.environ)
    pkg_root = str(__import__("pathlib").Path(
        __file__).resolve().parent.parent)
    env["PYTHONPATH"] = os.pathsep.join(
        [pkg_root] + ([env["PYTHONPATH"]]
                      if env.get("PYTHONPATH") else [])).lstrip(os.pathsep)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "ios_research.harness_runner"],
            input=request.encode("utf-8"),
            capture_output=True, timeout=timeout_s, env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False,
                "error": f"smoke run exceeded {timeout_s:g}s and was killed"}
    except OSError as exc:
        return {"ok": False, "error": f"could not spawn runner: {exc}"}

    if proc.returncode != 0:
        detail = f"exit code {proc.returncode}"
        if proc.stderr:
            tail = proc.stderr.decode("utf-8", "replace").strip()[-200:]
            detail = f"{detail}: {tail}" if tail else detail
        return {"ok": False, "error": f"runner terminated ({detail})"}
    # Only trust a JSON object emitted by the runner; generated code may have
    # printed arbitrary bytes before it, including on the same line.
    stdout = proc.stdout.decode("utf-8", "replace")[-65536:]
    start = stdout.rfind("{")
    while start >= 0:
        try:
            verdict = json.loads(stdout[start:])
        except json.JSONDecodeError:
            start = stdout.rfind("{", 0, start)
            continue
        if isinstance(verdict, dict) and {"ok"} <= set(verdict):
            return verdict
        start = stdout.rfind("{", 0, start)
    return {"ok": False, "error": "runner produced no parsable verdict"}


# --- store -------------------------------------------------------------------
@dataclass
class HarnessCandidate:
    id: str
    target: str
    provider: str
    kind: str
    code: str
    rationale: str
    status: str
    validation: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HarnessStore:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def _rel(self, candidate_id: str) -> str:
        return f"harnesses/{candidate_id}.json"

    def save(self, cand: HarnessCandidate) -> None:
        self.ws.write_json(self._rel(cand.id), cand.to_dict())

    def get(self, candidate_id: str) -> HarnessCandidate:
        rel = self._rel(candidate_id)
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"harness candidate '{candidate_id}' not found")
        return HarnessCandidate(**self.ws.read_json(rel))

    def list(self, *, status: str | None = None) -> list[HarnessCandidate]:
        out = [HarnessCandidate(**rec) for rec in self.ws.list_json("harnesses")]
        if status:
            out = [c for c in out if c.status == status]
        return sorted(out, key=lambda c: (c.created_at, c.id))


# --- generation --------------------------------------------------------------
class HarnessGenerator:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.store = HarnessStore(workspace)

    def generate(self, *, target_id: str, provider, max_candidates: int,
                 smoke: bool = False) -> list[HarnessCandidate]:
        try:
            desc = next(t for t in targets.list_targets()
                        if t["id"] == target_id)
        except StopIteration:
            raise NotFoundError(f"unknown target '{target_id}'")
        proposals = provider.propose(desc, max_candidates)
        if not proposals:
            raise ValidationError("provider produced no usable proposals")

        created: list[HarnessCandidate] = []
        for idx, prop in enumerate(proposals):
            cand_id = make_id("harness", target_id, provider.name,
                              prop["kind"], prop["code"])
            validation = validate_code(prop["code"])
            if smoke and validation["ok"]:
                validation["smoke"] = smoke_run(prop["code"], target_id)
            status = STATUS_VALIDATED if validation["ok"] else STATUS_REJECTED
            cand = HarnessCandidate(
                id=cand_id, target=target_id, provider=provider.name,
                kind=prop["kind"], code=prop["code"],
                rationale=prop.get("rationale", ""), status=status,
                validation=validation, created_at=now_iso())
            self.store.save(cand)
            created.append(cand)
        return created

    def transition(self, candidate_id: str, action: str,
                   *, reason: str = "") -> HarnessCandidate:
        cand = self.store.get(candidate_id)
        target_status = STATUS_REJECTED if action == "reject" else STATUS_ACCEPTED
        if action not in ("accept", "reject"):
            raise ValidationError(f"unknown harness action '{action}'")
        if target_status == STATUS_ACCEPTED and cand.status != STATUS_VALIDATED:
            raise ValidationError(
                f"candidate '{candidate_id}' must be validated before acceptance "
                f"(status: {cand.status})")
        if target_status not in _TRANSITIONS[cand.status]:
            raise ValidationError(
                f"candidate '{candidate_id}' in status '{cand.status}' cannot "
                f"transition to '{target_status}'")
        cand.status = target_status
        if reason:
            cand.validation["review_reason"] = reason
        self.store.save(cand)
        return cand
