"""Offline supply-chain vetting for research dependencies (#72).

Three fully offline checks over Python dependencies the research pipeline
pulls in: requirements auditing (pin and hash hygiene), static behavioral
scanning of a package tree for risky call patterns, and lockfile drift
verification via SHA-256. No network access, no package installation.
"""

from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from .clock import now_iso
from .errors import NotFoundError, ValidationError
from .hashing import sha256_bytes, sha256_text, canonical_json
from .ids import make_id
from .workspace import Workspace

_PRUNE_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__",
               ".ios-research"}

_OBFUSCATION_MIN_LEN = 200

# Dotted callee -> reason. Static signal only; presence is not proof of abuse.
RISKY_CALLS: dict[str, str] = {
    "socket.socket": "raw socket creation",
    "subprocess.run": "subprocess execution",
    "subprocess.call": "subprocess execution",
    "subprocess.Popen": "subprocess execution",
    "os.system": "shell command execution",
    "os.popen": "shell command execution",
    "eval": "dynamic code evaluation",
    "exec": "dynamic code execution",
    "ctypes.CDLL": "native library loading",
    "urllib.request.urlopen": "network fetch",
    "requests.get": "network fetch",
    "requests.post": "network exfiltration-capable upload",
}

_HIGH_RISK_CALLS = {"socket.socket", "subprocess.run", "subprocess.call",
                    "subprocess.Popen", "os.system", "os.popen", "eval",
                    "exec", "ctypes.CDLL"}


# --- requirements parsing -------------------------------------------------------
def parse_requirements(text: str) -> dict[str, Any]:
    """Parse requirements.txt-style text into normalized entries.

    Blank lines and ``#`` comments are ignored; ``--`` option lines are
    counted under ``options``. Entries carry the lowercased distribution name,
    its version spec (markers/extras stripped), pin and hash flags. Lines with
    no recognizable name are counted in ``skipped``.
    """
    entries: list[dict[str, Any]] = []
    skipped = options = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            options += 1
            continue
        # strip environment markers / per-requirement options after ';'
        line = line.split(";", 1)[0].strip()
        if not line:
            continue
        match = _REQ_RE.match(line)
        if match is None:
            skipped += 1
            continue
        tokens = [t for t in match.group(2).split()
                  if not t.startswith("--")]
        spec = "".join(tokens)
        entries.append({
            "name": match.group(1).lower(),
            "spec": spec,
            "pinned": spec.startswith("=="),
            "hashes": "--hash=" in raw.lower(),
        })
    return {"entries": entries, "options": options, "skipped": skipped}


# distribution name, optional extras, then the constraint tail
_REQ_RE = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
                     r"(?:\[[^\]]*\])?\s*(.*)$")


def audit_requirements(text: str) -> dict[str, Any]:
    """Audit requirement hygiene: pins, hashes, risk classification."""
    parsed = parse_requirements(text)
    entries = parsed["entries"]
    total = len(entries)
    unpinned = [e["name"] for e in entries if not e["pinned"]]
    hashed = sum(1 for e in entries if e["hashes"])
    pct = int(round(100 * len(unpinned) / total)) if total else 0
    if unpinned:
        risk = "high"
    elif total and hashed < total:
        risk = "medium"
    else:
        risk = "low"
    return {"total": total, "pinned": total - len(unpinned),
            "unpinned": sorted(unpinned), "hashed": hashed,
            "unpinned_pct": pct, "skipped": parsed["skipped"],
            "risk": risk}


# --- behavioral scan --------------------------------------------------------------
def _dotted_name(node: ast.AST) -> str | None:
    """Resolve a Name/Attribute chain to its dotted source form."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class _BehaviorVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[dict[str, Any]] = []

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func)
        if dotted in RISKY_CALLS:
            self.findings.append({"kind": "risky-call", "call": dotted,
                                  "line": node.lineno,
                                  "reason": RISKY_CALLS[dotted]})
        elif (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Call)
                and _dotted_name(node.func.value.func) == "getattr"):
            self.findings.append({"kind": "dynamic-attr", "call": "getattr",
                                  "line": node.lineno,
                                  "reason": "attribute resolved via getattr"})
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if (isinstance(value, str) and len(value) >= _OBFUSCATION_MIN_LEN
                and value.isprintable()):
            self.findings.append({"kind": "obfuscation", "line": node.lineno,
                                  "reason": f"large string literal "
                                            f"({len(value)} chars)"})
        self.generic_visit(node)


def scan_behavior(root_path: str | os.PathLike, *, max_files: int = 500,
                  max_bytes: int = 524288) -> dict[str, Any]:
    """Statically scan ``*.py`` files under ``root`` for risky patterns.

    Deterministic sorted walk; prunes vendored/build directories; stops after
    ``max_files`` files (recording ``truncated``); skips files larger than
    ``max_bytes`` bytes.
    """
    root = Path(root_path)
    py_files: list[Path] = []
    truncated = False
    stack = [root]
    while stack and not truncated:
        current = stack.pop()
        children = sorted(current.iterdir(), key=lambda p: p.name)
        dirs = []
        for child in children:
            if child.is_dir():
                if child.name not in _PRUNE_DIRS:
                    dirs.append(child)
            elif child.suffix == ".py":
                if len(py_files) >= max_files:
                    truncated = True
                    break
                py_files.append(child)
        stack.extend(reversed(dirs))

    findings: list[dict[str, Any]] = []
    syntax_errors = 0
    files_scanned = 0
    for path in py_files:
        try:
            if path.stat().st_size > max_bytes:
                continue
            source = path.read_bytes()
        except OSError:
            continue
        try:
            tree = ast.parse(source.decode("utf-8", errors="replace"),
                             filename=str(path))
        except SyntaxError:
            syntax_errors += 1
            continue
        files_scanned += 1
        visitor = _BehaviorVisitor()
        visitor.visit(tree)
        rel = path.relative_to(root).as_posix()
        for finding in visitor.findings:
            findings.append({"file": rel, **finding})

    findings.sort(key=lambda f: (f["file"], f["line"], f.get("call", "")))
    by_kind: dict[str, int] = {}
    for finding in findings:
        by_kind[finding["kind"]] = by_kind.get(finding["kind"], 0) + 1
    high = any(f["kind"] == "risky-call" and f["call"] in _HIGH_RISK_CALLS
               for f in findings)
    risk = "high" if high else ("medium" if findings else "low")
    return {"files_scanned": files_scanned, "truncated": truncated,
            "syntax_errors": syntax_errors, "findings": findings,
            "by_kind": by_kind, "risk": risk}


# --- lockfile verification ---------------------------------------------------------
def verify_lock(lock_path: str | os.PathLike,
                root_path: str | os.PathLike) -> dict[str, Any]:
    """Verify a JSON lockfile of SHA-256s against files on disk.

    The lockfile format is ``{"files": [{"path": <relative>, "sha256": <hex>}]}``.
    Missing lockfile raises :class:`NotFoundError`; missing or modified files
    are reported rather than raised.
    """
    lock = Path(lock_path)
    root = Path(root_path)
    if not lock.exists():
        raise NotFoundError(f"lockfile not found: {lock}")
    try:
        doc = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"lockfile is not valid JSON: {exc}") from exc
    files = doc.get("files") if isinstance(doc, dict) else None
    if not isinstance(files, list):
        raise ValidationError("lockfile must contain a 'files' array")

    drifted: list[dict[str, Any]] = []
    missing: list[str] = []
    for entry in files:
        rel = str(entry.get("path") or "")
        expected = str(entry.get("sha256") or "")
        target = root / rel
        if not target.is_file():
            missing.append(rel)
            continue
        actual = sha256_bytes(target.read_bytes())
        if actual != expected:
            drifted.append({"path": rel, "expected": expected,
                            "actual": actual})
    checked = len(files)
    return {"verified": checked == 0 or not (drifted or missing),
            "checked": checked, "drifted": sorted(drifted,
                                                  key=lambda d: d["path"]),
            "missing": sorted(missing)}


# --- record + store ------------------------------------------------------------------
@dataclass
class SupplyRecord:
    id: str
    kind: str
    target: str
    created_at: str
    result: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SupplyStore:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def create(self, kind: str, target: str,
               result: dict[str, Any]) -> SupplyRecord:
        rec = SupplyRecord(
            id=make_id("supply", kind, target,
                       sha256_text(canonical_json(result))),
            kind=kind, target=target, created_at=now_iso(), result=result)
        self.save(rec)
        return rec

    def save(self, rec: SupplyRecord) -> None:
        self.ws.write_json(f"supply/{rec.id}.json", rec.to_dict())

    def get(self, record_id: str) -> SupplyRecord:
        if not self.ws.path(f"supply/{record_id}.json").exists():
            raise NotFoundError(f"supply record '{record_id}' not found")
        return SupplyRecord(**self.ws.read_json(f"supply/{record_id}.json"))

    def list(self) -> list[SupplyRecord]:
        out = [SupplyRecord(**r) for r in self.ws.list_json("supply")]
        return sorted(out, key=lambda r: (r.created_at, r.id))
