"""Known-CVE patch-regression validation.

This module manages a workspace-local registry of **already-public** vulnerability
regression inputs (published advisories, vendor write-ups, or mock analogs) and
re-runs them against registered research targets to verify that:

- ``vulnerable`` targets still exhibit the historical defect (the input crashes), and
- ``fixed`` targets no longer do (the input is cleanly accepted/rejected).

It exists for **patch validation in an authorized lab**: confirming a fix works
and detecting regressions. It does not generate exploit code, weaponize inputs,
or target anything beyond targets explicitly registered in this framework.

Registry layout (workspace-relative)::

    known-cve/registry.json   # {"schema": 1, "entries": [...]}

Each entry::

    {
      "id": "CVE-2024-1234",
      "title": "...",
      "reference": "https://...",
      "note": "...",
      "input_hex": "...",          # small PoC input, <= MAX_INPUT_BYTES
      "sha256": "...",             # integrity hash of the decoded input
      "vulnerable_targets": ["mock:parser"],   # must crash
      "fixed_targets": ["mock:parser-v2"],     # must stay clean
      "added_at": "...",
      "last_validated": "",        # ISO timestamp of last validate run
      "last_result": ""            # pass | fail | skipped
    }
"""

from __future__ import annotations

import binascii
import re
from dataclasses import dataclass, field, asdict
from typing import Any

from .clock import now_iso
from .errors import NotFoundError, StateError, ValidationError
from .hashing import sha256_bytes
from .targets.base import Outcome
from .workspace import Workspace

SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 4096

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_SKIPPED = "skipped"


@dataclass
class CveEntry:
    id: str
    title: str
    input_hex: str
    sha256: str
    vulnerable_targets: list[str] = field(default_factory=list)
    fixed_targets: list[str] = field(default_factory=list)
    reference: str = ""
    note: str = ""
    added_at: str = ""
    last_validated: str = ""
    last_result: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def input_bytes(self) -> bytes:
        return bytes.fromhex(self.input_hex)


def _validate_id(cve_id: str) -> None:
    if not _ID_RE.match(cve_id):
        raise ValidationError(
            f"invalid CVE identifier '{cve_id}' (use e.g. CVE-2024-1234 "
            f"or MOCK-OOBREAD-001)")


def decode_input_hex(input_hex: str) -> bytes:
    """Decode and bound-check a hex-encoded regression input."""
    if not isinstance(input_hex, str) or not input_hex.strip():
        raise ValidationError("input_hex must be a non-empty hex string")
    compact = "".join(input_hex.split())
    try:
        data = bytes.fromhex(compact)
    except (ValueError, binascii.Error):
        raise ValidationError("input_hex is not valid hexadecimal") from None
    if len(data) > MAX_INPUT_BYTES:
        raise ValidationError(
            f"regression input exceeds {MAX_INPUT_BYTES} bytes")
    return data


class CveRegistry:
    """Workspace-persisted registry of known-CVE regression entries."""

    def __init__(self, workspace: Workspace):
        self.ws = workspace

    @staticmethod
    def _rel() -> str:
        return "known-cve/registry.json"

    # persistence ---------------------------------------------------------
    def load(self) -> dict[str, Any]:
        path = self.ws.path(self._rel())
        if not path.exists():
            return {"schema": SCHEMA_VERSION, "entries": []}
        doc = self.ws.read_json(self._rel())
        if not isinstance(doc, dict) \
                or doc.get("schema") != SCHEMA_VERSION \
                or not isinstance(doc.get("entries"), list):
            raise StateError(
                "known-cve registry is corrupt or from an incompatible "
                "version")
        return doc

    def save(self, doc: dict[str, Any]) -> None:
        self.ws.write_json(self._rel(), doc)

    # entry management ----------------------------------------------------
    def entries(self) -> list[CveEntry]:
        doc = self.load()
        out = []
        for raw in doc["entries"]:
            try:
                out.append(CveEntry(**raw))
            except TypeError:
                raise StateError(
                    "known-cve registry contains an incompatible entry",
                    details={"keys": sorted(raw)}) from None
        return out

    def get(self, cve_id: str) -> CveEntry:
        for entry in self.entries():
            if entry.id == cve_id:
                return entry
        raise NotFoundError(f"CVE entry '{cve_id}' not found in registry")

    def add(self, *, cve_id: str, title: str, input_data: bytes,
            vulnerable_targets: list[str], fixed_targets: list[str],
            reference: str = "", note: str = "") -> CveEntry:
        _validate_id(cve_id)
        if len(input_data) > MAX_INPUT_BYTES:
            raise ValidationError(
                f"regression input exceeds {MAX_INPUT_BYTES} bytes")
        if not vulnerable_targets and not fixed_targets:
            raise ValidationError(
                "list at least one vulnerable or fixed target")
        if self.exists(cve_id):
            raise StateError(f"CVE entry '{cve_id}' already exists")
        entry = CveEntry(
            id=cve_id, title=title, input_hex=input_data.hex(),
            sha256=sha256_bytes(input_data),
            vulnerable_targets=list(vulnerable_targets),
            fixed_targets=list(fixed_targets),
            reference=reference, note=note, added_at=now_iso())
        doc = self.load()
        doc["entries"].append(entry.to_dict())
        self.save(doc)
        return entry

    def remove(self, cve_id: str) -> None:
        doc = self.load()
        before = len(doc["entries"])
        doc["entries"] = [e for e in doc["entries"]
                          if e.get("id") != cve_id]
        if len(doc["entries"]) == before:
            raise NotFoundError(f"CVE entry '{cve_id}' not found in registry")
        self.save(doc)

    def exists(self, cve_id: str) -> bool:
        return any(e.id == cve_id for e in self.entries())

    def update_status(self, cve_id: str, status: str) -> None:
        doc = self.load()
        for raw in doc["entries"]:
            if raw.get("id") == cve_id:
                raw["last_validated"] = now_iso()
                raw["last_result"] = status
                self.save(doc)
                return
        raise NotFoundError(f"CVE entry '{cve_id}' not found in registry")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_entry(entry: CveEntry) -> dict[str, Any]:
    """Run one regression entry against its declared targets.

    Deterministic: outcomes depend only on the input bytes and target
    implementations. Returns a per-target report plus an overall ``passed``
    verdict; never raises for mismatched outcomes (that is the result).
    """
    from . import targets as target_registry

    data = entry.input_bytes()
    results: list[dict[str, Any]] = []
    passed = True

    def run_one(target_id: str, expect_crash: bool) -> None:
        nonlocal passed
        row: dict[str, Any] = {
            "target": target_id,
            "expectation": "crash" if expect_crash else "clean",
        }
        if not target_registry.is_registered(target_id):
            row.update(status=STATUS_SKIPPED,
                       detail="target not registered in this framework")
            passed = False
            results.append(row)
            return
        target = target_registry.create(target_id)
        res = target.execute(data)
        crashed = res.outcome == Outcome.CRASH
        ok = crashed == expect_crash
        passed = passed and ok
        signature = res.diagnostics.signature if res.diagnostics else ""
        classification = res.diagnostics.classification_hint \
            if res.diagnostics else ""
        row.update(status=STATUS_PASS if ok else STATUS_FAIL,
                   observed=res.outcome,
                   signature=signature,
                   classification=classification)
        results.append(row)

    for target_id in entry.vulnerable_targets:
        run_one(target_id, expect_crash=True)
    for target_id in entry.fixed_targets:
        run_one(target_id, expect_crash=False)

    return {"id": entry.id, "title": entry.title,
            "sha256": entry.sha256, "input_size": len(data),
            "passed": passed, "targets": results}


# ---------------------------------------------------------------------------
# Built-in mock-analog catalog
# ---------------------------------------------------------------------------

def _mock_record(version: int, rtype: int, declared: int,
                 payload: bytes) -> bytes:
    return b"MOCK" + bytes([version, rtype]) \
        + declared.to_bytes(2, "big") + payload


def builtin_catalog() -> list[dict[str, Any]]:
    """Documented mock-analog regression cases shipped with the framework.

    These map *defect classes* documented in public advisories onto the mock
    parser's deterministic defect rules, so the patch-validation workflow can
    be exercised without any real vendor PoC material. They are training
    analogs, not real exploit inputs.
    """
    return [
        {
            "id": "MOCK-NULLDISPATCH-001",
            "title": "Analog: unvalidated record type leads to null dispatch",
            "rationale": "Mirrors the class of 'missing handler validation' "
                         "bugs common in parser advisories.",
            "vulnerable": ["mock:parser"],
            "fixed": ["mock:parser-v2"],
            "input": _mock_record(1, 0xFF, 2, b"ok"),
        },
        {
            "id": "MOCK-ASSERT-001",
            "title": "Analog: reserved type triggers reachable assertion",
            "rationale": "Assertion-reachable-from-input is a documented "
                         "denial-of-service advisory class.",
            "vulnerable": ["mock:parser"],
            "fixed": ["mock:parser-v2"],
            "input": _mock_record(1, 0x7E, 2, b"ok"),
        },
        {
            "id": "MOCK-V2OOBWRITE-001",
            "title": "Analog: version-gated unchecked write (v2 regression)",
            "rationale": "Demonstrates regression detection: a fix release "
                         "that introduces a new memory-safety defect.",
            "vulnerable": ["mock:parser-v2"],
            "fixed": [],
            "input": _mock_record(2, 0x01, 2, b"x"),
        },
    ]


def install_builtin_catalog(registry: CveRegistry,
                            *, overwrite: bool = False) -> list[str]:
    """Register the built-in mock analogs into a workspace registry."""
    added: list[str] = []
    for spec in builtin_catalog():
        if not overwrite and registry.exists(spec["id"]):
            continue
        if registry.exists(spec["id"]):
            registry.remove(spec["id"])
        registry.add(
            cve_id=spec["id"], title=spec["title"],
            input_data=spec["input"],
            vulnerable_targets=spec["vulnerable"],
            fixed_targets=spec["fixed"],
            reference="docs/CVE-REGRESSION.md",
            note=f"built-in mock analog. {spec['rationale']}")
        added.append(spec["id"])
    return added
