"""External fuzzer-engine adapters and artifact ingestion (#48).

Teams already run libFuzzer, AFL++, or Honggfuzz against their own authorized
targets. This module ingests those engines' *output* into ios-research's
triage pipeline through a neutral, versioned manifest:

```json
{
  "schema_version": 1,
  "engine": "libfuzzer",
  "command": "./fuzzer corpus -runs=1000",
  "target": "mac:imageio",
  "stats": {"runs": 100000},
  "artifacts": [
    {"kind": "crash", "path": "crash-oobs", "sha256": "...",
     "stderr_log": "oobs.log"}
  ]
}
```

* Paths resolve relative to the manifest file; every copied artifact lands at
  a content-addressed workspace path computed by *this* module, so hostile
  names cannot escape the workspace.
* Hashes verify before anything is recorded.
* Crash artifacts are reproduced through the declared target when available
  and normalized into the standard crash pipeline; when the target is not
  available the raw sanitizer report is still classified and stored as an
  explicitly ``unverified`` imported finding.
* Provenance (engine name, command, source) is preserved on every record so
  equivalent findings from different engines stay attributable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import targets
from .clock import now_iso
from .errors import NotFoundError, ValidationError
from .hashing import sha256_bytes
from .ids import make_id
from .sanitizers import detect_sanitizers, triage_report
from .workspace import Workspace

IMPORT_SCHEMA_VERSION = 1
KNOWN_KINDS = ("crash", "corpus", "coverage")
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"cannot read manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValidationError("manifest must be a JSON object")
    if manifest.get("schema_version") != IMPORT_SCHEMA_VERSION:
        raise ValidationError(
            f"unsupported manifest schema_version "
            f"{manifest.get('schema_version')!r}; expected "
            f"{IMPORT_SCHEMA_VERSION}")
    if not isinstance(manifest.get("engine"), str) or not manifest["engine"]:
        raise ValidationError("manifest.engine must be a non-empty string")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValidationError("manifest.artifacts must be a list")
    return manifest


class EngineImporter:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.crash_store = None

    def _resolve(self, base: Path, relative: str) -> Path:
        candidate = (base / relative).resolve()
        if not candidate.is_file():
            raise NotFoundError(
                f"artifact not found: {relative} (resolved {candidate})")
        return candidate

    def _verified_bytes(self, base: Path, artifact: dict[str, Any],
                        key: str) -> bytes | None:
        rel = artifact.get(key)
        if not rel:
            return None
        hash_key = f"{key}_sha256" if key != "path" else "sha256"
        source = self._resolve(base, rel)
        blob = source.read_bytes()
        if len(blob) > MAX_ARTIFACT_BYTES:
            raise ValidationError(f"artifact exceeds size bound: {rel}")
        expected = artifact.get(hash_key)
        if expected is None:
            # A missing hash is itself malformed input: fail safely rather
            # than ingest unverified bytes.
            raise ValidationError(
                f"artifact '{rel}' has no {hash_key}; refusing to import")
        if sha256_bytes(blob) != expected:
            raise ValidationError(f"sha256 mismatch for artifact '{rel}'")
        return blob

    def import_manifest(self, manifest_path: str | Path, *,
                        target_id: str | None = None,
                        reproduce: bool = True) -> dict[str, Any]:
        from .crashes import CrashStore
        from .targets.base import Outcome

        manifest_path = Path(manifest_path)
        manifest = _load_manifest(manifest_path)
        base = manifest_path.resolve().parent
        target_id = target_id or manifest.get("target")

        experiment_id = make_import_experiment(manifest["engine"])
        crash_store = CrashStore(self.ws)

        imported = 0
        skipped = 0
        findings: list[dict[str, Any]] = []
        reproducible = 0
        unverified = 0

        executor = None
        if reproduce and target_id:
            if not targets.is_registered(target_id):
                raise NotFoundError(f"unknown target '{target_id}'")
            executor = targets.create(target_id)

        for artifact in manifest["artifacts"]:
            if not isinstance(artifact, dict):
                raise ValidationError("each artifact must be an object")
            kind = artifact.get("kind")
            if kind not in KNOWN_KINDS:
                raise ValidationError(
                    f"artifact kind must be one of {KNOWN_KINDS}")
            if kind != "crash":
                skipped += 1     # corpus/coverage handled by corpus importer
                continue
            blob = self._verified_bytes(base, artifact, "path")
            if blob is None:
                continue
            imported += 1

            log_blob = self._verified_bytes(base, artifact, "stderr_log")
            provenance = {
                "engine": manifest["engine"],
                "command": manifest.get("command", ""),
                "source": "external-import",
                "imported_at": now_iso(),
            }

            exec_result = None
            if executor is not None:
                from .targets.base import ExecResult
                exec_result = executor.execute(blob)

            if exec_result is not None and \
                    exec_result.outcome == Outcome.CRASH and \
                    exec_result.diagnostics is not None:
                crash = crash_store.record(
                    experiment_id=experiment_id,
                    target=target_id or "unknown",
                    fmt="external-artifact",
                    data=blob,
                    exec_result=exec_result,
                    lineage=dict(provenance, verified=True))
                reproducible += 1
                findings.append({"signature": crash.signature,
                                 "status": "reproduced"})
            else:
                text = (log_blob or b"").decode("utf-8", "replace")
                triage = triage_report(text) if text else {
                    "sanitizers": [], "violation_class": "UNKNOWN",
                    "dedup_signature": "none_unknown_"
                                       + sha256_bytes(blob)[:16]}
                record = {
                    "schema_version": IMPORT_SCHEMA_VERSION,
                    "id": make_id("importfinding", experiment_id,
                                  triage["dedup_signature"]),
                    "status": "unverified",
                    "reason": ("could not reproduce through declared target"
                               if executor is not None else
                               "no target declared; report-only import"),
                    "input_sha256": sha256_bytes(blob),
                    "provenance": provenance,
                    **triage,
                }
                self.ws.write_json(
                    f"findings/{record['id']}/import.json", record)
                unverified += 1
                findings.append({"id": record["id"],
                                 "status": "unverified"})

        result = {
            "schema_version": IMPORT_SCHEMA_VERSION,
            "engine": manifest["engine"],
            "experiment_id": experiment_id,
            "artifacts_total": len(manifest["artifacts"]),
            "crashes_imported": imported,
            "non_crash_artifacts_skipped": skipped,
            "reproduced": reproducible,
            "unverified": unverified,
            "findings": findings,
        }
        self.ws.write_json(f"research/import-{experiment_id}.json", result)
        return result


def make_import_experiment(engine: str) -> str:
    from .ids import make_id
    return make_id("experiment", "import", engine)


def write_libfuzzer_fixture(directory: Path, *, engine: str = "libfuzzer"
                            ) -> Path:
    """Create a deterministic two-engine-comparable fixture on disk."""
    directory.mkdir(parents=True, exist_ok=True)
    payload = b"OOB" + b"A" * 16
    log = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address "
        "0x602000000010 at pc 0x1 bp 0x2 sp 0x3\n"
        "READ of size 1 at 0x602000000010 thread T0\n"
        "    #0 0x1 in decode_frame frame.c:88\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow frame.c:88 in "
        "decode_frame\n")
    (directory / "crash-oobs").write_bytes(payload)
    (directory / "oobs.log").write_text(log, encoding="utf-8")
    manifest = {
        "schema_version": IMPORT_SCHEMA_VERSION,
        "engine": engine,
        "command": f"./{engine.lower()}_fuzzer corpus -runs=1000",
        "target": "",
        "stats": {"runs": 1000},
        "artifacts": [{
            "kind": "crash",
            "path": "crash-oobs",
            "sha256": sha256_bytes(payload),
            "stderr_log": "oobs.log",
            "stderr_log_sha256": sha256_bytes(log.encode("utf-8")),
        }],
    }
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2),
                             encoding="utf-8")
    return manifest_path
