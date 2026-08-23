"""Engine-neutral import of externally produced fuzzing artifacts (#48).

Brings findings from researcher-run external engines (libFuzzer, AFL++, ...) a
researcher already executed elsewhere into the local workspace so existing
deduplication, reproduction, minimization, and reporting tooling applies to
them unchanged.

Import is strictly opt-in and local: this module never invokes an external
executable, alters host security settings, or transmits data anywhere. All
manifest-referenced paths must resolve inside the manifest's directory
(malformed archives cannot escape into the rest of the workspace).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .errors import ValidationError
from .hashing import sha256_bytes
from .sanitizers import triage_report
from .targets.base import Diagnostics, ExecResult, Outcome

IMPORT_SCHEMA_VERSION = 1
MANIFEST_KIND = "engine-campaign"
MAX_FILE_BYTES = 64 * 1024 * 1024

#: Known engines get filename-derived metadata when no sanitizer log exists.
_LIBFUZZER_PREFIXES = {
    "crash-": ("crash", "UNKNOWN_CRASH"),
    "leak-": ("leak", "MEMORY_LEAK"),
    "oom-": ("oom", "RESOURCE_EXHAUSTION"),
    "timeout-": ("timeout", "TIMEOUT"),
}
_AFL_SIGNALS = {
    "01": "SIGHUP", "02": "SIGINT", "03": "SIGQUIT", "04": "SIGABRT",
    "05": "SIGKILL", "06": "SIGSEGV", "07": "SIGBUS", "08": "SIGILL",
    "09": "SIGFPE", "10": "SIGUSR1", "11": "SIGSEGV", "12": "SIGXCPU",
    "13": "SIGPIPE", "14": "SIGTERM", "15": "SIGTIMER",
}


def _err(message: str) -> ValidationError:
    return ValidationError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise _err(message)


def load_manifest(path: str | Path) -> tuple[dict[str, Any], Path]:
    """Load and structurally validate an import manifest.

    Returns ``(manifest, base_dir)`` where every relative artifact path is
    resolved against ``base_dir`` (the manifest's own directory).
    """
    manifest_path = Path(path)
    try:
        raw = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise _err(f"cannot read import manifest: {exc}") from exc
    try:
        manifest = json.loads(raw)
    except ValueError as exc:
        raise _err(f"import manifest is not valid JSON: {exc}") from exc
    _require(isinstance(manifest, dict), "import manifest must be a JSON object")
    _require(manifest.get("schema_version") == IMPORT_SCHEMA_VERSION,
             f"unsupported import schema_version "
             f"(want {IMPORT_SCHEMA_VERSION})")
    _require(manifest.get("kind") == MANIFEST_KIND,
             f"import manifest kind must be '{MANIFEST_KIND}'")

    engine = manifest.get("engine")
    _require(isinstance(engine, dict) and isinstance(engine.get("name"), str)
             and bool(engine["name"].strip()),
             "import manifest requires engine.name")
    findings = manifest.get("findings", [])
    _require(isinstance(findings, list), "'findings' must be an array")
    for i, finding in enumerate(findings):
        _require(isinstance(finding, dict),
                 f"finding #{i} must be an object")
        _require(isinstance(finding.get("input"), str)
                 and bool(finding["input"].strip()),
                 f"finding #{i} requires an 'input' path")
        _require(bool(finding.get("sanitizer_output")) or
                 isinstance(finding.get("detail"), str),
                 f"finding #{i} needs 'sanitizer_output' or 'detail'")
    corpus = manifest.get("corpus", [])
    _require(isinstance(corpus, list), "'corpus' must be an array")
    stats = manifest.get("stats", {})
    _require(isinstance(stats, dict), "'stats' must be an object")
    return manifest, manifest_path.resolve().parent


def _resolve_under(base_dir: Path, rel: str) -> Path:
    """Resolve ``rel`` strictly inside ``base_dir`` (fail closed)."""
    _require(isinstance(rel, str) and bool(rel.strip()),
             "artifact path must be a non-empty string")
    candidate = Path(rel)
    _require(not candidate.is_absolute(),
             f"artifact path must be relative: {rel}")
    resolved = (base_dir / candidate).resolve()
    _try_relative(resolved, base_dir.resolve(), rel)
    _require(resolved.is_file(), f"artifact file is missing: {rel}")
    _require(resolved.stat().st_size <= MAX_FILE_BYTES,
             f"artifact exceeds {MAX_FILE_BYTES} bytes: {rel}")
    return resolved


def _try_relative(resolved: Path, base: Path, rel: str) -> None:
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise _err(
            f"import path escapes the manifest directory: {rel}") from exc


def _filename_metadata(name: str) -> dict[str, str]:
    """Best-effort metadata from conventional engine artifact names."""
    lower = name.lower()
    for prefix, (kind, classification) in _LIBFUZZER_PREFIXES.items():
        if lower.startswith(prefix):
            return {"engine_kind": kind, "classification": classification,
                    "signal": ""}
    if ",sig:" in name:
        sig = name.rsplit(",sig:", 1)[1].split(",", 1)[0].zfill(2)
        if sig in _AFL_SIGNALS:
            signal = _AFL_SIGNALS[sig]
            classification = ("SEGV_OR_NULL_DEREF"
                              if signal.endswith(("SEGV", "SIGBUS")) else
                              "ABORT" if signal == "SIGABRT" else "SIGNAL")
            return {"engine_kind": "crash", "classification": classification,
                    "signal": signal}
    return {"engine_kind": "", "classification": "", "signal": ""}


class EngineImporter:
    """Import one external-engine campaign manifest into this workspace."""

    def __init__(self, workspace):
        from .crashes import CrashStore
        self.ws = workspace
        self.crashes = CrashStore(workspace)
        self.artifacts = ArtifactStore(workspace)

    def import_manifest(self, path: str | Path,
                        *, experiment_id: str | None = None) -> dict[str, Any]:
        from .experiment import ExperimentStore

        manifest, base_dir = load_manifest(path)
        engine = manifest.get("engine", {})
        engine_name = str(engine.get("name", "")).strip()
        command = engine.get("command")
        _require(command is None or isinstance(command, list),
                 "'engine.command' must be an array of strings")

        manifest_bytes = Path(path).read_bytes()
        manifest_sha = sha256_bytes(manifest_bytes)
        exp_id = experiment_id or self._ensure_experiment(
            manifest, engine_name, manifest_sha)

        imported: list[dict[str, Any]] = []
        deduped: list[str] = []
        for i, finding in enumerate(manifest.get("findings", [])):
            outcome = self._import_finding(
                finding, index=i, base_dir=base_dir, engine=engine_name,
                command=command, manifest_sha=manifest_sha,
                experiment_id=exp_id, manifest=manifest)
            if outcome["deduped"]:
                deduped.append(outcome["crash_id"])
            else:
                imported.append(outcome)

        corpus_shas: list[str] = []
        for rel in manifest.get("corpus", []):
            data = _resolve_under(base_dir, rel).read_bytes()
            artifact = self.artifacts.put(data, kind="engine-corpus")
            corpus_shas.append(artifact.sha256)

        summary = {
            "schema_version": IMPORT_SCHEMA_VERSION,
            "kind": "engine-import-summary",
            "import_id": self._import_id(engine_name, manifest_sha),
            "engine": {"name": engine_name,
                       "version": str(engine.get("version", "")),
                       "command": command or []},
            "manifest_sha256": manifest_sha,
            "experiment_id": exp_id,
            "crashes": [item["crash_id"] for item in imported],
            "crash_deduped": sorted(set(deduped)),
            "corpus_artifacts": len(corpus_shas),
            "stats": manifest.get("stats", {}),
        }
        self.ws.write_json(
            self._summary_rel(summary["import_id"]), summary)
        return summary

    # -- internals -----------------------------------------------------------

    def _import_finding(self, finding: dict[str, Any], *, index: int,
                        base_dir: Path, engine: str, command: list | None,
                        manifest_sha: str, experiment_id: str,
                        manifest: dict[str, Any]) -> dict[str, Any]:
        input_rel = str(finding["input"])
        input_path = _resolve_under(base_dir, input_rel)
        data = input_path.read_bytes()

        sanitizer_rel = finding.get("sanitizer_output") or ""
        sanitizer_text = ""
        if sanitizer_rel:
            sanitizer_text = _resolve_under(
                base_dir, str(sanitizer_rel)).read_text(
                encoding="utf-8", errors="replace")[:200_000]

        meta = _filename_metadata(input_path.name)
        detail = str(finding.get("detail", ""))
        if sanitizer_text:
            triage = triage_report(sanitizer_text)
            diagnostics = Diagnostics(
                exception_type=triage["violation_class"],
                signal="",
                stack_trace=list(triage["top_frames"]),
                signature=triage["dedup_signature"],
                classification_hint=triage["classification"] or "UNKNOWN",
            )
            detail = detail or triage["violation_class"].lower()
        else:
            digest12 = sha256_bytes(data)[:12]
            classification = meta["classification"] or "UNKNOWN_CRASH"
            signature_material = f"{meta['engine_kind'] or 'crash'}|{digest12}"
            from .hashing import sha256_text
            diagnostics = Diagnostics(
                exception_type=classification,
                signal=meta["signal"],
                signature=(f"{meta['engine_kind'] or 'crash'}_"
                           f"{sha256_text(signature_material)[:16]}"),
                classification_hint=classification,
            )
            detail = detail or (
                f"imported {meta['engine_kind'] or 'crash'} artifact")

        target = manifest.get("target", {})
        target_id = str(target.get("id", "")).strip() or "external:unknown"
        fmt = str(target.get("fmt", "")).strip() or "raw"

        exec_result = ExecResult(outcome=Outcome.CRASH, detail=detail[:500],
                                 diagnostics=diagnostics)
        lineage = {
            "origin": "engine-import",
            "engine": engine,
            "engine_command": command or [],
            "artifact": input_rel,
            "sanitizer_output": sanitizer_rel or None,
            "finding_index": index,
            "manifest_sha256": manifest_sha,
        }
        record = self.crashes.record(
            experiment_id=experiment_id, target=target_id, fmt=fmt,
            data=data, exec_result=exec_result, lineage=lineage)
        return {"crash_id": record.id, "deduped": record.count > 1}

    def _ensure_experiment(self, manifest: dict[str, Any], engine_name: str,
                           manifest_sha: str) -> str:
        from .errors import NotFoundError
        from .experiment import ExperimentStore
        store = ExperimentStore(self.ws)
        requested = manifest.get("experiment_id")
        if isinstance(requested, str) and requested.strip():
            try:
                return store.get(requested.strip()).id
            except NotFoundError:
                pass
        target = manifest.get("target", {})
        experiment = store.create(
            target=str(target.get("id", "")).strip() or "external:unknown",
            device=f"external:{engine_name}",
            os_version=str(target.get("os_version", "unknown")),
            config_hash=f"engine-import-{manifest_sha[:16]}",
            seed=0,
            params={"origin": "engine-import"},
        )
        return experiment.id

    @staticmethod
    def _import_id(engine_name: str, manifest_sha: str) -> str:
        from .ids import make_id
        return make_id("imp", engine_name, manifest_sha)

    def _summary_rel(self, import_id: str) -> str:
        return f"research/imports/{import_id}.json"

    def list_imports(self) -> list[dict[str, Any]]:
        out = []
        base = self.ws.dir("research") / "imports"
        if not base.is_dir():
            return out
        for path in sorted(base.glob("imp_*.json")):
            out.append(json.loads(path.read_text(encoding="utf-8")))
        return out
