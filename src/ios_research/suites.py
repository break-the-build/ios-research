"""Versioned protocol/format suite catalog (#47).

A *suite* bundles everything a campaign needs for one safe, user-declared
protocol or file/media format: a seed corpus, an optional token dictionary,
optional grammar/mutator plugins, an optional state machine, optional oracle
definitions, and licensing/provenance metadata. Suites live in a local
directory described by a ``suite.json`` manifest:

```json
{
  "schema_version": 1,
  "name": "mock-record",
  "version": "1.0.0",
  "description": "...",
  "license": "MIT",
  "compatibility": {"framework": "ios-research",
                    "min_framework_version": "0.1.0"},
  "contents": {"seeds_dir": "seeds", "dictionary": "dictionary.txt"},
  "provenance": {"source": "...", "created_at": "..."}
}
```

Trust and safety model mirrors the rest of the framework:

* Manifests are validated strictly (unknown fields rejected; every declared
  path must exist *and* resolve inside the suite directory — absolute paths
  and ``..`` escapes are rejected before any file is read).
* Validation never raises for a broken suite: it returns structured
  ``problems`` so agents can triage without exception handling.
* The :class:`SuiteCatalog` installs suites into the workspace under
  ``suites/<name>-<version>/``, recording provenance plus the SHA-256 of every
  copied file, and refuses duplicate installs. Removing a suite deletes only
  its own directory; core code is never modified.
* Benchmarks are bounded (<= 200 cases) deterministic mini-campaigns driven by
  :class:`ios_research.fuzz.FuzzEngine`, so two runs with the same inputs
  produce identical stats.

Suites ship for safe, user-declared file/media and application protocols only;
they carry no exploit-generation or device-attack capability.
"""

from __future__ import annotations

import json
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

from . import __version__, targets
from .clock import now_iso
from .dictionary import load_dictionary
from .errors import NotFoundError, StateError, UsageError, ValidationError
from .grammar import PluginHost
from .hashing import sha256_bytes, sha256_text
from .ids import make_id
from .workspace import Workspace

SUITE_SCHEMA_VERSION = 1
MANIFEST_NAME = "suite.json"
RECEIPT_NAME = ".iosr-install.json"
FRAMEWORK_NAME = "ios-research"
MAX_BENCHMARK_CASES = 200
MAX_MANIFEST_BYTES = 256 * 1024

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
_MIN_FRAMEWORK_RE = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.\-]+)?$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")

_TOP_FIELDS = {"schema_version", "name", "version", "description", "license",
               "compatibility", "contents", "provenance"}
_COMPAT_FIELDS = {"framework", "min_framework_version"}
_CONTENT_FIELDS = {"seeds_dir", "dictionary", "plugins", "state_machine",
                   "oracles"}
_PROVENANCE_FIELDS = {"source", "created_at"}


# --- version helpers ---------------------------------------------------------

def version_tuple(text: str) -> tuple[int, ...]:
    """Parse a version string into a comparable int tuple.

    Non-numeric parts are tolerated and count as 0, e.g. ``"0.2rc1"`` ->
    ``(0, 2, 0)``. Never raises.
    """
    parts: list[int] = []
    for chunk in re.split(r"[.+\-_]", str(text)):
        digits = re.match(r"\d+", chunk)
        parts.append(int(digits.group()) if digits else 0)
    return tuple(parts) if parts else (0,)


def _version_cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    a += (0,) * (width - len(a))
    b += (0,) * (width - len(b))
    return (a > b) - (a < b)


# --- manifest parsing --------------------------------------------------------

def _resolve_in_suite(base: Path, rel: str) -> Path:
    """Resolve ``rel`` inside suite dir ``base`` or raise ValidationError."""
    candidate = Path(rel)
    if candidate.is_absolute():
        raise ValidationError(
            f"absolute path not allowed; must be relative to the suite "
            f"directory: {rel}")
    if ".." in candidate.parts:
        raise ValidationError(f"path must not contain '..': {rel}")
    resolved = (base / candidate).resolve()
    base_resolved = base.resolve()
    if resolved != base_resolved and base_resolved not in resolved.parents:
        raise ValidationError(f"path escapes the suite directory: {rel}")
    return resolved


def _require_str(manifest_path: str, obj: dict, key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(
            f"{manifest_path}.{key} must be a non-empty string")
    return value


def _reject_unknown(where: str, obj: dict, allowed: set[str]) -> None:
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise ValidationError(
            f"{where}: unknown field(s): {', '.join(unknown)}")


def parse_suite_manifest(suite_dir: str | Path) -> dict[str, Any]:
    """Strictly parse and validate ``suite.json`` inside ``suite_dir``.

    Raises :class:`ValidationError` on any structural problem; path existence
    and containment are checked here too, before any content is read.
    """
    base = Path(suite_dir)
    manifest_path = base / MANIFEST_NAME
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise ValidationError(f"cannot read {manifest_path}: {exc}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValidationError("suite manifest exceeds size bound")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValidationError(f"suite manifest is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError("suite manifest must be a JSON object")
    _reject_unknown("suite manifest", data, _TOP_FIELDS)

    if data.get("schema_version") != SUITE_SCHEMA_VERSION:
        raise ValidationError(
            f"unsupported suite schema_version "
            f"{data.get('schema_version')!r}; expected {SUITE_SCHEMA_VERSION}")
    name = _require_str("manifest", data, "name")
    if not _NAME_RE.match(name):
        raise ValidationError(f"invalid suite name: {name!r}")
    version = _require_str("manifest", data, "version")
    if not _VERSION_RE.match(version):
        raise ValidationError(
            f"suite version {version!r} is not semver-ish (X.Y.Z[-suffix])")
    description = _require_str("manifest", data, "description")
    license_id = _require_str("manifest", data, "license")

    compat = data.get("compatibility")
    if not isinstance(compat, dict):
        raise ValidationError("manifest.compatibility must be an object")
    _reject_unknown("manifest.compatibility", compat, _COMPAT_FIELDS)
    framework = _require_str("manifest.compatibility", compat, "framework")
    min_framework = _require_str(
        "manifest.compatibility", compat, "min_framework_version")
    if not _MIN_FRAMEWORK_RE.match(min_framework):
        raise ValidationError(
            f"compatibility.min_framework_version {min_framework!r} "
            f"is not a dotted numeric version")

    contents = data.get("contents")
    if not isinstance(contents, dict):
        raise ValidationError("manifest.contents must be an object")
    _reject_unknown("manifest.contents", contents, _CONTENT_FIELDS)
    seeds_rel = _require_str("manifest.contents", contents, "seeds_dir")
    seeds_dir = _resolve_in_suite(base, seeds_rel)
    if not seeds_dir.is_dir():
        raise ValidationError(
            f"contents.seeds_dir does not exist: {seeds_rel}")

    def _existing_file(key: str) -> Path | None:
        rel = contents.get(key)
        if rel is None:
            return None
        if not isinstance(rel, str) or not rel:
            raise ValidationError(f"manifest.contents.{key} must be a string")
        path = _resolve_in_suite(base, rel)
        if not path.is_file():
            raise ValidationError(
                f"manifest.contents.{key} does not exist: {rel}")
        return path

    dictionary_path = _existing_file("dictionary")
    state_machine_path = _existing_file("state_machine")
    oracles_path = _existing_file("oracles")

    plugins_rel = contents.get("plugins", [])
    plugin_paths: list[Path] = []
    if not isinstance(plugins_rel, list):
        raise ValidationError("manifest.contents.plugins must be a list")
    for rel in plugins_rel:
        if not isinstance(rel, str) or not rel:
            raise ValidationError(
                "manifest.contents.plugins entries must be strings")
        path = _resolve_in_suite(base, rel)
        if not path.is_file():
            raise ValidationError(
                f"manifest.contents.plugins entry does not exist: {rel}")
        plugin_paths.append(path)

    provenance = data.get("provenance")
    if not isinstance(provenance, dict):
        raise ValidationError("manifest.provenance must be an object")
    _reject_unknown("manifest.provenance", provenance, _PROVENANCE_FIELDS)
    source = _require_str("manifest.provenance", provenance, "source")
    created_at = _require_str("manifest.provenance", provenance, "created_at")

    return {
        "schema_version": SUITE_SCHEMA_VERSION,
        "name": name,
        "version": version,
        "description": description,
        "license": license_id,
        "compatibility": {"framework": framework,
                          "min_framework_version": min_framework},
        "contents": {
            "seeds_dir": seeds_rel,
            **({"dictionary": contents["dictionary"]}
               if dictionary_path else {}),
            **({"plugins": list(plugins_rel)} if plugins_rel else {}),
            **({"state_machine": contents["state_machine"]}
               if state_machine_path else {}),
            **({"oracles": contents["oracles"]} if oracles_path else {}),
        },
        "provenance": {"source": source, "created_at": created_at},
        "_paths": {
            "base": base,
            "seeds_dir": seeds_dir,
            "dictionary": dictionary_path,
            "state_machine": state_machine_path,
            "oracles": oracles_path,
            "plugins": plugin_paths,
        },
    }


# --- validation --------------------------------------------------------------

def validate_suite(suite_dir: str | Path,
                   framework_version: str | None = None) -> dict[str, Any]:
    """Validate a suite directory, returning ``{"valid": bool, "problems": []}``.

    Invalid or incompatible suites NEVER raise here: every failure becomes a
    structured problem entry so callers (and agents) can triage safely.
    """
    current = framework_version or __version__
    problems: list[str] = []
    manifest: dict[str, Any] | None = None
    paths: dict[str, Any] = {}
    try:
        manifest = parse_suite_manifest(suite_dir)
        paths = manifest.pop("_paths")
    except ValidationError as exc:
        problems.append(exc.message)
    except Exception as exc:  # noqa: BLE001 - fail safely, never crash
        problems.append(f"suite validation failed unexpectedly: {exc}")

    name = manifest["name"] if manifest else Path(suite_dir).name
    version = manifest["version"] if manifest else ""

    if manifest is not None:
        compat = manifest["compatibility"]
        if compat["framework"] != FRAMEWORK_NAME:
            problems.append(
                f"compatibility.framework is {compat['framework']!r}; "
                f"expected {FRAMEWORK_NAME!r}")
        elif _version_cmp(
                version_tuple(compat["min_framework_version"]),
                version_tuple(current)) > 0:
            problems.append(
                f"suite requires framework >= "
                f"{compat['min_framework_version']}; running {current}")
        seeds = [p for p in sorted(paths["seeds_dir"].iterdir())
                 if p.is_file()]
        if not seeds:
            problems.append("seed corpus is empty")

        dict_path = paths.get("dictionary")
        if dict_path is not None:
            try:
                load_dictionary(dict_path)
            except ValidationError as exc:
                problems.append(f"dictionary invalid: {exc.message}")

        for rel, path in zip(manifest["contents"].get("plugins", []),
                             paths["plugins"]):
            host = PluginHost().discover([path])
            if not host.plugins:
                detail = f": {host.last_error}" if host.last_error else ""
                problems.append(f"plugin failed to load ({rel}){detail}")

        for label, path in (("state_machine", paths.get("state_machine")),
                            ("oracles", paths.get("oracles"))):
            if path is None:
                continue
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, UnicodeError) as exc:
                problems.append(f"{label} is not valid JSON: {exc}")
                continue
            if not isinstance(parsed, dict):
                problems.append(f"{label} must be a JSON object")

    return {
        "valid": not problems,
        "problems": problems,
        "name": name,
        "version": version,
        "framework_version": current,
    }


# --- catalog -------------------------------------------------------------------

class SuiteCatalog:
    """Installs, enumerates, benchmarks, and removes local suites."""

    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.base = self.ws.dir("suites")

    # -- helpers ----------------------------------------------------------
    def _installed_dirs(self) -> list[Path]:
        if not self.base.is_dir():
            return []
        return sorted(p for p in self.base.iterdir()
                      if p.is_dir() and (p / MANIFEST_NAME).is_file())

    def _read_manifest(self, path: Path) -> dict[str, Any] | None:
        try:
            return parse_suite_manifest(path)
        except Exception:  # noqa: BLE001 - enumeration must not crash
            return None

    @staticmethod
    def _record(manifest: dict[str, Any]) -> dict[str, Any]:
        paths = manifest.pop("_paths", {})
        record = dict(manifest)
        record["path"] = str(paths.get("base", ""))
        receipt = paths.get("base", Path("")) / RECEIPT_NAME
        if receipt.is_file():
            try:
                record["install_receipt"] = json.loads(
                    receipt.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                record["install_receipt"] = None
        return record

    # -- lifecycle ----------------------------------------------------------
    def install(self, src_dir: str | Path) -> dict[str, Any]:
        """Validate then copy a suite into the workspace catalog."""
        src = Path(src_dir)
        report = validate_suite(src)
        if not report["valid"]:
            raise ValidationError(
                "suite validation failed: " + "; ".join(report["problems"]),
                details={"problems": report["problems"]})
        manifest = self._read_manifest(src)
        if manifest is None:
            raise ValidationError(
                "suite became unreadable during install")  # pragma: no cover
        name, version = manifest["name"], manifest["version"]
        dest = self.base / f"{name}-{version}"
        if dest.exists():
            raise StateError(
                f"suite '{name}' version '{version}' is already installed")
        self.base.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dest)
        files = []
        for file_path in sorted(dest.rglob("*")):
            if not file_path.is_file() or file_path.name == RECEIPT_NAME:
                continue
            blob = file_path.read_bytes()
            files.append({
                "path": file_path.relative_to(dest).as_posix(),
                "sha256": sha256_bytes(blob),
                "size": len(blob),
            })
        receipt = {
            "schema_version": SUITE_SCHEMA_VERSION,
            "name": name,
            "version": version,
            "installed_at": now_iso(),
            "provenance": manifest["provenance"],
            "manifest_sha256": sha256_bytes(
                (dest / MANIFEST_NAME).read_bytes()),
            "files": files,
        }
        self.ws.write_json(str((dest / RECEIPT_NAME).relative_to(self.ws.root)),
                           receipt)
        return {
            "name": name,
            "version": version,
            "path": str(dest),
            "files_copied": len(files),
            "receipt_sha256": sha256_text(json.dumps(receipt, sort_keys=True)),
        }

    def list(self) -> list[dict[str, Any]]:
        out = []
        for path in self._installed_dirs():
            manifest = self._read_manifest(path)
            if manifest is None:
                continue
            out.append(self._record(manifest))
        out.sort(key=lambda r: (r["name"], version_tuple(r["version"])))
        return out

    def get(self, name: str, version: str | None = None) -> dict[str, Any]:
        candidates = []
        for path in self._installed_dirs():
            manifest = self._read_manifest(path)
            if manifest is None or manifest["name"] != name:
                continue
            if version is not None and manifest["version"] != version:
                continue
            candidates.append(manifest)
        if not candidates:
            label = f"'{name}' version '{version}'" if version \
                else f"'{name}' (any version)"
            raise NotFoundError(f"suite {label} is not installed")
        candidates.sort(key=lambda m: version_tuple(m["version"]))
        return self._record(candidates[-1])

    def remove(self, name: str, version: str) -> dict[str, Any]:
        target = None
        for path in self._installed_dirs():
            manifest = self._read_manifest(path)
            if manifest and manifest["name"] == name \
                    and manifest["version"] == version:
                target = path
                break
        if target is None:
            raise NotFoundError(
                f"suite '{name}' version '{version}' is not installed")
        shutil.rmtree(target)
        return {"removed": True, "name": name, "version": version}

    # -- corpus / benchmark -------------------------------------------------
    def seed_corpus(self, suite: str | Path | dict[str, Any]) -> list[bytes]:
        """Seed bytes for a suite (path, installed record, or directory)."""
        if isinstance(suite, dict):
            suite = suite.get("path") or suite.get("_paths", {}).get("base")
            if not suite:
                raise ValidationError("suite record has no path")
        base = Path(suite)
        manifest = parse_suite_manifest(base)
        paths = manifest.pop("_paths")
        return [path.read_bytes()
                for path in sorted(paths["seeds_dir"].iterdir())
                if path.is_file()]

    def run_benchmark(self, suite_dir: str | Path, target_id: str, *,
                      cases: int = 50, seed: int = 0) -> dict[str, Any]:
        """Deterministic bounded mini-campaign over a suite's seeds.

        Uses :class:`FuzzEngine` with the suite's seed corpus (and its
        dictionary when declared). For fixed ``(suite, target, cases, seed)``
        inputs the returned stats are stable across runs and workspaces.
        """
        from .corpus import CorpusStore
        from .experiment import ExperimentStore
        from .fuzz import FuzzEngine

        if cases > MAX_BENCHMARK_CASES:
            raise UsageError(
                f"benchmark cases limited to {MAX_BENCHMARK_CASES}")
        if cases < 1:
            raise UsageError("benchmark requires at least 1 case")
        if not targets.is_registered(target_id):
            raise UsageError(f"unknown target '{target_id}'")
        target = targets.create(target_id)
        available = getattr(target, "available", None)
        if getattr(target, "mock", True) is False \
                and callable(available) and not available():
            raise StateError(
                f"target '{target_id}' is not available for benchmarking")

        report = validate_suite(suite_dir)
        if not report["valid"]:
            raise ValidationError(
                "cannot benchmark invalid suite: "
                + "; ".join(report["problems"]),
                details={"problems": report["problems"]})
        manifest = parse_suite_manifest(suite_dir)
        paths = manifest.pop("_paths")

        seeds = self.seed_corpus(suite_dir)
        corpus_store = CorpusStore(self.ws)
        corpus = corpus_store.create(
            f"suite-bench-{uuid.uuid4().hex[:12]}", target=target_id)
        for blob in seeds:
            corpus_store.add_bytes(corpus, blob, origin="seed")

        exp = ExperimentStore(self.ws).create(
            target=target_id, device="mock:device", os_version="17.0",
            config_hash=make_id("suite", manifest["name"],
                                manifest["version"], str(seed), str(cases)),
            seed=seed)
        engine = FuzzEngine(self.ws)
        session = engine.create(
            experiment_id=exp.id, target=target_id, corpus_id=corpus.id,
            seed=seed, workers=1, max_cases=cases, duration_s=None,
            dictionary_path=(str(paths["dictionary"])
                             if paths.get("dictionary") else None))
        session = engine.advance(session)
        return {
            "suite": {"name": manifest["name"], "version": manifest["version"]},
            "target": target_id,
            "cases": cases,
            "seed": seed,
            "executed": session.cursor,
            "unique_features": len(session.coverage_features),
            "outcomes": dict(session.outcomes),
            "experiment_id": exp.id,
            "session_id": session.id,
        }


# --- built-in example ----------------------------------------------------------

EXAMPLE_SUITE_NAME = "mock-record"


def write_example_suite(dest_dir: str | Path) -> Path:
    """Write the built-in example suite: a safe mock-record format.

    Deterministic seeds derived from ``MOCK\\x01\\x01\\x00\\x02ok``, a small
    token dictionary, MIT license, no plugins. Returns the suite directory.
    """
    dest = Path(dest_dir)
    seeds_dir = dest / "seeds"
    seeds_dir.mkdir(parents=True, exist_ok=True)
    base = b"MOCK\x01\x01\x00\x02ok"
    variants = [
        base,
        base[:4] + b"\x02" + base[5:],          # different tag byte
        base[:6] + b"\x00\x04" + b"okay",       # different length field
        base + b"\x00\x03tail",                 # trailing record
    ]
    for i, blob in enumerate(variants):
        (seeds_dir / f"seed_{i:02d}.bin").write_bytes(blob)
    (dest / "dictionary.txt").write_text(
        "# mock-record token dictionary\n"
        'mock_magic="MOCK"\n'
        'ok_tail="ok"\n'
        'len_zero="\\x00\\x00"\n'
        'tag_two="\\x02"\n',
        encoding="utf-8")
    manifest = {
        "schema_version": SUITE_SCHEMA_VERSION,
        "name": EXAMPLE_SUITE_NAME,
        "version": "1.0.0",
        "description": "Built-in example: safe mock record format for "
                       "demonstrating the suite catalog.",
        "license": "MIT",
        "compatibility": {"framework": FRAMEWORK_NAME,
                          "min_framework_version": "0.1.0"},
        "contents": {"seeds_dir": "seeds", "dictionary": "dictionary.txt"},
        "provenance": {"source": "built-in-example",
                       "created_at": now_iso()},
    }
    (dest / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return dest
