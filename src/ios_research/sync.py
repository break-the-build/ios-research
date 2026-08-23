"""Corpus synchronization for distributed fuzzing campaigns (#32).

Workers exchange corpora through an append-only, content-addressed bundle
format so that every artifact is verifiable and every import is idempotent:

``bundle.json``
    {schema_version, kind, worker_id, target, created_at_cursor,
     entries: [{sha256, size, origin, parent, mutation, seed, iteration,
     coverage_features}] sorted by sha256,
     manifest_sha256 = sha256 over the canonical JSON of everything else}

``inputs/<sha256>.bin``
    One content-addressed input per entry.

Safety model:
* Import requires an explicit allowlist of filesystem roots; a bundle outside
  those roots fails closed (no implicit discovery, no network anywhere).
* The manifest hash verifies before any entry is trusted.
* Every input's bytes verify against its claimed sha256 and size *before*
  anything is written; one malformed entry aborts the whole import atomically.
* Writes are content-addressed, so duplicates cannot corrupt existing state
  and re-running an interrupted import converges to the same final state.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .corpus import CorpusStore
from .clock import now_iso
from .errors import NotFoundError, SafetyError, ValidationError
from .hashing import canonical_json, sha256_bytes, sha256_text
from .ids import make_id
from .workspace import Workspace

BUNDLE_SCHEMA_VERSION = 1
BUNDLE_KIND = "iosr-corpus-bundle"
MANIFEST_NAME = "bundle.json"

ENTRY_FIELDS = frozenset({
    "sha256", "size", "origin", "parent", "mutation", "seed", "iteration",
    "coverage_features",
})
MANIFEST_FIELDS = frozenset({
    "schema_version", "kind", "worker_id", "target", "created_at_cursor",
    "entries", "manifest_sha256",
})


# manifest hashing ---------------------------------------------------------
def manifest_body(manifest: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in manifest.items() if k != "manifest_sha256"}


def compute_manifest_sha256(manifest: dict[str, Any]) -> str:
    return sha256_text(canonical_json(manifest_body(manifest)))


def _is_hex_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


# export -------------------------------------------------------------------
def export_corpus(workspace: Workspace, corpus_id: str, out_dir: str | Path,
                  worker_id: str = "local", *,
                  cursor: int = 0) -> dict[str, Any]:
    """Write ``corpus_id`` as a deterministic exchange bundle at ``out_dir``.

    The same corpus always produces a byte-identical ``bundle.json``: entries
    are sorted by sha256 and no wall-clock timestamps are embedded.
    """
    store = CorpusStore(workspace)
    corpus = store.get(corpus_id)
    out = Path(out_dir)
    inputs_dir = out / "inputs"

    entries: list[dict[str, Any]] = []
    blobs: dict[str, bytes] = {}
    for tc in corpus.testcases:
        sha = tc["sha256"]
        data = store.read_bytes(corpus, sha)
        if sha256_bytes(data) != sha:
            raise ValidationError(
                f"corpus input '{sha}' does not match its recorded hash")
        blobs[sha] = data
        entries.append({
            "sha256": sha,
            "size": tc["size"],
            "origin": tc["origin"],
            "parent": tc.get("parent"),
            "mutation": tc.get("mutation"),
            "seed": tc.get("seed"),
            "iteration": tc.get("iteration"),
            "coverage_features": sorted(tc.get("coverage_features") or []),
        })
    entries.sort(key=lambda e: e["sha256"])

    manifest: dict[str, Any] = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "kind": BUNDLE_KIND,
        "worker_id": worker_id,
        "target": corpus.target or "",
        "created_at_cursor": int(cursor),
        "entries": entries,
    }
    manifest["manifest_sha256"] = compute_manifest_sha256(manifest)

    inputs_dir.mkdir(parents=True, exist_ok=True)
    for sha, data in sorted(blobs.items()):
        (inputs_dir / f"{sha}.bin").write_bytes(data)
    (out / MANIFEST_NAME).write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        encoding="utf-8")
    return {
        "worker_id": worker_id,
        "target": manifest["target"],
        "created_at_cursor": manifest["created_at_cursor"],
        "entries": len(entries),
        "bytes_written": sum(len(b) for b in blobs.values()),
        "path": str(out),
    }


# import -------------------------------------------------------------------
def require_allowlisted_root(bundle_dir: str | Path,
                             allowed_roots: list[str]) -> Path:
    """Resolve ``bundle_dir`` and fail closed unless inside an allowed root."""
    if not allowed_roots:
        raise SafetyError(
            "bundle import requires an explicit --allow-root; refusing to "
            "read from an unlisted location")
    resolved = Path(bundle_dir).resolve()
    for raw in allowed_roots:
        root = Path(raw).resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        break
    else:
        raise SafetyError(
            f"bundle dir '{resolved}' is not inside any allowlisted root")
    return resolved


def _load_bundle(resolved: Path
                 ) -> tuple[dict[str, Any], list[dict[str, Any]], list[bytes]]:
    manifest_path = resolved / MANIFEST_NAME
    if not manifest_path.is_file():
        raise NotFoundError(f"no {MANIFEST_NAME} found under {resolved}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"cannot read bundle manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValidationError("bundle manifest must be a JSON object")
    unknown = set(manifest) - MANIFEST_FIELDS
    if unknown:
        raise ValidationError(
            f"bundle manifest has unknown fields: {sorted(unknown)}")
    if manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise ValidationError(
            f"unsupported bundle schema_version "
            f"{manifest.get('schema_version')!r}")
    if manifest.get("kind") != BUNDLE_KIND:
        raise ValidationError(f"unexpected bundle kind {manifest.get('kind')!r}")

    expected = manifest.get("manifest_sha256")
    if not _is_hex_sha256(expected):
        raise ValidationError("bundle manifest_sha256 missing or malformed")
    actual = compute_manifest_sha256(manifest)
    if actual != expected:
        raise ValidationError(
            f"manifest hash mismatch: expected {expected}, computed {actual}; "
            f"bundle.json was modified or corrupted")

    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise ValidationError("bundle.entries must be a list")

    inputs_dir = resolved / "inputs"
    verified: list[tuple[dict[str, Any], bytes]] = []
    for idx, entry in enumerate(entries):
        where = f"entry[{idx}] ({entry.get('sha256', '?') if isinstance(entry, dict) else '?'})"
        if not isinstance(entry, dict):
            raise ValidationError(f"malformed bundle {where}: not an object")
        unknown_entry = set(entry) - ENTRY_FIELDS
        if unknown_entry:
            raise ValidationError(
                f"malformed bundle {where}: unknown fields {sorted(unknown_entry)}")
        missing = ENTRY_FIELDS - set(entry)
        if missing:
            raise ValidationError(
                f"malformed bundle {where}: missing fields {sorted(missing)}")
        sha = entry["sha256"]
        if not _is_hex_sha256(sha):
            raise ValidationError(
                f"malformed bundle {where}: sha256 is not valid lowercase hex")
        size = entry["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValidationError(f"malformed bundle {where}: invalid size")
        features = entry["coverage_features"]
        if not isinstance(features, list) or \
                not all(isinstance(f, str) for f in features):
            raise ValidationError(
                f"malformed bundle {where}: coverage_features must be strings")
        blob_rel = inputs_dir / f"{sha}.bin"
        if not blob_rel.is_file():
            raise ValidationError(
                f"malformed bundle {where}: missing input file {blob_rel.name}")
        blob = blob_rel.read_bytes()
        if len(blob) != size:
            raise ValidationError(
                f"malformed bundle {where}: size mismatch "
                f"(declared {size}, got {len(blob)})")
        if sha256_bytes(blob) != sha:
            raise ValidationError(
                f"malformed bundle {where}: input bytes do not match sha256")
        verified.append((entry, blob))
    return manifest, [entry for entry, _ in verified], [blob for _, blob in verified]


def _greedy_feature_cover(candidates: list[tuple[dict[str, Any], bytes]]
                          ) -> tuple[list[tuple[dict[str, Any], bytes]], int]:
    """Greedy set-cover over stored coverage_features (no target execution).

    Keeps one input per newly-covered feature; drops redundant candidates.
    Mirrors :meth:`CorpusStore.minimize` tie-breaking for determinism.
    """
    feature_sets: dict[str, set[str]] = {
        entry["sha256"]: set(entry.get("coverage_features") or [])
        for entry, _ in candidates}
    kept: list[tuple[dict[str, Any], bytes]] = []
    covered: set[str] = set()
    remaining = list(candidates)
    while remaining:
        def gain(pair: tuple[dict[str, Any], bytes]) -> tuple[int, int, str]:
            entry, _blob = pair
            return (len(feature_sets[entry["sha256"]] - covered),
                    -entry["size"], entry["sha256"])
        candidate = max(remaining, key=gain)
        new = feature_sets[candidate[0]["sha256"]] - covered
        if not new:
            break
        kept.append(candidate)
        covered.update(new)
        remaining.remove(candidate)
    return kept, len(candidates) - len(kept)


def import_bundle(workspace: Workspace, corpus_id: str, bundle_dir: str | Path,
                  *, allowed_roots: list[str],
                  minimize: bool = False) -> dict[str, Any]:
    """Import an exchange bundle into ``corpus_id`` atomically.

    Validates the allowlist, the manifest hash, and every input's bytes before
    writing anything; then merges content-addressed inputs, skipping entries
    already present in the target corpus. Idempotent by construction.
    """
    resolved = require_allowlisted_root(bundle_dir, allowed_roots)
    manifest, entries, blobs = _load_bundle(resolved)

    store = CorpusStore(workspace)
    corpus = store.get(corpus_id)

    known_shas = corpus.shas
    fresh: list[tuple[dict[str, Any], bytes]] = [
        (entry, blob) for entry, blob in zip(entries, blobs)
        if entry["sha256"] not in known_shas]
    duplicates = len(entries) - len(fresh)

    dropped_by_minimize = 0
    if minimize and fresh:
        fresh, dropped_by_minimize = _greedy_feature_cover(fresh)

    # Validation is complete; only now mutate workspace state. Content-addressed
    # destinations mean repeated/interrupted imports converge to one state.
    for entry, blob in fresh:
        sha = entry["sha256"]
        store.ws.write_bytes(store._input_rel(corpus.id, sha), blob)
        corpus.testcases.append({
            "id": make_id("testcase", corpus.id, sha),
            "sha256": sha,
            "size": entry["size"],
            "origin": entry["origin"] or "import",
            "parent": entry["parent"],
            "mutation": entry["mutation"],
            "seed": entry["seed"],
            "iteration": entry["iteration"],
            "coverage_features": list(entry["coverage_features"]),
            "coverage_new_features": [],
            "created_at": now_iso(),
        })
    store.save(corpus)

    return {
        "corpus_id": corpus.id,
        "source_worker_id": manifest.get("worker_id", ""),
        "source_created_at_cursor": manifest.get("created_at_cursor", 0),
        "bundle_dir": str(resolved),
        "entries_total": len(entries),
        "imported": len(fresh),
        "duplicates_skipped": duplicates,
        "minimize_dropped": dropped_by_minimize,
        "target_size": len(store.get(corpus.id).testcases),
    }


# aggregate status ----------------------------------------------------------
def aggregate_status(workspace: Workspace,
                     worker_dirs: list[str]) -> dict[str, Any]:
    """Read-only rollup across local worker export directories.

    Missing/unreadable workers are reported as unhealthy entries, never raised.
    Sync lag is measured against the freshest observed session cursor.
    """
    workers: list[dict[str, Any]] = []
    for raw in worker_dirs:
        record: dict[str, Any] = {"worker_dir": str(raw), "healthy": True}
        try:
            base = Path(raw).resolve()
            manifest = json.loads(
                (base / MANIFEST_NAME).read_text(encoding="utf-8"))
            if compute_manifest_sha256(manifest) != \
                    manifest.get("manifest_sha256"):
                raise ValidationError("manifest hash mismatch")
            entries = manifest.get("entries") or []
            features: set[str] = set()
            for entry in entries:
                features.update(entry.get("coverage_features") or [])
            status: dict[str, Any] = {}
            status_path = base / "status.json"
            if status_path.is_file():
                loaded = json.loads(status_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    status = loaded
            cursor = manifest.get("created_at_cursor", 0)
            record.update({
                "worker_id": manifest.get("worker_id", ""),
                "executions": status.get("executions", cursor),
                "corpus_entries": len(entries),
                "coverage_features": len(features),
                "crashes": status.get("crashes", 0),
                "cursor": cursor,
            })
        except Exception as exc:  # read-only rollup must never raise
            record["healthy"] = False
            record["reason"] = str(exc)[:200]
        workers.append(record)

    healthy = [w for w in workers if w["healthy"]]
    max_cursor = max((w["cursor"] for w in healthy), default=0)
    for worker in healthy:
        worker["sync_lag"] = max_cursor - worker["cursor"]
    return {
        "workers": workers,
        "workers_healthy": len(healthy),
        "workers_unhealthy": len(workers) - len(healthy),
        "totals": {
            "executions": sum(w["executions"] for w in healthy),
            "corpus_entries": sum(w["corpus_entries"] for w in healthy),
            "coverage_features": max((w["coverage_features"]
                                      for w in healthy), default=0),
            "crashes": sum(w["crashes"] for w in healthy),
        },
        "max_cursor": max_cursor,
    }
