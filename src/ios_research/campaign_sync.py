"""Distributed fuzzing campaign corpus synchronization (#32).

Companion to :mod:`ios_research.campaign` (continuous regression campaigns):
this module coordinates corpora between authorized machines through shared
directories (never implicit network discovery) using an append-only,
content-addressed exchange format:

    <bundle-dir>/
      manifest.json          # schema, campaign, worker, entries, stats
      inputs/<sha256>.bin    # one content-addressed input per entry

Safety model:
- Sync paths must live under a configured allowlisted root
  (config ``campaign.sync_roots``) or inside the workspace; anything else is
  refused with an actionable error. Distributed mode is opt-in by config.
- Imports verify every input's SHA-256 before it can touch the corpus;
  hash mismatches, unreadable files, and malformed manifests are *counted and
  rejected*, never partially applied (single atomic corpus save at the end).
- Duplicate inputs (by content hash) are no-ops, so re-running an interrupted
  import is safe and two workers can push concurrently without conflict.
- Coverage minimization: when entries carry coverage features, inputs that add
  no new feature for the local corpus are skipped (configurable).

Everything is deterministic: manifests are sorted by input hash and imports
process entries in that order.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .clock import now_iso
from .config import Config
from .corpus import Corpus, CorpusStore
from .errors import ValidationError
from .hashing import sha256_bytes
from .workspace import Workspace

SCHEMA_VERSION = 1
MANIFEST_NAME = "manifest.json"
INPUTS_DIRNAME = "inputs"


# ---------------------------------------------------------------------------
# Path allowlist
# ---------------------------------------------------------------------------

def ensure_allowed_path(path: Path, workspace: Workspace,
                        config: Config) -> Path:
    """Require ``path`` to live under a configured sync root or the workspace.

    ``campaign.sync_roots`` is an explicit allowlist of directories; an empty
    list means only workspace-internal exchange is permitted. This keeps
    distributed mode opt-in and prevents pointing imports at arbitrary
    filesystem locations.
    """
    resolved = path.resolve()
    roots = [Path(r).resolve() for r in
             (config.get("campaign.sync_roots") or [])]
    roots.append(workspace.root)
    for root in roots:
        if resolved == root or root in resolved.parents:
            return resolved
    raise ValidationError(
        f"path '{path}' is not under a configured campaign sync root; "
        f"add it to config key 'campaign.sync_roots' "
        f"(currently: {[str(r) for r in roots[:-1]]} + workspace)")


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_bundle(workspace: Workspace, corpus_store: CorpusStore,
                  corpus: Corpus, out_dir: Path, *, worker_id: str,
                  campaign_id: str, stats: dict[str, Any] | None = None
                  ) -> dict[str, Any]:
    """Write an append-only exchange bundle for ``corpus`` to ``out_dir``.

    Deterministic: the manifest entry list is sorted by input SHA-256, so
    exporting the same corpus state twice produces identical entry lists.
    """
    if not worker_id.strip():
        raise ValidationError("worker_id must be a non-empty string")
    entries = []
    for tc in corpus.testcases:
        data = corpus_store.read_bytes(corpus, tc["sha256"])
        entries.append({
            "sha256": tc["sha256"],
            "size": len(data),
            "origin": tc.get("origin", ""),
            "coverage_features": sorted(tc.get("coverage_features") or []),
        })
    entries.sort(key=lambda e: e["sha256"])
    manifest = {
        "schema": SCHEMA_VERSION,
        "kind": "ios-research-campaign-bundle",
        "campaign_id": campaign_id,
        "worker_id": worker_id,
        "corpus_name": corpus.name,
        "exported_at": now_iso(),
        "entries": entries,
        "stats": stats or {},
    }
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    inputs_dir = out_dir / INPUTS_DIRNAME
    inputs_dir.mkdir(exist_ok=True)
    for entry in entries:
        data = corpus_store.read_bytes(corpus, entry["sha256"])
        (inputs_dir / f"{entry['sha256']}.bin").write_bytes(data)
    (out_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return manifest


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

def _load_manifest(bundle_dir: Path) -> dict[str, Any]:
    manifest_path = bundle_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        raise ValidationError(
            f"not a campaign bundle: {MANIFEST_NAME} missing in {bundle_dir}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"{manifest_path}: invalid JSON ({exc.msg} at line {exc.lineno})"
        ) from None
    if not isinstance(manifest, dict) \
            or manifest.get("schema") != SCHEMA_VERSION \
            or manifest.get("kind") != "ios-research-campaign-bundle" \
            or not isinstance(manifest.get("entries"), list):
        raise ValidationError(
            f"{manifest_path}: unsupported or malformed campaign manifest "
            f"(schema {SCHEMA_VERSION} expected)")
    return manifest


def import_bundle(workspace: Workspace, corpus_store: CorpusStore,
                  corpus: Corpus, bundle_dir: Path, *,
                  dry_run: bool = False,
                  require_new_coverage: bool = False) -> dict[str, Any]:
    """Import a bundle into ``corpus`` with verification and dedup.

    Returns a deterministic report; the corpus is modified only if at least
    one entry is accepted and ``dry_run`` is false, and always in a single
    atomic save.
    """
    bundle_dir = Path(bundle_dir)
    manifest = _load_manifest(bundle_dir)
    inputs_dir = bundle_dir / INPUTS_DIRNAME

    known_shas = {tc["sha256"] for tc in corpus.testcases}
    known_features: set[str] = set()
    for tc in corpus.testcases:
        known_features.update(tc.get("coverage_features") or [])

    accepted: list[dict[str, Any]] = []
    duplicates = 0
    rejected: list[dict[str, str]] = []
    coverage_skipped = 0

    for entry in sorted(manifest["entries"], key=lambda e: e.get("sha256", "")):
        if not isinstance(entry, dict) \
                or not isinstance(entry.get("sha256"), str):
            rejected.append({"sha256": "", "reason": "malformed entry"})
            continue
        sha = entry["sha256"]
        if sha in known_shas:
            duplicates += 1
            continue
        input_path = inputs_dir / f"{sha}.bin"
        if not input_path.is_file():
            rejected.append({"sha256": sha, "reason": "input file missing"})
            continue
        try:
            data = input_path.read_bytes()
        except OSError as exc:
            rejected.append({"sha256": sha,
                             "reason": f"unreadable: {exc}"})
            continue
        if sha256_bytes(data) != sha:
            rejected.append({"sha256": sha,
                             "reason": "sha256 mismatch (corrupt or tampered)"})
            continue
        features = sorted(entry.get("coverage_features") or [])
        if require_new_coverage and features \
                and not (set(features) - known_features):
            coverage_skipped += 1
            continue
        accepted.append({"sha256": sha, "size": len(data),
                         "origin": entry.get("origin", ""),
                         "coverage_features": features})
        known_shas.add(sha)
        known_features.update(features)

    report = {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": manifest.get("campaign_id", ""),
        "worker_id": manifest.get("worker_id", ""),
        "bundle": str(bundle_dir),
        "dry_run": dry_run,
        "entries_seen": len(manifest["entries"]),
        "accepted": sorted(accepted, key=lambda e: e["sha256"]),
        "accepted_count": len(accepted),
        "duplicates": duplicates,
        "rejected": sorted(rejected, key=lambda r: r["sha256"]),
        "rejected_count": len(rejected),
        "coverage_skipped": coverage_skipped,
    }

    if accepted and not dry_run:
        for item in accepted:
            data = (inputs_dir / f"{item['sha256']}.bin").read_bytes()
            corpus_store.add_bytes(
                corpus, data, origin="campaign-import",
                coverage_features=item["coverage_features"] or None)
        corpus_store.save(corpus)
        # Retain the imported manifest for status aggregation/audit.
        record = dict(manifest)
        record["import_report"] = {
            k: report[k] for k in ("accepted_count", "duplicates",
                                   "rejected_count", "coverage_skipped")
        }
        record["imported_at"] = now_iso()
        workspace.write_json(
            f"campaign/imports/{manifest.get('worker_id', 'unknown')}_"
            f"{sha256_bytes(json.dumps(manifest, sort_keys=True).encode())[:12]}"
            ".json", record)
    return report


# ---------------------------------------------------------------------------
# Status aggregation
# ---------------------------------------------------------------------------

def aggregate_status(workspace: Workspace,
                     *, campaign_id: str | None = None) -> dict[str, Any]:
    """Aggregate worker health and corpus deltas from imported manifests."""
    base = workspace.dir("campaign") / "imports"
    workers: dict[str, dict[str, Any]] = {}
    manifests_seen = 0
    if base.exists():
        for path in sorted(base.glob("*.json")):
            record = workspace.read_json(str(path.relative_to(workspace.root)))
            if campaign_id and record.get("campaign_id") != campaign_id:
                continue
            manifests_seen += 1
            worker = str(record.get("worker_id") or "unknown")
            slot = workers.setdefault(worker, {
                "worker_id": worker,
                "campaigns": sorted({record.get("campaign_id", "")}),
                "imports": 0,
                "inputs_imported": 0,
                "rejected": 0,
                "duplicates": 0,
                "last_sync": "",
                "last_stats": {},
            })
            slot["imports"] += 1
            report = record.get("import_report") or {}
            slot["inputs_imported"] += int(report.get("accepted_count", 0))
            slot["rejected"] += int(report.get("rejected_count", 0))
            slot["duplicates"] += int(report.get("duplicates", 0))
            imported_at = record.get("imported_at", "")
            if imported_at > slot["last_sync"]:
                slot["last_sync"] = imported_at
                slot["last_stats"] = record.get("stats") or {}
    worker_list = sorted(workers.values(), key=lambda w: w["worker_id"])
    newest = max((w["last_sync"] for w in worker_list), default="")
    return {
        "campaign_id": campaign_id,
        "manifests_seen": manifests_seen,
        "workers": worker_list,
        "worker_count": len(worker_list),
        "total_inputs_imported": sum(w["inputs_imported"]
                                     for w in worker_list),
        "total_rejected": sum(w["rejected"] for w in worker_list),
        "newest_sync": newest,
        "generated_at": now_iso(),
        "note": "sync lag = time since newest imported manifest; "
                "executions/crashes come from each worker's exported stats",
    }
