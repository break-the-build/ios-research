"""Opt-in coordination of distributed fuzzing campaigns (#32).

The native campaign runner already parallelizes locally; this module adds
first-class coordination *between* authorized machines over a shared directory
that the researcher explicitly allowlists:

* **Append-only exchange format** — inputs are stored content-addressed by the
  existing SHA-256 digests (``hashing.py``); producers append manifests carrying
  monotonic per-producer sequence numbers and a SHA-256 integrity digest over
  the canonical manifest payload. Optional HMAC signing is supported when a key
  is configured; integrity checking plus strict schema validation always apply.
* **Safe import pipeline** — pulled artifacts are deduplicated by content hash,
  coverage-minimized before they touch the active corpus, and anything
  malformed (bad JSON, digest mismatch, oversize, wrong campaign) is
  quarantined and reported, never merged.
* **Status aggregation** — per-worker status files are merged into one
  aggregate JSON (health, executions, coverage, corpus deltas, crashes, sync
  lag) following the observability/campaign record conventions.
* **Resume-safe** — every write is atomic (tmp file + rename); importers track
  the last applied sequence per producer, so an interrupted pull replays
  cleanly and loses nothing.

There is no network transport here at all: sync targets are plain directories.
A root must be listed under ``distcampaign.allowlist_roots`` in configuration
before any operation is permitted (otherwise exit code 5 SAFETY). Transport is
designed to be pluggable behind :class:`ExchangeDir`, but no discovery or
implicit endpoints exist.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import targets
from .clock import Clock, now_iso
from .config import Config
from .corpus import Corpus, CorpusStore
from .errors import (
    InterruptedError_,
    NotFoundError,
    SafetyError,
    StateError,
    ValidationError,
)
from .hashing import canonical_json, sha256_bytes
from .ids import make_id
from .workspace import Workspace, validate_component

DISTCAMPAIGN_SCHEMA_VERSION = 1
MANIFEST_KIND = "distcampaign-manifest"
STATUS_KIND = "distcampaign-status"
QUARANTINE_KIND = "distcampaign-quarantine"
AGGREGATE_KIND = "distcampaign-aggregate"

#: Per-manifest caps keep a single malicious artifact bounded.
MAX_MANIFEST_ENTRIES = 4096
MAX_BLOB_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024

#: A pull staging more than this many fresh entries requires ``--yes``
#: (same confirmation convention as ``research run``).
LARGE_IMPORT_ENTRIES = 10_000

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_SEQ_DIGITS = 8


# --- exchange format ---------------------------------------------------------

def _atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically (tmp file + rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def manifest_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the manifest minus its integrity block (the signed material)."""
    return {k: v for k, v in manifest.items() if k != "integrity"}


def manifest_digest(manifest: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of the manifest payload."""
    return sha256_bytes(canonical_json(manifest_payload(manifest)).encode("utf-8"))


def sign_manifest(manifest: dict[str, Any], key: str) -> dict[str, Any]:
    """Attach an optional HMAC-SHA256 signature over the manifest payload.

    Signing is planned-but-optional: unsigned manifests remain valid as long as
    their SHA-256 integrity digest matches. When both sides configure a key,
    signatures are enforced on import.
    """
    integrity = dict(manifest.get("integrity") or {})
    mac = hmac.new(key.encode("utf-8"),
                   canonical_json(manifest_payload(manifest)).encode("utf-8"),
                   hashlib.sha256).hexdigest()
    integrity["hmac_sha256"] = mac
    out = dict(manifest)
    out["integrity"] = integrity
    return out


def build_manifest(*, campaign_id: str, producer: str, sequence: int,
                   entries: list[dict[str, Any]], target: str | None = None,
                   created_at: str | None = None) -> dict[str, Any]:
    """Build an integrity-stamped manifest for a batch of exported inputs."""
    manifest = {
        "schema_version": DISTCAMPAIGN_SCHEMA_VERSION,
        "kind": MANIFEST_KIND,
        "campaign_id": campaign_id,
        "producer": producer,
        "sequence": int(sequence),
        "created_at": created_at or now_iso(),
        "target": target,
        "entries": entries,
    }
    manifest["integrity"] = {"algorithm": "sha256",
                             "manifest_sha256": manifest_digest(manifest)}
    return manifest


def validate_manifest(raw: bytes | str, *, hmac_key: str | None = None
                      ) -> dict[str, Any]:
    """Strictly validate a raw manifest document.

    Raises :class:`ValidationError` for any schema/integrity deviation and
    :class:`SafetyError` when an HMAC signature is configured but does not
    match. Returns the parsed manifest.
    """
    try:
        manifest = json.loads(raw)
    except ValueError as exc:
        raise ValidationError(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValidationError("manifest must be a JSON object")

    def need(cond: bool, msg: str) -> None:
        if not cond:
            raise ValidationError(msg)

    need(manifest.get("schema_version") == DISTCAMPAIGN_SCHEMA_VERSION,
         f"unsupported manifest schema_version "
         f"(want {DISTCAMPAIGN_SCHEMA_VERSION})")
    need(manifest.get("kind") == MANIFEST_KIND,
         f"manifest kind must be '{MANIFEST_KIND}'")
    for field in ("campaign_id", "producer"):
        value = manifest.get(field)
        need(isinstance(value, str) and bool(value.strip()),
             f"manifest requires a non-empty '{field}'")
        validate_component(value, what=f"manifest {field}")
    sequence = manifest.get("sequence")
    need(isinstance(sequence, int) and not isinstance(sequence, bool)
         and sequence >= 1, "manifest 'sequence' must be an integer >= 1")
    need(isinstance(manifest.get("created_at"), str)
         and bool(manifest["created_at"].strip()),
         "manifest requires 'created_at'")
    entries = manifest.get("entries")
    need(isinstance(entries, list), "'entries' must be an array")
    need(len(entries) <= MAX_MANIFEST_ENTRIES,
         f"manifest exceeds {MAX_MANIFEST_ENTRIES} entries")
    for i, entry in enumerate(entries):
        need(isinstance(entry, dict), f"entry #{i} must be an object")
        sha = entry.get("sha256")
        need(isinstance(sha, str) and _SHA_RE.match(sha),
             f"entry #{i} needs a lowercase hex sha256")
        size = entry.get("size")
        need(isinstance(size, int) and not isinstance(size, bool)
             and 0 <= size <= MAX_BLOB_BYTES,
             f"entry #{i} size out of range")
        features = entry.get("coverage_features", [])
        need(isinstance(features, list),
             f"entry #{i} coverage_features must be an array")
    integrity = manifest.get("integrity")
    need(isinstance(integrity, dict), "manifest requires an integrity block")
    need(integrity.get("algorithm") == "sha256",
         "integrity algorithm must be 'sha256'")
    need(integrity.get("manifest_sha256") == manifest_digest(manifest),
         "manifest integrity digest mismatch")
    expected_mac = integrity.get("hmac_sha256")
    if hmac_key is not None:
        signed = sign_manifest(dict(manifest), hmac_key)
        need(expected_mac == signed["integrity"]["hmac_sha256"],
             "manifest HMAC signature mismatch")
    # A signature present without a locally configured key leaves authenticity
    # unverifiable; structural integrity above still applies.
    return manifest


class ExchangeDir:
    """    Layout of one campaign's slice inside the shared sync root::

        <root>/<campaign>/blobs/<sha256>
        <root>/<campaign>/manifests/<producer>-<seq>.json   (append-only)
        <root>/<campaign>/status/<producer>.json

    This is the seam for future transports: everything above it operates on
    these paths only, and nothing discovers endpoints implicitly.
    """

    def __init__(self, root: Path, campaign_id: str):
        self.root = Path(root)
        self.campaign_id = validate_component(campaign_id,
                                              what="campaign id")

    @property
    def base(self) -> Path:
        return self.root / self.campaign_id

    @property
    def blobs(self) -> Path:
        return self.base / "blobs"

    @property
    def manifests(self) -> Path:
        return self.base / "manifests"

    @property
    def status(self) -> Path:
        return self.base / "status"

    def blob_path(self, sha256: str) -> Path:
        if not _SHA_RE.match(sha256):
            raise ValidationError(f"invalid blob digest: {sha256!r}")
        return self.blobs / f"{sha256}.bin"

    def manifest_path(self, producer: str, sequence: int) -> Path:
        validate_component(producer, what="producer id")
        return self.manifests / f"{producer}-{sequence:0{_SEQ_DIGITS}d}.json"

    def status_path(self, producer: str) -> Path:
        validate_component(producer, what="producer id")
        return self.status / f"{producer}.json"

    def list_manifests(self) -> list[tuple[int, str, Path]]:
        """All well-named manifests as sorted ``(sequence, producer, path)``."""
        out: list[tuple[int, str, Path]] = []
        if not self.manifests.is_dir():
            return out
        for path in sorted(self.manifests.glob("*.json")):
            stem = path.stem
            if "-" not in stem:
                continue
            producer, _, seq_text = stem.rpartition("-")
            if not seq_text.isdigit() or len(seq_text) != _SEQ_DIGITS:
                continue
            try:
                validate_component(producer, what="producer id")
            except ValidationError:
                continue
            out.append((int(seq_text), producer, path))
        return sorted(out)


# --- allowlist enforcement ----------------------------------------------------

def resolve_sync_root(config: Config, requested: str | None = None) -> Path:
    """Resolve the shared sync directory against the explicit allowlist.

    Distributed mode is strictly opt-in: with no ``distcampaign.allowlist_roots``
    configured every request fails closed with exit code 5. The resolved root
    must sit at-or-under exactly one allowlisted root (the leaf itself may be
    created lazily by export). No default endpoint exists.
    """
    allowlist = config.get("distcampaign.allowlist_roots") or []
    if not isinstance(allowlist, list) or not allowlist:
        raise SafetyError(
            "distributed campaign sync is opt-in and disabled: add the shared "
            "directory to 'distcampaign.allowlist_roots' in your workspace "
            "config first")
    root_str = requested or config.get("distcampaign.sync_root")
    if not root_str or not isinstance(root_str, str):
        raise ValidationError(
            "no sync root given; pass --sync-root or set "
            "'distcampaign.sync_root'")
    resolved = Path(root_str).expanduser().resolve()
    for allowed in allowlist:
        if not isinstance(allowed, str) or not allowed.strip():
            continue
        allowed_resolved = Path(allowed).expanduser().resolve()
        if resolved == allowed_resolved or allowed_resolved in resolved.parents:
            # The leaf may not exist yet (export creates it lazily); import
            # surfaces a stable NotFoundError when there is nothing to pull.
            return resolved
    raise SafetyError(
        f"sync root '{resolved}' is not allowlisted; distributed sync only "
        f"operates inside explicitly allowed directories "
        f"({len([a for a in allowlist if isinstance(a, str)])} configured)")


# --- worker state (resume bookkeeping) ----------------------------------------

def _state_rel(campaign_id: str, producer: str) -> str:
    return f"research/distcampaign/state-{campaign_id}-{producer}.json"


def load_state(ws: Workspace, campaign_id: str, producer: str) -> dict[str, Any]:
    rel = _state_rel(campaign_id, producer)
    if ws.path(rel).exists():
        data = ws.read_json(rel)
        if isinstance(data, dict) and data.get("schema_version") \
                == DISTCAMPAIGN_SCHEMA_VERSION:
            return data
    return {
        "schema_version": DISTCAMPAIGN_SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "producer": producer,
        "last_sequence": 0,
        "applied_sequences": [],
        "exported_shas": [],
        "imported_shas": [],
    }


def save_state(ws: Workspace, state: dict[str, Any]) -> None:
    ws.write_json(_state_rel(state["campaign_id"], state["producer"]), state)


def _known_imported(workspace: Workspace, campaign_id: str) -> set[str]:
    """Union of every locally recorded imported sha for ``campaign_id``."""
    base = workspace.dir("research") / "distcampaign"
    known: set[str] = set()
    if not base.is_dir():
        return known
    for path in sorted(base.glob(f"state-{campaign_id}-*.json")):
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if isinstance(state, dict):
            shas = state.get("imported_shas", [])
            if isinstance(shas, list):
                known.update(s for s in shas if isinstance(s, str))
    return known


# --- coordination engine --------------------------------------------------------

class DistCampaignSync:
    """Export/import/status operations against one allowlisted exchange."""

    def __init__(self, workspace: Workspace, config: Config | None = None,
                 *, hmac_key: str | None = None):
        self.ws = workspace
        self.config = config or Config({})
        self.corpora = CorpusStore(workspace)
        # An empty-string key means "no signing"; normalize once here.
        self.hmac_key = hmac_key or None

    # -- export ------------------------------------------------------------
    def export(self, *, sync_root: Path, campaign_id: str, producer: str,
               corpus: Corpus, session_stats: dict[str, Any] | None = None
               ) -> dict[str, Any]:
        """Append one manifest exporting not-yet-exported corpus inputs.

        Blobs are content-addressed, so re-exports are byte-identical and
        harmless. The sequence number is derived from both local state and the
        exchange directory itself, so a crash between writing the manifest and
        updating local state can never overwrite an existing manifest.
        """
        ex = ExchangeDir(sync_root, campaign_id)
        state = load_state(self.ws, campaign_id, producer)
        # Anything this workspace ever imported from *any* producer is already
        # known to the campaign; re-exporting it would only waste blobs.
        foreign = _known_imported(self.ws, campaign_id)
        already = set(state["exported_shas"])
        pending = sorted(
            (tc for tc in corpus.testcases
             if tc["sha256"] not in already and tc["sha256"] not in foreign),
            key=lambda tc: tc["sha256"])

        disk_sequences = [seq for seq, prod, _ in ex.list_manifests()
                          if prod == producer]
        next_seq = max([*disk_sequences, state["last_sequence"]], default=0) + 1

        entries: list[dict[str, Any]] = []
        for tc in pending:
            data = self.corpora.read_bytes(corpus, tc["sha256"])
            observed = sha256_bytes(data)
            if observed != tc["sha256"]:
                raise StateError(
                    f"local corpus blob failed its own digest: {tc['sha256']}")
            _atomic_write(ex.blob_path(observed), data)
            entries.append({
                "sha256": observed,
                "size": len(data),
                "coverage_features": sorted(
                    tc.get("coverage_features") or []),
            })

        manifest = build_manifest(
            campaign_id=campaign_id, producer=producer, sequence=next_seq,
            entries=entries, target=corpus.target)
        if self.hmac_key:
            manifest = sign_manifest(manifest, self.hmac_key)
        _atomic_write(ex.manifest_path(producer, next_seq),
                      json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
                      + b"\n")

        state["last_sequence"] = next_seq
        state["applied_sequences"] = sorted(
            set(state["applied_sequences"]) | {next_seq})
        state["exported_shas"] = sorted(
            already | {e["sha256"] for e in entries})
        save_state(self.ws, state)

        stats = session_stats or {}
        coverage = stats.get("coverage")
        if isinstance(coverage, dict):
            feature_count = len(coverage.get("features", []) or [])
        else:
            feature_count = int(stats.get("coverage_features", 0) or 0)
        self.publish_status(
            sync_root=sync_root, campaign_id=campaign_id, producer=producer,
            executions=int(stats.get("executed", 0)),
            crashes=int(stats.get("crashes", 0)),
            unique_crashes=int(stats.get("unique_crashes", 0)),
            corpus_size=len(self.corpora.get(corpus.id).testcases),
            coverage_features=feature_count,
            health=str(stats.get("status") or "ok"))
        return {
            "campaign_id": campaign_id,
            "producer": producer,
            "sequence": next_seq,
            "exported": len(entries),
            "skipped_already_exported": len(already & {tc["sha256"] for tc in
                                                       corpus.testcases}),
            "corpus_size": len(corpus.testcases),
            "manifest_sha256": manifest["integrity"]["manifest_sha256"],
            "signed": bool(self.hmac_key),
        }

    def publish_status(self, *, sync_root: Path, campaign_id: str,
                       producer: str, executions: int = 0, crashes: int = 0,
                       unique_crashes: int = 0, corpus_size: int = 0,
                       coverage_features: int = 0, health: str = "ok",
                       session_id: str = "") -> dict[str, Any]:
        """Atomically publish this worker's status snapshot for aggregation."""
        record = {
            "schema_version": DISTCAMPAIGN_SCHEMA_VERSION,
            "kind": STATUS_KIND,
            "campaign_id": campaign_id,
            "producer": producer,
            "updated_at": now_iso(),
            "health": health or "ok",
            "session_id": session_id or "",
            "executions": max(0, int(executions)),
            "crashes": max(0, int(crashes)),
            "unique_crashes": max(0, int(unique_crashes)),
            "corpus_size": max(0, int(corpus_size)),
            "coverage_features": max(0, int(coverage_features)),
        }
        ex = ExchangeDir(sync_root, campaign_id)
        _atomic_write(ex.status_path(producer),
                      json.dumps(record, indent=2, sort_keys=True).encode("utf-8")
                      + b"\n")
        return record

    # -- import --------------------------------------------------------------
    def pull(self, *, sync_root: Path, campaign_id: str,
             exclude_producer: str | None = None,
             active_corpus: Corpus | None = None,
             target_id: str | None = None,
             assume_yes: bool = False) -> dict[str, Any]:
        """Pull, verify and merge all not-yet-applied remote manifests.

        Idempotent and resume-safe: per-producer state advances only after a
        manifest has been fully applied, and every merge step deduplicates by
        content hash, so replaying after interruption loses nothing and
        duplicates cannot corrupt the active corpus. Malformed artifacts are
        quarantined and reported instead of failing the whole pull.
        """
        ex = ExchangeDir(sync_root, campaign_id)
        if not ex.manifests.is_dir():
            raise NotFoundError(
                f"no manifests found for campaign '{campaign_id}' under {ex.root}")

        target = None
        if target_id:
            if not targets.is_registered(target_id):
                raise ValidationError(f"unknown target '{target_id}'")
            target = targets.create(target_id)

        manifests = ex.list_manifests()
        states = {p: load_state(self.ws, campaign_id, p)
                  for _, p, _ in manifests}
        total_pending = sum(len(self._pending_entries(states[prod], path))
                            for _, prod, path in manifests
                            if prod != exclude_producer)
        if total_pending > LARGE_IMPORT_ENTRIES and not assume_yes:
            raise InterruptedError_(
                f"pull would stage {total_pending} new entries; re-run with "
                "--yes to confirm this resource-consuming import")

        summary: dict[str, Any] = {
            "campaign_id": campaign_id,
            "manifests_applied": 0,
            "manifests_quarantined": 0,
            "manifests_skipped_current": 0,
            "unrecognized_files": 0,
            "entries_seen": 0,
            "imported": 0,
            "duplicates": 0,
            "quarantined": [],
            "producers": {},
        }
        known_names = {path.name for _, _, path in manifests}
        summary["unrecognized_files"] = sum(
            1 for p in ex.manifests.glob("*.json") if p.name not in known_names)

        for sequence, producer, path in manifests:
            if producer == exclude_producer:
                continue
            state = states[producer]
            if sequence <= state["last_sequence"]:
                summary["manifests_skipped_current"] += 1
                continue
            self._apply_manifest(ex, path, sequence, producer, state, summary,
                                 campaign_id=campaign_id,
                                 active_corpus=active_corpus, target=target)

        for producer, state in states.items():
            summary["producers"][producer] = {
                "last_sequence": state["last_sequence"],
                "applied": len(state["applied_sequences"]),
            }
        active_corpus = active_corpus or self._default_corpus(campaign_id)
        summary["corpus_size"] = len(
            self.corpora.get(active_corpus.id).testcases)
        return summary

    @staticmethod
    def _pending_entries(state: dict[str, Any], path: Path) -> list[Any]:
        """Entries in ``path`` beyond the applied sequence (best-effort).

        Used only for the large-import confirmation gate before any validation
        work; unreadable manifests count as zero because they are quarantined —
        never silently staged — during the real pass.
        """
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                return []
            if int(manifest.get("sequence", 0)) <= state["last_sequence"]:
                return []
            entries = manifest.get("entries", [])
            return entries if isinstance(entries, list) else []
        except (OSError, ValueError, TypeError):
            return []

    def _apply_manifest(self, ex: ExchangeDir, path: Path, sequence: int,
                        producer: str, state: dict[str, Any],
                        summary: dict[str, Any], *, campaign_id: str,
                        active_corpus: Corpus | None,
                        target: Any) -> None:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            self._quarantine(campaign_id=campaign_id, source=path.name,
                             reason=f"unreadable manifest: {exc}")
            summary["manifests_quarantined"] += 1
            summary["quarantined"].append(f"{path.name}:unreadable")
            return
        if len(raw) > MAX_MANIFEST_BYTES:
            self._quarantine(campaign_id=campaign_id, source=path.name,
                             reason=f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
            summary["manifests_quarantined"] += 1
            summary["quarantined"].append(f"{path.name}:oversize")
            return
        try:
            manifest = validate_manifest(raw, hmac_key=self.hmac_key)
            if manifest["campaign_id"] != campaign_id:
                raise ValidationError(
                    f"manifest declares campaign '{manifest['campaign_id']}' "
                    f"but was found in '{campaign_id}'")
            if manifest["producer"] != producer:
                raise ValidationError(
                    f"manifest filename names producer '{producer}' but "
                    f"content declares '{manifest['producer']}'")
        except (ValidationError, SafetyError) as exc:
            self._quarantine(campaign_id=campaign_id, source=path.name,
                             reason=str(exc))
            summary["manifests_quarantined"] += 1
            summary["quarantined"].append(f"{path.name}:invalid")
            return

        candidates: dict[str, tuple[bytes, list[str]]] = {}
        for entry in sorted(manifest["entries"], key=lambda e: e["sha256"]):
            sha = entry["sha256"]
            summary["entries_seen"] += 1
            blob_path = ex.blob_path(sha)
            if not blob_path.exists():
                self._quarantine(campaign_id=campaign_id,
                                 source=f"blobs/{sha}",
                                 reason="referenced blob is missing")
                summary["quarantined"].append(f"blobs/{sha}:missing")
                continue
            if blob_path.stat().st_size > MAX_BLOB_BYTES:
                self._quarantine(campaign_id=campaign_id,
                                 source=f"blobs/{sha}",
                                 reason=f"blob exceeds {MAX_BLOB_BYTES} bytes")
                summary["quarantined"].append(f"blobs/{sha}:oversize")
                continue
            data = blob_path.read_bytes()
            observed = sha256_bytes(data)
            if observed != sha:
                self._quarantine(
                    campaign_id=campaign_id, source=f"blobs/{sha}",
                    reason=f"blob digest mismatch (expected {sha}, "
                           f"got {observed})", expected=sha, observed=observed)
                summary["quarantined"].append(f"blobs/{sha}:digest-mismatch")
                continue
            candidates[sha] = (data, self._normalize_features(
                entry.get("coverage_features")))

        kept = self._minimize_candidates(candidates, target)
        corpus = active_corpus or self._default_corpus(
            campaign_id, manifest_target=manifest.get("target"))
        limit = int(self.config.get("limits.max_testcases", 100000) or 100000)
        if len(corpus.testcases) + len(kept) > limit:
            raise StateError(
                f"merging {len(kept)} imported inputs would exceed the "
                f"configured corpus limit ({limit}); pull stopped resumably "
                f"at sequence {sequence - 1} for '{producer}'")

        handled: set[str] = set(candidates)
        for sha in sorted(kept):
            data, features = kept[sha]
            added = self.corpora.add_bytes(
                corpus, data, origin="dist-import", coverage_features=features)
            if added is not None:
                summary["imported"] += 1
            else:
                summary["duplicates"] += 1
        # Every entry referenced by an applied manifest counts as handled
        # (including quarantined/duplicate ones) so replays stay idempotent.
        handled.update(e["sha256"] for e in manifest["entries"])
        state["last_sequence"] = sequence
        state["applied_sequences"] = sorted(
            set(state["applied_sequences"]) | {sequence})
        state["imported_shas"] = sorted(
            set(state["imported_shas"]) | handled)
        save_state(self.ws, state)
        summary["manifests_applied"] += 1

    # -- minimization --------------------------------------------------------
    @staticmethod
    def _normalize_features(features: Any) -> list[str]:
        normalized = coverage_normalize(features)
        return list(normalized or ())

    @staticmethod
    def _minimize_candidates(
            candidates: dict[str, tuple[bytes, list[str]]],
            target: Any) -> dict[str, tuple[bytes, list[str]]]:
        """Coverage-greedy selection over staged imports before merging.

        Mirrors the greedy set-cover phase of :meth:`CorpusStore.minimize`:
        prefer metadata features captured at discovery time, optionally query
        the authorized target adapter otherwise, and keep feature-less inputs
        conservatively (their behavior is simply unknown here, and dropping
        them could silently lose coverage).
        """
        if not candidates:
            return {}
        ordered = sorted(candidates.items())
        feature_sets: dict[str, set[str]] = {}
        for sha, (data, features) in ordered:
            feats = set(features)
            if not feats and target is not None:
                provided = coverage_adapter_features(target, data)
                if provided:
                    feats = set(provided)
            feature_sets[sha] = feats

        kept: dict[str, tuple[bytes, list[str]]] = {}
        covered: set[str] = set()
        remaining = [sha for sha, _ in ordered]
        while remaining:
            best = max(remaining,
                       key=lambda s: (len(feature_sets[s] - covered), s))
            fresh = feature_sets[best] - covered
            if not fresh:
                break
            covered.update(fresh)
            kept[best] = candidates[best]
            remaining.remove(best)
        # Feature-less inputs are kept: unknown coverage beats silent loss.
        for sha, pair in ordered:
            if not feature_sets[sha] and sha not in kept:
                kept[sha] = pair
        return kept

    # -- quarantine ------------------------------------------------------------
    def _quarantine(self, *, campaign_id: str, source: str, reason: str,
                    expected: str | None = None,
                    observed: str | None = None) -> dict[str, Any]:
        record = {
            "schema_version": DISTCAMPAIGN_SCHEMA_VERSION,
            "kind": QUARANTINE_KIND,
            "id": make_id("quarantine", campaign_id, source, reason),
            "campaign_id": campaign_id,
            "source": source,
            "reason": reason,
            "expected_sha256": expected,
            "observed_sha256": observed,
            "created_at": now_iso(),
        }
        self.ws.write_json(
            f"research/distcampaign/quarantine/{record['id']}.json", record)
        return record

    # -- corpora helpers ---------------------------------------------------------
    def _default_corpus(self, campaign_id: str,
                        manifest_target: str | None = None) -> Corpus:
        name = f"distributed-{campaign_id}"
        existing = [c for c in self.corpora.list() if c.name == name]
        if existing:
            return existing[0]
        return self.corpora.create(name, target=manifest_target)

    def get_or_default_corpus(self, campaign_id: str,
                              corpus_id: str | None = None) -> Corpus:
        if corpus_id:
            return self.corpora.get(corpus_id)
        return self._default_corpus(campaign_id)

    # -- aggregation ---------------------------------------------------------
    def aggregate_status(self, *, sync_root: Path,
                         campaign_id: str) -> dict[str, Any]:
        """Merge worker status snapshots into one aggregate JSON record."""
        ex = ExchangeDir(sync_root, campaign_id)
        workers: list[dict[str, Any]] = []
        malformed: list[dict[str, str]] = []
        now = Clock().now()
        if ex.status.is_dir():
            for path in sorted(ex.status.glob("*.json")):
                producer = path.stem
                try:
                    validate_component(producer, what="producer id")
                    record = json.loads(path.read_text(encoding="utf-8"))
                    if not isinstance(record, dict):
                        raise ValueError("status must be a JSON object")
                    if record.get("kind") != STATUS_KIND:
                        raise ValueError(
                            f"status kind must be '{STATUS_KIND}'")
                    updated = datetime.fromisoformat(
                        str(record.get("updated_at", ""))
                        .replace("Z", "+00:00"))
                    if updated.tzinfo is None:
                        updated = updated.replace(tzinfo=timezone.utc)
                except (ValueError, ValidationError, OSError) as exc:
                    malformed.append({"source": path.name,
                                      "reason": str(exc)})
                    continue
                workers.append({
                    "producer": producer,
                    "health": str(record.get("health") or "unknown"),
                    "updated_at": record.get("updated_at"),
                    "lag_seconds": max(
                        0, int((now - updated).total_seconds())),
                    "executions": int(record.get("executions", 0) or 0),
                    "crashes": int(record.get("crashes", 0) or 0),
                    "unique_crashes": int(
                        record.get("unique_crashes", 0) or 0),
                    "corpus_size": int(record.get("corpus_size", 0) or 0),
                    "coverage_features": int(
                        record.get("coverage_features", 0) or 0),
                    "session_id": str(record.get("session_id") or ""),
                })
        aggregate = {
            "schema_version": DISTCAMPAIGN_SCHEMA_VERSION,
            "kind": AGGREGATE_KIND,
            "campaign_id": campaign_id,
            "generated_at": now_iso(),
            "worker_count": len(workers),
            "workers": workers,
            "malformed_status_files": malformed,
            "totals": {
                "executions": sum(w["executions"] for w in workers),
                "crashes": sum(w["crashes"] for w in workers),
                "unique_crashes": sum(w["unique_crashes"] for w in workers),
            },
            "max_coverage_features": max(
                [w["coverage_features"] for w in workers], default=0),
            "sync_lag_seconds": max(
                [w["lag_seconds"] for w in workers], default=0),
            "corpus_deltas": self._corpus_deltas(campaign_id),
        }
        self.ws.write_json(
            f"research/distcampaign/aggregate-{campaign_id}.json", aggregate)
        return aggregate

    def _corpus_deltas(self, campaign_id: str) -> dict[str, Any]:
        deltas: dict[str, Any] = {}
        base = self.ws.dir("research") / "distcampaign"
        if not base.is_dir():
            return deltas
        prefix = f"state-{campaign_id}-"
        for path in sorted(base.glob(f"{prefix}*.json")):
            producer = path.name[len(prefix):][:-len(".json")]
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            if isinstance(state, dict):
                deltas[producer] = {
                    "exported": len(state.get("exported_shas", [])),
                    "imported": len(state.get("imported_shas", [])),
                }
        return deltas


# --- thin indirections over reusable utilities ----------------------------------

def coverage_normalize(features: Any) -> tuple[str, ...] | None:
    from .coverage import normalize_features
    return normalize_features(features)


def coverage_adapter_features(target: Any, data: bytes) -> tuple[str, ...] | None:
    result = target.execute(data)
    from .coverage import normalize_features
    return normalize_features(target.coverage_features(data, result))
