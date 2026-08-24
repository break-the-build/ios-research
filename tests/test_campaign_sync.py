"""Distributed campaign corpus synchronization (#32).

Two local fixture workers exchange corpora deterministically; malformed or
duplicate remote artifacts cannot corrupt the local workspace; distributed
mode is opt-in via the sync-root allowlist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ios_research.campaign_sync import (
    aggregate_status, ensure_allowed_path, export_bundle, import_bundle,
)
from ios_research.config import Config
from ios_research.corpus import CorpusStore
from ios_research.errors import ValidationError
from ios_research.hashing import sha256_bytes
from ios_research.workspace import Workspace
from ios_research import __version__


def _workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(tmp_path / ".ios-research")
    ws.init(framework_version=__version__, created_at="2023-11-14T22:13:20Z")
    return ws


def _seeded_corpus(ws: Workspace, name: str, payloads: list[bytes]):
    store = CorpusStore(ws)
    corpus = store.create(name, target="mock:parser")
    for data in payloads:
        store.add_bytes(corpus, data, origin="seed")
    return store, corpus


def _allow(tmp_path: Path, roots: list[str]) -> Config:
    return Config(values={"campaign": {"sync_roots": roots}})


A_INPUTS = [b"MOCK-worker-A-input-1", b"MOCK-worker-A-input-2"]
B_INPUTS = [b"MOCK-worker-B-input-1"]


class TestExport:
    def test_manifest_is_sorted_and_content_addressed(self, tmp_path):
        ws = _workspace(tmp_path)
        store, corpus = _seeded_corpus(ws, "c", list(reversed(A_INPUTS)))
        out = tmp_path / "bundle-a"
        manifest = export_bundle(ws, store, corpus, out,
                                 worker_id="worker-a", campaign_id="camp-1")
        shas = [e["sha256"] for e in manifest["entries"]]
        assert shas == sorted(shas)
        for entry in manifest["entries"]:
            data = (out / "inputs" / f"{entry['sha256']}.bin").read_bytes()
            assert sha256_bytes(data) == entry["sha256"]

    def test_export_is_idempotent_for_same_corpus_state(self, tmp_path):
        ws = _workspace(tmp_path)
        store, corpus = _seeded_corpus(ws, "c", A_INPUTS)
        m1 = export_bundle(ws, store, corpus, tmp_path / "b1",
                           worker_id="w", campaign_id="c1")
        m2 = export_bundle(ws, store, corpus, tmp_path / "b2",
                           worker_id="w", campaign_id="c1")
        assert m1["entries"] == m2["entries"]

    def test_empty_worker_id_rejected(self, tmp_path):
        ws = _workspace(tmp_path)
        store, corpus = _seeded_corpus(ws, "c", A_INPUTS)
        with pytest.raises(ValidationError):
            export_bundle(ws, store, corpus, tmp_path / "b",
                          worker_id="  ", campaign_id="c")


class TestImport:
    def test_two_workers_exchange_deterministically(self, tmp_path):
        ws_a = _workspace(tmp_path / "a")
        ws_b = _workspace(tmp_path / "b")
        store_a, corpus_a = _seeded_corpus(ws_a, "c", A_INPUTS)
        store_b, corpus_b = _seeded_corpus(ws_b, "c", B_INPUTS)

        bundle_a = tmp_path / "exchange" / "a"
        export_bundle(ws_a, store_a, corpus_a, bundle_a,
                      worker_id="worker-a", campaign_id="camp-1")

        report = import_bundle(ws_b, store_b, corpus_b, bundle_a)
        assert report["accepted_count"] == len(A_INPUTS)
        assert report["rejected_count"] == 0
        shas_b = {tc["sha256"] for tc in corpus_b.testcases}
        assert {sha256_bytes(x) for x in A_INPUTS} <= shas_b

        # And the reverse direction.
        bundle_b = tmp_path / "exchange" / "b"
        export_bundle(ws_b, store_b, corpus_b, bundle_b,
                      worker_id="worker-b", campaign_id="camp-1")
        report_back = import_bundle(ws_a, store_a, corpus_a, bundle_b)
        assert report_back["accepted_count"] == len(B_INPUTS)

    def test_reimport_is_all_duplicates_resume_safe(self, tmp_path):
        ws = _workspace(tmp_path)
        store, corpus = _seeded_corpus(ws, "c", [])
        bundle = tmp_path / "bundle"
        ws_src = _workspace(tmp_path / "src")
        store_src, corpus_src = _seeded_corpus(ws_src, "c", A_INPUTS)
        export_bundle(ws_src, store_src, corpus_src, bundle,
                      worker_id="w", campaign_id="c")

        first = import_bundle(ws, store, corpus, bundle)
        assert first["accepted_count"] == len(A_INPUTS)
        # Simulate interruption: run import again from scratch.
        ws2 = _workspace(tmp_path / "ws2")
        store2, corpus2 = _seeded_corpus(ws2, "c", [])
        second = import_bundle(ws2, store2, corpus2, bundle)
        assert second["accepted_count"] == len(A_INPUTS)
        # Re-import into the already-populated corpus: all duplicates.
        again = import_bundle(ws, store, corpus, bundle)
        assert again["accepted_count"] == 0
        assert again["duplicates"] == len(A_INPUTS)
        assert len(corpus.testcases) == len(A_INPUTS)

    def test_dry_run_makes_no_changes(self, tmp_path):
        ws = _workspace(tmp_path)
        store, corpus = _seeded_corpus(ws, "c", [])
        bundle = tmp_path / "bundle"
        ws_src = _workspace(tmp_path / "src")
        store_src, corpus_src = _seeded_corpus(ws_src, "c", A_INPUTS)
        export_bundle(ws_src, store_src, corpus_src, bundle,
                      worker_id="w", campaign_id="c")
        report = import_bundle(ws, store, corpus, bundle, dry_run=True)
        assert report["accepted_count"] == len(A_INPUTS)
        assert report["dry_run"] is True
        assert len(corpus.testcases) == 0
        assert not (ws.root / "campaign" / "imports").exists()

    def test_corrupt_input_rejected_workspace_untouched(self, tmp_path):
        ws = _workspace(tmp_path)
        store, corpus = _seeded_corpus(ws, "c", [])
        bundle = tmp_path / "bundle"
        ws_src = _workspace(tmp_path / "src")
        store_src, corpus_src = _seeded_corpus(ws_src, "c", A_INPUTS)
        export_bundle(ws_src, store_src, corpus_src, bundle,
                      worker_id="w", campaign_id="c")
        # Tamper with one input file after export.
        victim = manifest = json.loads(
            (bundle / "manifest.json").read_text())["entries"][0]["sha256"]
        (bundle / "inputs" / f"{victim}.bin").write_bytes(b"tampered")

        report = import_bundle(ws, store, corpus, bundle)
        assert report["rejected_count"] == 1
        assert report["rejected"][0]["reason"] == \
            "sha256 mismatch (corrupt or tampered)"
        assert report["accepted_count"] == len(A_INPUTS) - 1
        # The tampered input must not be in the corpus under its claimed hash.
        shas = {tc["sha256"] for tc in corpus.testcases}
        assert victim not in shas

    def test_missing_input_file_rejected(self, tmp_path):
        ws = _workspace(tmp_path)
        store, corpus = _seeded_corpus(ws, "c", [])
        bundle = tmp_path / "bundle"
        manifest = {
            "schema": 1, "kind": "ios-research-campaign-bundle",
            "campaign_id": "c", "worker_id": "w", "corpus_name": "x",
            "exported_at": "2023-11-14T22:13:20Z",
            "entries": [{"sha256": "ab" * 32, "size": 2, "origin": "seed",
                         "coverage_features": []}],
            "stats": {},
        }
        (bundle / "inputs").mkdir(parents=True)
        (bundle / "manifest.json").write_text(json.dumps(manifest))
        report = import_bundle(ws, store, corpus, bundle)
        assert report["rejected_count"] == 1
        assert report["rejected"][0]["reason"] == "input file missing"
        assert len(corpus.testcases) == 0

    def test_malformed_manifest_rejected_entirely(self, tmp_path):
        ws = _workspace(tmp_path)
        store, corpus = _seeded_corpus(ws, "c", [])
        bundle = tmp_path / "bundle"
        bundle.mkdir()
        (bundle / "manifest.json").write_text("{broken")
        with pytest.raises(ValidationError):
            import_bundle(ws, store, corpus, bundle)
        assert len(corpus.testcases) == 0

        bundle2 = tmp_path / "bundle2"
        bundle2.mkdir()
        (bundle2 / "manifest.json").write_text(json.dumps({"schema": 99}))
        with pytest.raises(ValidationError):
            import_bundle(ws, store, corpus, bundle2)

    def test_require_new_coverage_skips_known_features(self, tmp_path):
        ws = _workspace(tmp_path)
        store, corpus = _seeded_corpus(ws, "c", [])
        # Seed the corpus with an input already carrying feature F1.
        store.add_bytes(corpus, b"existing", origin="seed",
                        coverage_features=["f1"])
        bundle = tmp_path / "bundle"
        (bundle / "inputs").mkdir(parents=True)
        new_payload = b"fresh-input"
        sha = sha256_bytes(new_payload)
        (bundle / "inputs" / f"{sha}.bin").write_bytes(new_payload)
        manifest = {
            "schema": 1, "kind": "ios-research-campaign-bundle",
            "campaign_id": "c", "worker_id": "w", "corpus_name": "x",
            "exported_at": "2023-11-14T22:13:20Z",
            "entries": [
                {"sha256": sha, "size": len(new_payload), "origin": "mutation",
                 "coverage_features": ["f1"]},
            ],
            "stats": {},
        }
        (bundle / "manifest.json").write_text(json.dumps(manifest))

        skipped = import_bundle(ws, store, corpus, bundle,
                                require_new_coverage=True)
        assert skipped["coverage_skipped"] == 1
        assert skipped["accepted_count"] == 0
        allowed = import_bundle(ws, store, corpus, bundle)
        assert allowed["accepted_count"] == 1


class TestAllowlist:
    def test_path_outside_sync_roots_refused(self, tmp_path):
        ws = _workspace(tmp_path / "ws-root-dir")
        config = _allow(tmp_path, [str(tmp_path / "sync")])
        with pytest.raises(ValidationError) as exc:
            ensure_allowed_path(tmp_path / "elsewhere", ws, config)
        assert "campaign.sync_roots" in str(exc.value.message)

    def test_path_under_sync_root_allowed(self, tmp_path):
        ws = _workspace(tmp_path / "ws-root-dir")
        root = tmp_path / "sync"
        config = _allow(tmp_path, [str(root)])
        resolved = ensure_allowed_path(root / "bundle", ws, config)
        assert resolved == (root / "bundle").resolve()

    def test_workspace_internal_paths_always_allowed(self, tmp_path):
        ws = _workspace(tmp_path / "ws-root-dir")
        config = _allow(tmp_path, [])
        resolved = ensure_allowed_path(ws.root / "campaign" / "b", ws, config)
        assert resolved.exists() or str(resolved).startswith(str(ws.root))


class TestStatus:
    def test_aggregates_worker_deltas_and_lag(self, tmp_path):
        ws = _workspace(tmp_path)
        store, corpus = _seeded_corpus(ws, "c", [])
        for worker, payloads in (("worker-a", A_INPUTS),
                                 ("worker-b", B_INPUTS)):
            ws_src = _workspace(tmp_path / f"src-{worker}")
            store_src, corpus_src = _seeded_corpus(ws_src, "c", payloads)
            bundle = tmp_path / f"bundle-{worker}"
            export_bundle(ws_src, store_src, corpus_src, bundle,
                          worker_id=worker, campaign_id="camp-1")
            import_bundle(ws, store, corpus, bundle)

        status = aggregate_status(ws, campaign_id="camp-1")
        assert status["worker_count"] == 2
        assert status["total_inputs_imported"] == len(A_INPUTS) + len(B_INPUTS)
        assert {w["worker_id"] for w in status["workers"]} == \
            {"worker-a", "worker-b"}
        assert status["newest_sync"] != ""
        assert status["manifests_seen"] == 2

    def test_campaign_filter(self, tmp_path):
        ws = _workspace(tmp_path)
        store, corpus = _seeded_corpus(ws, "c", [])
        ws_src = _workspace(tmp_path / "src")
        store_src, corpus_src = _seeded_corpus(ws_src, "c", A_INPUTS)
        bundle = tmp_path / "bundle"
        export_bundle(ws_src, store_src, corpus_src, bundle,
                      worker_id="w", campaign_id="other-campaign")
        import_bundle(ws, store, corpus, bundle)
        assert aggregate_status(ws, campaign_id="camp-1")["manifests_seen"] == 0
        assert aggregate_status(ws)["manifests_seen"] == 1
