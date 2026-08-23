"""Corpus synchronization: bundles, allowlisted import, aggregate status (#32)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ios_research.corpus import CorpusStore
from ios_research.errors import SafetyError, ValidationError
from ios_research.hashing import sha256_bytes as sha
from ios_research.sync import (
    BUNDLE_KIND, export_corpus, import_bundle, aggregate_status,
)
from ios_research.workspace import Workspace
from ios_research import __version__, clock


def _workspace(root: Path) -> Workspace:
    ws = Workspace(root / ".ios-research")
    ws.init(framework_version=__version__, created_at=clock.now_iso())
    return ws


def _seed(ws: Workspace, name: str, items: list[tuple[bytes, list[str]]]):
    store = CorpusStore(ws)
    corpus = store.create(name, target="mock:echo")
    for data, features in items:
        assert store.add_bytes(corpus, data, origin="seed",
                               coverage_features=features) is not None
    return corpus.id


SHARED_1 = (b"shared-input-one", ["feat:s1a", "feat:s1b"])
SHARED_2 = (b"shared-input-two", ["feat:s2"])
UNIQUE_A = (b"worker-a-exclusive", ["feat:a-only", "feat:s2"])
UNIQUE_B = (b"worker-b-exclusive", ["feat:b-only"])


def test_two_workers_exchange_deterministically_and_resume(tmp_path):
    a_ws = _workspace(tmp_path / "worker-a")
    b_ws = _workspace(tmp_path / "worker-b")
    corpus_a = _seed(a_ws, "alpha", [SHARED_1, SHARED_2, UNIQUE_A])
    corpus_b = _seed(b_ws, "beta", [SHARED_1, SHARED_2, UNIQUE_B])

    exchange = tmp_path / "exchange"
    bundle_a = exchange / "a"
    bundle_b = exchange / "b"
    out_a = export_corpus(a_ws, corpus_a, bundle_a, worker_id="worker-a")
    out_b = export_corpus(b_ws, corpus_b, bundle_b, worker_id="worker-b")
    assert out_a["entries"] == 3 and out_b["entries"] == 3
    manifest_a = json.loads((bundle_a / "bundle.json").read_text())
    assert manifest_a["kind"] == BUNDLE_KIND
    assert [e["sha256"] for e in manifest_a["entries"]] == sorted(
        e["sha256"] for e in manifest_a["entries"])

    # Same corpus => byte-identical bundle.json.
    repeat = exchange / "a-again"
    export_corpus(a_ws, corpus_a, repeat, worker_id="worker-a")
    assert (repeat / "bundle.json").read_bytes() == \
        (bundle_a / "bundle.json").read_bytes()

    # Cross-import: A -> B and B -> A merge to the identical set of shas.
    roots = [str(exchange)]
    into_b = import_bundle(b_ws, corpus_b, bundle_a, allowed_roots=roots)
    into_a = import_bundle(a_ws, corpus_a, bundle_b, allowed_roots=roots)
    merged_a = CorpusStore(a_ws).get(corpus_a).shas
    merged_b = CorpusStore(b_ws).get(corpus_b).shas
    assert merged_a == merged_b
    assert merged_a == {sha(SHARED_1[0]), sha(SHARED_2[0]),
                        sha(UNIQUE_A[0]), sha(UNIQUE_B[0])}
    assert into_b["duplicates_skipped"] == 2 and into_b["imported"] == 1
    assert into_a["duplicates_skipped"] == 2 and into_a["imported"] == 1

    # Idempotent resume: re-importing after interruption adds nothing.
    again_b = import_bundle(b_ws, corpus_b, bundle_a, allowed_roots=roots)
    again_a = import_bundle(a_ws, corpus_a, bundle_b, allowed_roots=roots)
    assert again_b["imported"] == 0 and again_a["imported"] == 0
    assert again_b["duplicates_skipped"] == 3
    assert CorpusStore(b_ws).get(corpus_b).shas == merged_b


def test_tampered_input_bytes_abort_import_atomically(tmp_path):
    src_ws = _workspace(tmp_path / "src")
    dst_ws = _workspace(tmp_path / "dst")
    corpus_src = _seed(src_ws, "src", [SHARED_1, UNIQUE_A])
    corpus_dst = _seed(dst_ws, "dst", [SHARED_1])

    bundle = tmp_path / "exchange" / "tamper"
    export_corpus(src_ws, corpus_src, bundle)
    entry = json.loads((bundle / "bundle.json").read_text())["entries"][0]
    target_file = bundle / "inputs" / f"{entry['sha256']}.bin"
    original = target_file.read_bytes()
    target_file.write_bytes(original + b"x")  # keep manifest, mutate bytes

    before = CorpusStore(dst_ws).get(corpus_dst).shas
    with pytest.raises(ValidationError, match=entry["sha256"][:12]):
        import_bundle(dst_ws, corpus_dst, bundle,
                      allowed_roots=[str(bundle)])
    assert CorpusStore(dst_ws).get(corpus_dst).shas == before


def test_tampered_manifest_fails_hash_verification(tmp_path):
    src_ws = _workspace(tmp_path / "src")
    dst_ws = _workspace(tmp_path / "dst")
    corpus_src = _seed(src_ws, "src", [SHARED_1])
    corpus_dst = _seed(dst_ws, "dst", [])

    bundle = tmp_path / "exchange" / "flipped"
    export_corpus(src_ws, corpus_src, bundle)
    manifest_path = bundle / "bundle.json"
    raw = manifest_path.read_text()
    assert '"local"' in raw
    manifest_path.write_text(raw.replace('"local"', "false"), encoding="utf-8")

    with pytest.raises(ValidationError, match="manifest hash mismatch"):
        import_bundle(dst_ws, corpus_dst, bundle, allowed_roots=[str(bundle)])
    assert CorpusStore(dst_ws).get(corpus_dst).testcases == []


def test_malformed_entries_are_rejected_before_any_write(tmp_path):
    src_ws = _workspace(tmp_path / "src")
    dst_ws = _workspace(tmp_path / "dst")
    corpus_src = _seed(src_ws, "src", [SHARED_1])
    corpus_dst = _seed(dst_ws, "dst", [])

    bad_sha = tmp_path / "exchange" / "bad-sha"
    export_corpus(src_ws, corpus_src, bad_sha)
    path = bad_sha / "bundle.json"
    manifest = json.loads(path.read_text())
    manifest["entries"][0]["sha256"] = "zz" + manifest["entries"][0]["sha256"][2:]
    body = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    from ios_research.hashing import canonical_json, sha256_text
    manifest["manifest_sha256"] = sha256_text(canonical_json(body))
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValidationError, match="not valid lowercase hex"):
        import_bundle(dst_ws, corpus_dst, bad_sha,
                      allowed_roots=[str(bad_sha)])

    unknown_field = tmp_path / "exchange" / "unknown-field"
    export_corpus(src_ws, corpus_src, unknown_field)
    path = unknown_field / "bundle.json"
    manifest = json.loads(path.read_text())
    manifest["entries"][0]["exploit"] = True   # unknown fields are rejected
    body = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    manifest["manifest_sha256"] = sha256_text(canonical_json(body))
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValidationError, match="unknown fields.*exploit"):
        import_bundle(dst_ws, corpus_dst, unknown_field,
                      allowed_roots=[str(unknown_field)])
    assert CorpusStore(dst_ws).get(corpus_dst).testcases == []


def test_import_requires_explicit_allowlisted_root(tmp_path):
    src_ws = _workspace(tmp_path / "src")
    dst_ws = _workspace(tmp_path / "dst")
    corpus_src = _seed(src_ws, "src", [SHARED_1])
    corpus_dst = _seed(dst_ws, "dst", [])
    bundle = tmp_path / "exchange" / "guarded"
    export_corpus(src_ws, corpus_src, bundle)

    with pytest.raises(SafetyError, match="--allow-root"):
        import_bundle(dst_ws, corpus_dst, bundle, allowed_roots=[])
    # Directory exists but outside every allowlisted root => fail closed.
    with pytest.raises(SafetyError, match="allowlisted root"):
        import_bundle(dst_ws, corpus_dst, bundle,
                      allowed_roots=[str(tmp_path / "elsewhere")])
    # Path traversal cannot escape the allowlist via symlinked parents.
    link = tmp_path / "link"
    link.symlink_to(bundle)
    with pytest.raises(SafetyError):
        import_bundle(dst_ws, corpus_dst, link,
                      allowed_roots=[str(tmp_path / "elsewhere")])


def test_minimize_shrinks_redundant_imports_preserving_features(tmp_path):
    src_ws = _workspace(tmp_path / "src")
    dst_ws = _workspace(tmp_path / "dst")
    corpus_src = _seed(src_ws, "src", [
        (b"redundant-one", ["feat:x", "feat:y"]),
        (b"redundant-two", ["feat:x", "feat:y"]),   # same features
        (b"solo", ["feat:z"]),
    ])
    corpus_dst = _seed(dst_ws, "dst", [])

    bundle = tmp_path / "exchange" / "min"
    export_corpus(src_ws, corpus_src, bundle)
    plain = import_bundle(dst_ws, corpus_dst, bundle,
                          allowed_roots=[str(bundle)])
    assert plain["imported"] == 3

    other = _workspace(tmp_path / "other")
    corpus_other = _seed(other, "other", [])
    minimized = import_bundle(other, corpus_other, bundle,
                              allowed_roots=[str(bundle)], minimize=True)
    assert minimized["imported"] == 2
    assert minimized["minimize_dropped"] == 1
    kept = CorpusStore(other).get(corpus_other).testcases
    covered = {f for tc in kept for f in tc["coverage_features"]}
    assert covered == {"feat:x", "feat:y", "feat:z"}  # all features preserved
    shas = {tc["sha256"] for tc in kept}
    assert len(shas) == 2


def test_aggregate_status_reports_lag_and_tolerates_missing_workers(tmp_path):
    a_ws = _workspace(tmp_path / "worker-a")
    b_ws = _workspace(tmp_path / "worker-b")
    corpus_a = _seed(a_ws, "a", [SHARED_1, UNIQUE_A])
    corpus_b = _seed(b_ws, "b", [SHARED_2])
    dir_a = tmp_path / "rollup" / "a"
    dir_b = tmp_path / "rollup" / "b"
    export_corpus(a_ws, corpus_a, dir_a, worker_id="worker-a", cursor=10)
    export_corpus(b_ws, corpus_b, dir_b, worker_id="worker-b", cursor=4)
    (dir_b / "status.json").write_text(json.dumps(
        {"executions": 4000, "crashes": 2}), encoding="utf-8")

    missing = str(tmp_path / "rollup" / "ghost")
    dirs = [str(dir_a), str(dir_b), missing]
    status = aggregate_status(a_ws, dirs)
    workers = {w["worker_dir"]: w for w in status["workers"]}
    assert status["workers_healthy"] == 2
    assert status["workers_unhealthy"] == 1
    assert not workers[missing]["healthy"]

    healthy_a = workers[str(dir_a)]
    healthy_b = workers[str(dir_b)]
    assert healthy_a["executions"] == 10          # falls back to the cursor
    assert healthy_b["executions"] == 4000        # provided by status.json
    assert healthy_b["crashes"] == 2
    assert healthy_a["corpus_entries"] == 2
    assert healthy_b["corpus_entries"] == 1
    assert status["max_cursor"] == 10
    assert healthy_a["sync_lag"] == 0
    assert healthy_b["sync_lag"] == 6
    assert status["totals"]["crashes"] == 2
