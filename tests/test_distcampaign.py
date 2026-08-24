"""Distributed campaign coordination: safe exchange, resume, quarantine (#32)."""

from __future__ import annotations

import json

import pytest

from ios_research import distcampaign as dc
from ios_research.cli import main as cli_main
from ios_research.config import Config
from ios_research.corpus import CorpusStore
from ios_research.errors import InterruptedError_, SafetyError, StateError
from ios_research.distcampaign import DistCampaignSync
from ios_research.hashing import sha256_bytes
from ios_research.workspace import Workspace


def fixture_blob(i: int) -> bytes:
    """Deterministic input bytes so two independent runs converge exactly."""
    return b"DIST-FIXTURE-%04d|%s" % (i, b"x" * (i % 7))


def make_workspace(tmp_path, name: str) -> Workspace:
    ws = Workspace(tmp_path / name)
    ws.init(framework_version="0.1.0", created_at="2026-01-01T00:00:00Z")
    return ws


def sync_config(shared_root) -> Config:
    return Config({"distcampaign": {
        "allowlist_roots": [str(shared_root)],
        "sync_root": str(shared_root)}})


def add_inputs(store: CorpusStore, corpus, indices) -> list[str]:
    shas = []
    for i in indices:
        tc = store.add_bytes(corpus, fixture_blob(i), origin="seed")
        assert tc is not None
        shas.append(tc.sha256)
    return shas


@pytest.fixture()
def two_workers(tmp_path):
    shared = tmp_path / "exchange"
    shared.mkdir()
    ws_a = make_workspace(tmp_path, ".ios-research-worker-a")
    ws_b = make_workspace(tmp_path, ".ios-research-worker-b")
    engines = {
        "a": DistCampaignSync(ws_a, sync_config(shared)),
        "b": DistCampaignSync(ws_b, sync_config(shared)),
    }
    return shared, ws_a, ws_b, engines


# --- acceptance: deterministic two-worker exchange -------------------------------

def test_two_fixture_workers_exchange_deterministically(two_workers, tmp_path):
    shared, ws_a, ws_b, engines = two_workers
    store_a = CorpusStore(ws_a)
    corpus_a = store_a.create("team-alpha", target="mock:parser")
    add_inputs(store_a, corpus_a, range(5))

    out = engines["a"].export(sync_root=shared, campaign_id="camp_demo",
                              producer="worker-a", corpus=corpus_a)
    assert out["exported"] == 5 and out["sequence"] == 1

    pulled = engines["b"].pull(sync_root=shared, campaign_id="camp_demo")
    assert pulled["imported"] == 5
    corpus_b = engines["b"].get_or_default_corpus("camp_demo")
    assert len(corpus_b.testcases) == 5

    # Worker B contributes its own inputs and pushes back.
    b_shas = add_inputs(CorpusStore(ws_b), corpus_b, range(100, 103))
    pushed = engines["b"].export(sync_root=shared, campaign_id="camp_demo",
                                 producer="worker-b", corpus=corpus_b)
    assert pushed["exported"] == 3 and pushed["sequence"] == 1

    back = engines["a"].pull(sync_root=shared, campaign_id="camp_demo",
                             exclude_producer="worker-a",
                             active_corpus=corpus_a)
    assert back["imported"] == 3

    final_a = {tc["sha256"] for tc in store_a.get(corpus_a.id).testcases}
    final_b = {tc["sha256"]
               for tc in engines["b"].corpora.get(corpus_b.id).testcases}
    assert final_a == final_b
    assert b_shas[0] in final_a

    # Idempotent replay: nothing new, everything reported as current.
    again = engines["b"].pull(sync_root=shared, campaign_id="camp_demo",
                              active_corpus=corpus_b)
    assert again["imported"] == 0
    assert again["manifests_skipped_current"] >= 2


def test_exchange_is_deterministic_across_independent_runs(tmp_path):
    """Same operations in a fresh layout converge to identical corpora."""
    results = []
    for run in range(2):
        root = tmp_path / f"run-{run}"
        root.mkdir()
        ws = make_workspace(root, ".ios-research")
        engine = DistCampaignSync(ws, sync_config(root))
        store = CorpusStore(ws)
        corpus = store.create("solo", target="mock:parser")
        add_inputs(store, corpus, range(4))
        engine.export(sync_root=root, campaign_id="camp_det",
                      producer="w1", corpus=corpus)
        mirror_ws = make_workspace(root, ".ios-research-mirror")
        mirror_engine = DistCampaignSync(mirror_ws, sync_config(root))
        mirror_engine.pull(sync_root=root, campaign_id="camp_det")
        mirror_corpus = mirror_engine.get_or_default_corpus("camp_det")
        results.append(sorted(tc["sha256"] for tc in mirror_corpus.testcases))
    assert results[0] == results[1]


# --- resume after interruption -----------------------------------------------------

def test_pull_resumes_after_interruption_without_loss_or_duplicates(
        two_workers, monkeypatch):
    shared, ws_a, ws_b, engines = two_workers
    store_a = CorpusStore(ws_a)
    corpus_a = store_a.create("resumable", target="mock:parser")
    add_inputs(store_a, corpus_a, range(3))
    engines["a"].export(sync_root=shared, campaign_id="camp_res",
                        producer="worker-a", corpus=corpus_a)
    add_inputs(store_a, corpus_a, range(50, 55))
    engines["a"].export(sync_root=shared, campaign_id="camp_res",
                        producer="worker-a", corpus=corpus_a)

    # Simulate a crash between manifests: first application succeeds, then
    # the process dies before the second manifest is applied.
    engine_b = engines["b"]
    original = engine_b._apply_manifest
    applied = {"count": 0}

    def interrupting_apply(*args, **kwargs):
        original(*args, **kwargs)
        applied["count"] += 1
        raise StateError("simulated interruption")

    monkeypatch.setattr(engine_b, "_apply_manifest", interrupting_apply)
    with pytest.raises(StateError, match="simulated interruption"):
        engine_b.pull(sync_root=shared, campaign_id="camp_res")
    assert applied["count"] == 1

    state = dc.load_state(ws_b, "camp_res", "worker-a")
    assert state["last_sequence"] == 1
    partial = engine_b.get_or_default_corpus("camp_res")
    assert len(partial.testcases) == 3

    # Resume cleanly: remaining manifest replays, nothing lost or duplicated.
    done = DistCampaignSync(ws_b, sync_config(shared)).pull(
        sync_root=shared, campaign_id="camp_res")
    assert done["manifests_applied"] == 1
    assert done["imported"] == 5
    resumed = engine_b.corpora.get(partial.id)
    assert len(resumed.testcases) == 8

    replay = DistCampaignSync(ws_b, sync_config(shared)).pull(
        sync_root=shared, campaign_id="camp_res")
    assert replay["imported"] == 0


def test_export_sequence_survives_lost_local_state(two_workers):
    """Sequence numbers come from the exchange dir too, so a lost state file
    cannot overwrite an existing append-only manifest."""
    shared, ws_a, _, engines = two_workers
    store = CorpusStore(ws_a)
    corpus = store.create("seqsafe", target="mock:parser")
    add_inputs(store, corpus, range(2))
    engines["a"].export(sync_root=shared, campaign_id="camp_seq",
                        producer="worker-a", corpus=corpus)
    add_inputs(store, corpus, range(20, 22))
    # Wipe local bookkeeping entirely (crash before state persisted).
    (ws_a.path("research/distcampaign/state-camp_seq-worker-a.json")).unlink()
    out = engines["a"].export(sync_root=shared, campaign_id="camp_seq",
                              producer="worker-a", corpus=corpus)
    assert out["sequence"] == 2  # not a silent overwrite of sequence 1
    assert out["exported"] == 4  # previously exported inputs are re-offered


# --- malformed artifacts are quarantined, never merged ------------------------------

def test_malformed_artifacts_quarantined_not_merged(two_workers):
    shared, ws_a, ws_b, engines = two_workers
    store_a = CorpusStore(ws_a)
    corpus_a = store_a.create("hostile", target="mock:parser")
    shas = add_inputs(store_a, corpus_a, range(3))
    engines["a"].export(sync_root=shared, campaign_id="camp_bad",
                        producer="worker-a", corpus=corpus_a)

    ex = dc.ExchangeDir(shared, "camp_bad")
    # 1) bit-flipped blob (digest mismatch)
    ex.blob_path(shas[0]).write_bytes(b"tampered-payload")
    # 2) vanished blob
    ex.blob_path(shas[1]).unlink()
    # 3) forged manifest with an integrity digest that does not match content
    forged = dc.build_manifest(campaign_id="camp_bad", producer="worker-evil",
                               sequence=1,
                               entries=[{"sha256": "cd" * 32, "size": 2}])
    forged["integrity"]["manifest_sha256"] = "0" * 64
    ex.manifest_path("worker-evil", 1).write_text(json.dumps(forged))
    # 4) unrecognized stray file
    (ex.manifests / "stray-notes.json").write_text("{}\n")

    summary = engines["b"].pull(sync_root=shared, campaign_id="camp_bad")
    assert summary["manifests_applied"] == 1      # the honest manifest
    assert summary["manifests_quarantined"] == 1  # the forged one
    assert summary["unrecognized_files"] == 1
    # Only the intact input survived into the local corpus.
    corpus_b = engines["b"].get_or_default_corpus("camp_bad")
    merged = {tc["sha256"] for tc in corpus_b.testcases}
    assert merged == {shas[2]}
    assert shas[0] not in merged and shas[1] not in merged

    quarantined = sorted(
        (ws_b.path("research/distcampaign/quarantine")).glob("*.json"))
    records = [json.loads(p.read_text()) for p in quarantined]
    sources = {r["source"] for r in records}
    assert f"blobs/{shas[0]}" in sources          # digest mismatch blob
    assert f"blobs/{shas[1]}" in sources          # missing blob
    assert "worker-evil-00000001.json" in sources  # forged manifest
    assert any("digest mismatch" in r["reason"] for r in records)
    # Every quarantine record is actionable: source + reason + timestamps.
    assert all(r["reason"] and r["created_at"] for r in records)


def test_hmac_signing_enforced_when_key_configured(tmp_path):
    shared = tmp_path / "exchange"
    shared.mkdir()
    ws_signer = make_workspace(tmp_path, ".ios-research-signer")
    ws_verifier = make_workspace(tmp_path, ".ios-research-verifier")
    ws_forge = make_workspace(tmp_path, ".ios-research-forge")
    signer = DistCampaignSync(ws_signer, sync_config(shared), hmac_key="k1")
    verifier = DistCampaignSync(ws_verifier, sync_config(shared),
                                hmac_key="k1")
    outsider = DistCampaignSync(ws_forge, sync_config(shared),
                                hmac_key="wrong-key")

    store = CorpusStore(ws_signer)
    corpus = store.create("signed", target="mock:parser")
    add_inputs(store, corpus, range(2))
    signer.export(sync_root=shared, campaign_id="camp_mac",
                  producer="worker-a", corpus=corpus)

    good = verifier.pull(sync_root=shared, campaign_id="camp_mac")
    assert good["imported"] == 2 and good["quarantined"] == []

    bad = outsider.pull(sync_root=shared, campaign_id="camp_mac")
    assert bad["imported"] == 0 and bad["manifests_quarantined"] == 1
    assert bad["corpus_size"] == 0


# --- opt-in allowlisting (exit 5 SAFETY) ---------------------------------------------

def test_sync_requires_explicit_allowlisted_root(tmp_path):
    outside = tmp_path / "not-allowed"
    outside.mkdir()
    allowed = tmp_path / "exchange"
    allowed.mkdir()
    config = Config({"distcampaign": {"allowlist_roots": [str(allowed)]}})

    with pytest.raises(SafetyError):          # empty allowlist -> disabled
        dc.resolve_sync_root(Config({}), str(outside))
    with pytest.raises(SafetyError):          # outside allowlist
        dc.resolve_sync_root(config, str(outside))
    resolved = dc.resolve_sync_root(config, str(allowed / "nested"))
    assert resolved == (allowed / "nested").resolve()

    # No endpoint given at all and none configured -> validation, not guessing.
    from ios_research.errors import ValidationError
    with pytest.raises(ValidationError):
        dc.resolve_sync_root(config, None)


def test_cli_refuses_unallowlisted_root_with_safety_exit(tmp_path, capsys):
    ws = make_workspace(tmp_path, ".ios-research-cli")
    ws.write_json("config/config.json", {"distcampaign": {
        "allowlist_roots": [str(tmp_path / "exchange")]}})
    rogue = tmp_path / "rogue-share"
    rogue.mkdir()
    rc = cli_main(["--workspace", str(ws.root), "--json", "campaign",
                   "status-aggregate", "camp_x", "--sync-root", str(rogue)])
    assert rc == 5  # ExitCode.SAFETY
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["ok"] is False and envelope["exit_code"] == 5


def test_cli_round_trip_export_import_and_aggregate(tmp_path, capsys):
    shared = tmp_path / "exchange"
    shared.mkdir()
    ws_a = make_workspace(tmp_path, ".ios-research-cli-a")
    ws_b = make_workspace(tmp_path, ".ios-research-cli-b")
    allow = {"distcampaign": {"allowlist_roots": [str(shared)],
                              "sync_root": str(shared)}}
    ws_a.write_json("config/config.json", allow)
    ws_b.write_json("config/config.json", allow)

    store = CorpusStore(ws_a)
    corpus = store.create("cli-corpus", target="mock:parser")
    add_inputs(store, corpus, range(3))

    base = ["--workspace", str(ws_a.root), "--json", "campaign"]
    rc = cli_main(base + ["export", "camp_cli", "--producer", "worker-a",
                          "--corpus", corpus.id])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["exported"] == 3

    rc = cli_main(["--workspace", str(ws_b.root), "--json", "campaign",
                   "import", "camp_cli"])
    assert rc == 0
    imported = json.loads(capsys.readouterr().out)["data"]
    assert imported["imported"] == 3 and imported["corpus_size"] == 3

    rc = cli_main(base + ["sync", "camp_cli", "--producer", "worker-a",
                          "--corpus", corpus.id])
    assert rc == 0
    synced = json.loads(capsys.readouterr().out)["data"]
    assert synced["aggregate"]["totals"]["executions"] == 0

    rc = cli_main(base + ["status-aggregate", "camp_cli"])
    assert rc == 0
    aggregate = json.loads(capsys.readouterr().out)["data"]
    assert aggregate["kind"] == "distcampaign-aggregate"
    assert aggregate["workers"][0]["producer"] == "worker-a"


# --- status aggregation -----------------------------------------------------------

def test_status_aggregation_totals_lag_and_malformed(two_workers):
    shared, ws_a, ws_b, engines = two_workers
    engines["a"].publish_status(sync_root=shared, campaign_id="camp_agg",
                                producer="worker-a", executions=120,
                                crashes=3, unique_crashes=2, corpus_size=40,
                                coverage_features=17)
    engines["b"].publish_status(sync_root=shared, campaign_id="camp_agg",
                                producer="worker-b", executions=80,
                                crashes=1, unique_crashes=1, corpus_size=25,
                                coverage_features=12, health="degraded")
    dc.ExchangeDir(shared, "camp_agg").status_path(
        "worker-broken").write_text("{not json")

    aggregate = engines["a"].aggregate_status(sync_root=shared,
                                              campaign_id="camp_agg")
    assert aggregate["worker_count"] == 2
    assert aggregate["totals"] == {"executions": 200, "crashes": 4,
                                   "unique_crashes": 3}
    assert aggregate["max_coverage_features"] == 17
    assert aggregate["sync_lag_seconds"] == 0  # frozen clock in tests
    health = {w["producer"]: w for w in aggregate["workers"]}
    assert health["worker-b"]["health"] == "degraded"
    assert health["worker-a"]["lag_seconds"] == 0
    assert aggregate["malformed_status_files"][0]["source"] == \
        "worker-broken.json"

    persisted = ws_a.path("research/distcampaign/aggregate-camp_agg.json")
    assert json.loads(persisted.read_text())["generated_at"]


# --- resource limits ------------------------------------------------------------------

def test_large_pull_requires_confirmation(two_workers, monkeypatch):
    shared, ws_a, ws_b, engines = two_workers
    store_a = CorpusStore(ws_a)
    corpus_a = store_a.create("bulk", target="mock:parser")
    add_inputs(store_a, corpus_a, range(4))
    engines["a"].export(sync_root=shared, campaign_id="camp_big",
                        producer="worker-a", corpus=corpus_a)
    monkeypatch.setattr(dc, "LARGE_IMPORT_ENTRIES", 3)

    with pytest.raises(InterruptedError_) as excinfo:
        engines["b"].pull(sync_root=shared, campaign_id="camp_big")
    assert "--yes" in str(excinfo.value.message)

    confirmed = engines["b"].pull(sync_root=shared, campaign_id="camp_big",
                                  assume_yes=True)
    assert confirmed["imported"] == 4


def test_corpus_limit_stops_pull_resumably(two_workers):
    shared, ws_a, ws_b, engines = two_workers
    store_a = CorpusStore(ws_a)
    corpus_a = store_a.create("capped", target="mock:parser")
    add_inputs(store_a, corpus_a, range(2))
    engines["a"].export(sync_root=shared, campaign_id="camp_cap",
                        producer="worker-a", corpus=corpus_a)
    config = Config({"limits": {"max_testcases": 1},
                     "distcampaign": {"allowlist_roots": [str(shared)]}})
    with pytest.raises(StateError, match="corpus limit"):
        DistCampaignSync(ws_b, config).pull(sync_root=shared,
                                            campaign_id="camp_cap")


# --- minimization -------------------------------------------------------------------

def test_minimize_candidates_prefers_max_feature_gain():
    candidates = {
        "aa" * 32: (b"c1", ["f1", "f2"]),
        "bb" * 32: (b"c2", ["f1"]),
        "cc" * 32: (b"c3", []),
    }
    kept = DistCampaignSync._minimize_candidates(candidates, target=None)
    # Greedy set cover keeps the highest-gain input; feature-less inputs are
    # conservatively retained because their behavior is unknown here.
    assert set(kept) == {"aa" * 32, "cc" * 32}


def test_minimize_candidates_queries_target_adapter():
    from ios_research.targets import create
    target = create("mock:parser")
    reject = b"short"
    valid = b"MOCK\x01\x01\x00\x02ok"
    oob = b"MOCK\x01\x01\xff\xffokokok"  # declared length exceeds payload
    candidates = {
        sha256_bytes(reject): (reject, []),
        sha256_bytes(valid): (valid, []),
        sha256_bytes(oob): (oob, []),
    }
    kept = DistCampaignSync._minimize_candidates(candidates, target=target)
    # All three inputs reach distinct mock branches, so all are retained...
    assert set(kept) == set(candidates)
    duplicate = b"MOCK\x01\x02\x00\x02zz"  # same accepted branch as `valid`
    candidates[sha256_bytes(duplicate)] = (duplicate, [])
    kept = DistCampaignSync._minimize_candidates(candidates, target=target)
    # ...while the redundant accepted-path input is dropped by the adapter.
    assert sha256_bytes(duplicate) not in kept
    assert sha256_bytes(valid) in kept
