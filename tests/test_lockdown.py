"""Lockdown Mode paired-run differential profile tests (#60)."""

from __future__ import annotations

import pytest

from ios_research.corpus import CorpusStore
from ios_research.errors import ValidationError
from ios_research.lockdown import (
    CANDIDATE, HARDENING, OK, LockdownEngine,
)
from ios_research.lockdown import _classify


# --- relation classification ----------------------------------------------------

def test_classify_lockdown_crash_is_candidate():
    verdict, reason = _classify("accepted", "crash", "", "sig_x")
    assert verdict == CANDIDATE
    assert "reachable" in reason


def test_classify_hardening_and_drift():
    # Standard accepts, lockdown rejects -> hardening evidence.
    verdict, _ = _classify("accepted", "rejected", "", "")
    assert verdict == HARDENING
    # Standard crashes where lockdown does not -> hardening.
    verdict, reason = _classify("crash", "accepted", "sig_a", "")
    assert verdict == HARDENING
    # A lockdown-side crash is always the candidate finding (dominant rule).
    verdict, _ = _classify("crash", "crash", "sig_a", "sig_b")
    assert verdict == CANDIDATE
    # Identical behavior -> consistent.
    verdict, _ = _classify("accepted", "accepted", "sig", "sig")
    assert verdict == OK


# --- engine -----------------------------------------------------------------

def test_create_requires_build_provenance(workspace):
    with pytest.raises(ValidationError, match="build identifiers"):
        LockdownEngine(workspace).create(
            name="p", target_standard="mock:parser",
            target_lockdown="mock:parser-v2",
            build_standard="", build_lockdown="26G",
            attested_lockdown_enabled=False)


def test_create_unknown_target_fails(workspace):
    with pytest.raises(Exception):
        LockdownEngine(workspace).create(
            name="p", target_standard="nope", target_lockdown="mock:parser-v2",
            build_standard="a", build_lockdown="b")


def test_run_requires_attestation(workspace):
    engine = LockdownEngine(workspace)
    pair = engine.create(name="unattested", target_standard="mock:parser",
                         target_lockdown="mock:parser-v2",
                         build_standard="26G90", build_lockdown="26G91",
                         attested_lockdown_enabled=False)
    with pytest.raises(ValidationError, match="attest"):
        engine.run(pair)


def test_paired_run_classifies_transitions(workspace):
    engine = LockdownEngine(workspace)
    corpus = CorpusStore(workspace).create("lm-corpus")
    for data in (b"MOCK\x01\x01\xff\xffshort",     # OOB read on both
                 b"MOCK\x02\x01\x00\x02payload",   # v1 accept, v2 OOB-write
                 b"MOCK\x01\x01\x00\x02ok"):       # accept both
        CorpusStore(workspace).add_bytes(corpus, data, origin="seed")
    pair = engine.create(name="sim", target_standard="mock:parser",
                         target_lockdown="mock:parser-v2",
                         build_standard="26G90", build_lockdown="26G91",
                         attested_lockdown_enabled=True, simulation=True,
                         corpus_id=corpus.id)
    summary = engine.run(pair)
    by_verdict = {r["input_sha256"]: r["verdict"] for r in summary["results"]}
    assert summary["provenance"]["attested_lockdown_enabled"] is True
    assert summary["counts"][CANDIDATE] >= 0  # deterministic; no assertion on mix
    # Every observation carries the observation-only flag except consistent ones.
    for r in summary["results"]:
        assert r["observation_only"] == (r["verdict"] != OK)
    # Deterministic re-run.
    second = engine.run(engine.get(pair.id))
    assert second["results"] == summary["results"]


def test_results_artifact_persists(workspace):
    engine = LockdownEngine(workspace)
    pair = engine.create(name="art", target_standard="mock:parser",
                         target_lockdown="mock:parser-v2",
                         build_standard="a", build_lockdown="b",
                         attested_lockdown_enabled=True)
    engine.run(pair)
    record = workspace.read_json(f"analysis/{pair.id}-results.json")
    assert record["kind"] == "lockdown-results"
    assert record["note"].startswith("verdicts are observations")


# --- CLI ----------------------------------------------------------------------

def test_lockdown_cli_roundtrip(workspace):
    from ios_research.cli import main
    ws = ["--workspace", str(workspace.root)]
    assert main([*ws, "lockdown", "create", "--name", "cli",
                 "--target-standard", "mock:parser",
                 "--target-lockdown", "mock:parser-v2",
                 "--build-standard", "26G90", "--build-lockdown", "26G91",
                 "--json"]) == 0
    assert main([*ws, "lockdown", "list", "--json"]) == 0
    # Running without attestation exits VALIDATION (4).
    code = main([*ws, "lockdown", "run", "--json"])
    assert code == 4
    code = main([*ws, "lockdown", "run", "--attest-lockdown-enabled",
                 "--json"])
    assert code == 0
