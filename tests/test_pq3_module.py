"""PQ3 module tests: mock ratchet session-transcript research targets."""

from __future__ import annotations

import pytest

from ios_research import mutation
from ios_research.targets import create, list_targets
from ios_research.targets.pq3 import PQ3_TARGETS
from ios_research.targets.base import Outcome
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine


PQ3_IDS = sorted(PQ3_TARGETS)


def _transcript(target, epoch: int, msg_type: int, payload: bytes,
                declared: int | None = None) -> bytes:
    """Build a synthetic transcript message: magic+len+epoch+type+payload."""
    if declared is None:
        declared = len(payload)
    hi, lo = epoch.to_bytes(2, "big")
    return target.magic + declared.to_bytes(2, "big") + bytes([hi, lo, msg_type]) + payload


@pytest.mark.parametrize("target_id", PQ3_IDS)
def test_pq3_targets_registered(target_id):
    ids = [t["id"] for t in list_targets()]
    assert target_id in ids


@pytest.mark.parametrize("target_id", PQ3_IDS)
def test_pq3_seed_is_accepted(target_id):
    target = create(target_id)
    seed = target.seeds()[0]
    assert target.execute(seed).outcome == Outcome.ACCEPTED


@pytest.mark.parametrize("target_id", PQ3_IDS)
def test_pq3_rejects_foreign_input(target_id):
    assert create(target_id).execute(b"not-transcript-bytes").outcome == Outcome.REJECTED


@pytest.mark.parametrize("target_id", PQ3_IDS)
def test_pq3_oob_read_on_oversized_declared_length(target_id):
    target = create(target_id)
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([0, 1, 1]) + b"x"
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "OUT_OF_BOUNDS_READ"


@pytest.mark.parametrize("target_id", PQ3_IDS)
def test_pq3_null_message_type_is_null_dereference(target_id):
    target = create(target_id)
    data = _transcript(target, epoch=1, msg_type=0x00, payload=b"data")
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "NULL_DEREFERENCE"


@pytest.mark.parametrize("target_id", PQ3_IDS)
def test_pq3_epoch_wrap_sentinel_is_integer_error(target_id):
    target = create(target_id)
    data = target.magic + len(b"data").to_bytes(2, "big") + bytes([255, 255, 1]) + b"data"
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "INTEGER_ERROR"


@pytest.mark.parametrize("target_id", PQ3_IDS)
def test_pq3_stale_epoch_marker_is_use_after_free(target_id):
    target = create(target_id)
    data = _transcript(target, epoch=2, msg_type=1, payload=b"\xde\xaddata")
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "USE_AFTER_FREE"


@pytest.mark.parametrize("target_id", PQ3_IDS)
def test_pq3_timeout_on_oversized_declared_length(target_id):
    target = create(target_id)
    # declared >= 0xF000 takes the timeout path (checked before OOB).
    data = target.magic + (0xF000).to_bytes(2, "big") + bytes([0, 1, 1]) + b"x"
    assert target.execute(data).outcome == Outcome.TIMEOUT


@pytest.mark.parametrize("target_id", PQ3_IDS)
def test_pq3_type_confusion_and_assertion_paths(target_id):
    target = create(target_id)
    confused = _transcript(target, epoch=1, msg_type=0xC0, payload=b"data")
    assert target.execute(confused).diagnostics.classification_hint == "TYPE_CONFUSION"
    asserted = _transcript(target, epoch=1, msg_type=0x7E, payload=b"data")
    assert target.execute(asserted).diagnostics.classification_hint == "ASSERTION"


def test_pq3_structure_mutate_is_format_aware():
    target = create("pq3:handshake")
    rng = mutation.rng_for(1, 1)
    mutated = target.structure_mutate(target.seeds()[0], rng)
    assert mutated.startswith(target.magic)


def test_pq3_diagnostics_are_deterministic():
    target = create("pq3:rekey")
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([0, 1, 1]) + b"x"
    d1 = target.execute(data).diagnostics
    d2 = target.execute(data).diagnostics
    assert d1.to_dict() == d2.to_dict()
    assert d1.signature == d2.signature


def test_pq3_epoch_oracle_monotone_acceptance():
    """Epoch-ordering oracle: monotone advance is accepted; replay crashes.

    A session transcript for ``pq3:rekey`` advances epochs 1 -> 2 -> 3 with
    benign message types and must be ACCEPTED at every step. Replaying an
    already-released epoch carrying the stale-state marker must surface a
    USE_AFTER_FREE crash.
    """
    target = create("pq3:rekey")

    for epoch in (1, 2, 3):
        res = target.execute(_transcript(target, epoch=epoch, msg_type=1,
                                         payload=f"msg-{epoch}".encode()))
        assert res.outcome == Outcome.ACCEPTED, (
            f"monotone epoch {epoch} should advance the session")

    replay = target.execute(_transcript(target, epoch=2, msg_type=1,
                                        payload=b"\xde\xadreplay"))
    assert replay.outcome == Outcome.CRASH
    assert replay.diagnostics.classification_hint == "USE_AFTER_FREE"
    assert replay.diagnostics.modules[0] == "PQ_RKParser"
    frames = [f.split("`", 1)[1].split("+", 1)[0]
              for f in replay.diagnostics.stack_trace]
    assert frames == ["advance_session", "free_stale_state", "use_state"]


def test_pq3_fuzz_finds_multiple_classifications(workspace):
    exp = ExperimentStore(workspace).create(
        target="pq3:handshake", device="mock:device", os_version="17.0",
        config_hash="cfg_x", seed=3)
    cs = CorpusStore(workspace)
    corpus = cs.create("pq3")
    for s in create("pq3:handshake").seeds():
        cs.add_bytes(corpus, s, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(experiment_id=exp.id, target="pq3:handshake",
                            corpus_id=corpus.id, seed=3, workers=1,
                            max_cases=300, duration_s=None)
    session = engine.advance(session)
    classifications = {
        engine.crash_store.get(cid).classification
        for cid in session.crash_ids
    }
    assert len(classifications) >= 3
