"""Messaging module tests: mock communication-message parser targets (#85)."""

from __future__ import annotations

import pytest

from ios_research import mutation
from ios_research.targets import create, list_targets
from ios_research.targets.messaging import MESSAGING_TARGETS
from ios_research.targets.base import Outcome
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine


MESSAGING_IDS = sorted(MESSAGING_TARGETS)


@pytest.mark.parametrize("target_id", MESSAGING_IDS)
def test_messaging_targets_registered(target_id):
    ids = [t["id"] for t in list_targets()]
    assert target_id in ids


@pytest.mark.parametrize("target_id", MESSAGING_IDS)
def test_messaging_seed_is_accepted(target_id):
    target = create(target_id)
    seed = target.seeds()[0]
    assert target.execute(seed).outcome == Outcome.ACCEPTED


@pytest.mark.parametrize("target_id", MESSAGING_IDS)
def test_messaging_rejects_foreign_input(target_id):
    assert create(target_id).execute(
        b"not-a-message-envelope").outcome == Outcome.REJECTED


@pytest.mark.parametrize("target_id", MESSAGING_IDS)
def test_messaging_describes_zero_click_entry_point(target_id):
    d = create(target_id).describe()
    assert d["entry_point"] == "network-zero-click"
    assert d["mock"] is True


@pytest.mark.parametrize("target_id", MESSAGING_IDS)
def test_messaging_oob_read_on_oversized_declared_length(target_id):
    target = create(target_id)
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([1, 1]) + b"x"
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "OUT_OF_BOUNDS_READ"


@pytest.mark.parametrize("target_id", MESSAGING_IDS)
def test_messaging_zero_part_count_is_integer_error(target_id):
    target = create(target_id)
    payload = b"body"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([0, 1]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "INTEGER_ERROR"


@pytest.mark.parametrize("target_id", MESSAGING_IDS)
def test_messaging_dead_marker_is_use_after_free(target_id):
    target = create(target_id)
    payload = b"\xde\xadbody"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([1, 1]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "USE_AFTER_FREE"


@pytest.mark.parametrize("target_id", MESSAGING_IDS)
def test_messaging_timeout_on_oversized_declared_length(target_id):
    target = create(target_id)
    # declared >= 0xF000 takes the timeout path (checked before OOB).
    data = target.magic + (0xF000).to_bytes(2, "big") + bytes([1, 1]) + b"x"
    res = target.execute(data)
    assert res.outcome == Outcome.TIMEOUT


@pytest.mark.parametrize("target_id", MESSAGING_IDS)
def test_messaging_encoding_confusion_is_type_confusion(target_id):
    target = create(target_id)
    payload = b"body"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([1, 0xC0]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "TYPE_CONFUSION"


@pytest.mark.parametrize("target_id", MESSAGING_IDS)
def test_messaging_assert_encoding_is_assertion(target_id):
    target = create(target_id)
    payload = b"body"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([1, 0x7E]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "ASSERTION"


@pytest.mark.parametrize("target_id", MESSAGING_IDS)
def test_messaging_shared_defect_model_yields_identical_signatures(target_id):
    """One root cause reached through three front-ends (#85 design intent)."""
    payload = b"\xde\xadbody"
    results = []
    for tid in MESSAGING_IDS:
        t = create(tid)
        data = t.magic + len(payload).to_bytes(2, "big") + bytes([1, 1]) + payload
        r = t.execute(data)
        assert r.diagnostics is not None
        results.append(r.diagnostics.signature)
    assert len(set(results)) == 1


# --- end-to-end pipeline -------------------------------------------------------

def test_messaging_fuzz_finds_multiple_classifications(workspace):
    exp = ExperimentStore(workspace).create(
        target="messaging:sms", device="mock:device", os_version="26.1",
        config_hash="cfg_m", seed=3)
    cs = CorpusStore(workspace)
    corpus = cs.create("messaging")
    for s in create("messaging:sms").seeds():
        cs.add_bytes(corpus, s, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(experiment_id=exp.id, target="messaging:sms",
                            corpus_id=corpus.id, seed=3, workers=1,
                            max_cases=300, duration_s=None)
    session = engine.advance(session)
    classifications = {
        engine.crash_store.get(cid).classification
        for cid in session.crash_ids
    }
    assert len(classifications) >= 3


def test_messaging_structure_mutate_is_format_aware():
    target = create("messaging:mime")
    rng = mutation.rng_for(1, 1)
    mutated = target.structure_mutate(target.seeds()[0], rng)
    assert mutated.startswith(target.magic)


def test_messaging_diagnostics_are_deterministic():
    target = create("messaging:link-preview")
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([1, 1]) + b"x"
    d1 = target.execute(data).diagnostics
    d2 = target.execute(data).diagnostics
    assert d1.to_dict() == d2.to_dict()
    assert d1.signature == d2.signature


def test_messaging_structure_mutator_hits_defect_paths():
    hits = set()
    for i in range(60):
        target = create("messaging:sms")
        rng = mutation.rng_for(i + 1, i)
        mutated = target.structure_mutate(target.seeds()[0], rng)
        res = target.execute(mutated)
        if res.diagnostics is not None:
            hits.add(res.diagnostics.classification_hint)
        elif res.outcome == Outcome.TIMEOUT:
            hits.add("TIMEOUT")
    assert {"OUT_OF_BOUNDS_READ", "INTEGER_ERROR",
            "TYPE_CONFUSION"} <= hits
