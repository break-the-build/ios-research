"""Wi-Fi module tests: mock Wi-Fi management-frame parser research targets."""

from __future__ import annotations

import pytest

from ios_research import mutation
from ios_research.targets import create, list_targets
from ios_research.targets.wifi import WIFI_TARGETS
from ios_research.targets.base import Outcome
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine


WIFI_IDS = sorted(WIFI_TARGETS)


@pytest.mark.parametrize("target_id", WIFI_IDS)
def test_wifi_targets_registered(target_id):
    ids = [t["id"] for t in list_targets()]
    assert target_id in ids


@pytest.mark.parametrize("target_id", WIFI_IDS)
def test_wifi_seed_is_accepted(target_id):
    target = create(target_id)
    seed = target.seeds()[0]
    assert target.execute(seed).outcome == Outcome.ACCEPTED


@pytest.mark.parametrize("target_id", WIFI_IDS)
def test_wifi_rejects_foreign_input(target_id):
    assert create(target_id).execute(b"not-wifi-frames").outcome == Outcome.REJECTED


@pytest.mark.parametrize("target_id", WIFI_IDS)
def test_wifi_oob_read_on_oversized_declared_length(target_id):
    target = create(target_id)
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([1, 2]) + b"x"
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "OUT_OF_BOUNDS_READ"


@pytest.mark.parametrize("target_id", WIFI_IDS)
def test_wifi_zero_ie_count_is_integer_error(target_id):
    target = create(target_id)
    payload = b"body"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([1, 0]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "INTEGER_ERROR"


@pytest.mark.parametrize("target_id", WIFI_IDS)
def test_wifi_dead_marker_is_use_after_free(target_id):
    target = create(target_id)
    payload = b"\xde\xadbody"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([1, 2]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "USE_AFTER_FREE"


@pytest.mark.parametrize("target_id", WIFI_IDS)
def test_wifi_timeout_on_oversized_declared_length(target_id):
    target = create(target_id)
    # declared >= 0xF000 takes the timeout path (checked before OOB).
    data = target.magic + (0xF000).to_bytes(2, "big") + bytes([1, 2]) + b"x"
    assert target.execute(data).outcome == Outcome.TIMEOUT


@pytest.mark.parametrize("target_id", WIFI_IDS)
def test_wifi_type_confusion_and_assertion_paths(target_id):
    target = create(target_id)
    payload = b"body"
    confused = target.magic + len(payload).to_bytes(2, "big") + bytes([0xC0, 2]) + payload
    assert target.execute(confused).diagnostics.classification_hint == "TYPE_CONFUSION"
    asserted = target.magic + len(payload).to_bytes(2, "big") + bytes([0x7E, 2]) + payload
    assert target.execute(asserted).diagnostics.classification_hint == "ASSERTION"


def test_wifi_structure_mutate_is_format_aware():
    target = create("wifi:beacon")
    rng = mutation.rng_for(1, 1)
    mutated = target.structure_mutate(target.seeds()[0], rng)
    assert mutated.startswith(target.magic)


def test_wifi_diagnostics_are_deterministic():
    target = create("wifi:action")
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([1, 2]) + b"x"
    d1 = target.execute(data).diagnostics
    d2 = target.execute(data).diagnostics
    assert d1.to_dict() == d2.to_dict()
    assert d1.signature == d2.signature


def test_wifi_fuzz_finds_multiple_classifications(workspace):
    exp = ExperimentStore(workspace).create(
        target="wifi:beacon", device="mock:device", os_version="17.0",
        config_hash="cfg_x", seed=3)
    cs = CorpusStore(workspace)
    corpus = cs.create("wifi")
    for s in create("wifi:beacon").seeds():
        cs.add_bytes(corpus, s, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(experiment_id=exp.id, target="wifi:beacon",
                            corpus_id=corpus.id, seed=3, workers=1,
                            max_cases=300, duration_s=None)
    session = engine.advance(session)
    classifications = {
        engine.crash_store.get(cid).classification
        for cid in session.crash_ids
    }
    assert len(classifications) >= 3
