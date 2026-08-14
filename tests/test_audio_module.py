"""Phase 03 tests: audio-processing research targets."""

from __future__ import annotations

import pytest

from ios_research import mutation
from ios_research.targets import create, list_targets
from ios_research.targets.audio import AUDIO_TARGETS
from ios_research.targets.base import Outcome
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine


AUDIO_IDS = sorted(AUDIO_TARGETS)


@pytest.mark.parametrize("target_id", AUDIO_IDS)
def test_audio_targets_registered(target_id):
    ids = [t["id"] for t in list_targets()]
    assert target_id in ids


@pytest.mark.parametrize("target_id", AUDIO_IDS)
def test_audio_seed_is_accepted(target_id):
    target = create(target_id)
    seed = target.seeds()[0]
    assert target.execute(seed).outcome == Outcome.ACCEPTED


@pytest.mark.parametrize("target_id", AUDIO_IDS)
def test_audio_rejects_foreign_input(target_id):
    assert create(target_id).execute(b"not-audio-data").outcome == Outcome.REJECTED


@pytest.mark.parametrize("target_id", AUDIO_IDS)
def test_audio_oob_read_on_oversized_declared_length(target_id):
    target = create(target_id)
    # magic + declared_length=0x00FF (but tiny payload) -> OOB read
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([2, 1]) + b"x"
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "OUT_OF_BOUNDS_READ"


@pytest.mark.parametrize("target_id", AUDIO_IDS)
def test_audio_zero_channels_is_integer_error(target_id):
    target = create(target_id)
    payload = b"body"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([0, 1]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "INTEGER_ERROR"


@pytest.mark.parametrize("target_id", AUDIO_IDS)
def test_audio_timeout_on_oversized_declared_length(target_id):
    target = create(target_id)
    # declared >= 0xF000 takes the timeout path (checked before OOB).
    data = target.magic + (0xF000).to_bytes(2, "big") + bytes([2, 1]) + b"x"
    assert target.execute(data).outcome == Outcome.TIMEOUT


def test_audio_structure_mutate_is_format_aware():
    target = create("audio:wav")
    rng = mutation.rng_for(1, 1)
    mutated = target.structure_mutate(target.seeds()[0], rng)
    assert mutated.startswith(target.magic)


def test_audio_diagnostics_are_deterministic():
    target = create("audio:mp3")
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([2, 1]) + b"x"
    d1 = target.execute(data).diagnostics
    d2 = target.execute(data).diagnostics
    assert d1.to_dict() == d2.to_dict()
    assert d1.signature == d2.signature


def test_audio_fuzz_finds_multiple_classifications(workspace):
    exp = ExperimentStore(workspace).create(
        target="audio:wav", device="mock:device", os_version="17.0",
        config_hash="cfg_x", seed=3)
    cs = CorpusStore(workspace)
    corpus = cs.create("audio")
    for s in create("audio:wav").seeds():
        cs.add_bytes(corpus, s, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(experiment_id=exp.id, target="audio:wav",
                            corpus_id=corpus.id, seed=3, workers=1,
                            max_cases=300, duration_s=None)
    session = engine.advance(session)
    classifications = {
        engine.crash_store.get(cid).classification
        for cid in session.crash_ids
    }
    assert len(classifications) >= 3
