"""Loopback network transport tests (#57)."""

from __future__ import annotations

import json

import pytest

from ios_research import targets as targets_mod
from ios_research.errors import SafetyError, ValidationError
from ios_research.nettransport import (
    LOOPBACK, LoopbackTcpTarget, _chunk_sizes, capture_from_result,
    capture_digest, replay,
)
from ios_research.targets.base import ExecResult, Outcome


CRASH_INPUT = b"MOCK\x01\x01\xff\xff" + b"A" * 20
OK_INPUT = b"MOCK\x01\x01\x00\x02ok"


def _target(schedule="single", inner_id="mock:parser"):
    return LoopbackTcpTarget(targets_mod.create(inner_id),
                             schedule=schedule)


# --- registry -----------------------------------------------------------------

def test_net_family_registration_and_guards():
    assert targets_mod.is_registered("net:mock:parser")
    assert not targets_mod.is_registered("net:")
    assert not targets_mod.is_registered("net:net:mock:parser")
    assert not targets_mod.is_registered("net:nope")
    target = targets_mod.create("net:mock:parser")
    assert target.target_id == "net:mock:parser"
    with pytest.raises(Exception):
        targets_mod.create("net:")


def test_refuses_non_loopback_binding():
    with pytest.raises(SafetyError):
        LoopbackTcpTarget(targets_mod.create("mock:parser"), host="0.0.0.0")


def test_unknown_schedule_rejected():
    with pytest.raises(ValidationError, match="unknown schedule"):
        _target(schedule="turbo")


# --- schedules and capture ------------------------------------------------------

@pytest.mark.parametrize("schedule,length,expected_chunks", [
    ("single", 6, [6]),
    ("split2", 6, [3, 3]),
    ("byte-by-byte", 4, [1, 1, 1, 1]),
    ("fragmented-4", 10, [2, 2, 2, 2, 2]),
])
def test_chunk_schedules_are_deterministic(schedule, length, expected_chunks):
    payload = bytes(range(length))
    assert _chunk_sizes(schedule, payload) == expected_chunks
    assert sum(_chunk_sizes(schedule, payload)) == length


def test_delivery_preserves_outcome_signature_and_capture():
    target = _target()
    crash_result = target.execute(CRASH_INPUT)
    assert crash_result.outcome == Outcome.CRASH
    assert crash_result.diagnostics.signature == \
        targets_mod.create("mock:parser").execute(CRASH_INPUT) \
        .diagnostics.signature
    capture = capture_from_result(crash_result)
    assert capture["host"] == LOOPBACK
    assert capture["payload_sha256"] == capture["received_sha256"]
    assert sum(capture["chunks"]) == len(CRASH_INPUT)

    ok_result = _target().execute(OK_INPUT)
    assert ok_result.outcome == Outcome.ACCEPTED


def test_byte_by_byte_transport_still_crashes_identically():
    result = _target(schedule="byte-by-byte").execute(CRASH_INPUT)
    assert result.outcome == Outcome.CRASH
    capture = capture_from_result(result)
    assert capture["chunks"] == [1] * len(CRASH_INPUT)


def test_capture_integrity_verification():
    from ios_research.nettransport import Capture
    capture = Capture(schedule="single", host=LOOPBACK, port=9,
                      payload_sha256="a" * 64,
                      chunks=[4], received_sha256="a" * 64)
    capture.verify(b"x" * 4)
    bad = Capture(schedule="single", host=LOOPBACK, port=9,
                  payload_sha256="a" * 64, chunks=[4],
                  received_sha256="b" * 64)
    with pytest.raises(ValidationError, match="integrity"):
        bad.verify(b"x" * 4)


# --- replay -----------------------------------------------------------------

def test_replay_matches_chunks_and_outcome():
    target = _target(schedule="split2")
    result = target.execute(CRASH_INPUT)
    capture = capture_from_result(result)
    verdict = replay(_target(schedule="split2"), CRASH_INPUT, capture)
    assert verdict["chunks_match"] is True
    assert verdict["outcome"] == Outcome.CRASH
    assert verdict["signature"] == result.diagnostics.signature


def test_replay_schedule_mismatch_fails(tmp_path):
    capture_file = tmp_path / "capture.json"
    capture_file.write_text(json.dumps({"schedule": "single"}))
    with pytest.raises(ValidationError, match="schedule mismatch"):
        replay(_target(schedule="split2"), CRASH_INPUT,
               {"schedule": "single"})


def test_capture_digest_is_stable():
    cap = {"schedule": "single", "chunks": [3], "port": 1}
    assert capture_digest(cap) == capture_digest(dict(cap))


# --- fuzz integration smoke -----------------------------------------------------

def test_fuzz_engine_runs_through_transport(workspace):
    from ios_research.experiment import ExperimentStore
    from ios_research.corpus import CorpusStore
    from ios_research.fuzz import FuzzEngine
    experiment = ExperimentStore(workspace).create(
        target="net:mock:parser", device="loopback", os_version="test",
        config_hash="cfg_test")
    corpus = CorpusStore(workspace).create("net-corpus")
    for seed in (OK_INPUT, CRASH_INPUT[:8]):
        CorpusStore(workspace).add_bytes(corpus, seed, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(experiment_id=experiment.id,
                            target="net:mock:parser", corpus_id=corpus.id,
                            seed=7, workers=1, max_cases=25, duration_s=None)
    session = engine.advance(session, max_new=25)
    stats = session.stats()
    assert stats["executed"] > 0
