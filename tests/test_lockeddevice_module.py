"""Locked-device module tests: mock physical-access parser targets (#86)."""

from __future__ import annotations

import pytest

from ios_research import mutation
from ios_research.targets import create, list_targets
from ios_research.targets.lockeddevice import LOCKED_DEVICE_TARGETS
from ios_research.targets.base import Outcome
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine


LOCKED_IDS = sorted(LOCKED_DEVICE_TARGETS)


@pytest.mark.parametrize("target_id", LOCKED_IDS)
def test_locked_device_targets_registered(target_id):
    ids = [t["id"] for t in list_targets()]
    assert target_id in ids


@pytest.mark.parametrize("target_id", LOCKED_IDS)
def test_locked_device_seed_is_accepted(target_id):
    target = create(target_id)
    assert target.execute(target.seeds()[0]).outcome == Outcome.ACCEPTED


@pytest.mark.parametrize("target_id", LOCKED_IDS)
def test_locked_device_rejects_foreign_input(target_id):
    assert create(target_id).execute(
        b"not-a-locked-device-record").outcome == Outcome.REJECTED


@pytest.mark.parametrize("target_id", LOCKED_IDS)
def test_locked_device_describes_physical_access_entry_point(target_id):
    d = create(target_id).describe()
    assert d["entry_point"] == "physical-access"
    assert d["mock"] is True


@pytest.mark.parametrize("target_id", LOCKED_IDS)
def test_locked_device_oob_read_on_oversized_declared_length(target_id):
    target = create(target_id)
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([1, 0]) + b"x"
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "OUT_OF_BOUNDS_READ"


@pytest.mark.parametrize("target_id", LOCKED_IDS)
def test_locked_device_compressed_flag_is_integer_error(target_id):
    target = create(target_id)
    payload = b"\xff\xff\xff"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([1, 0x80]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "INTEGER_ERROR"


@pytest.mark.parametrize("target_id", LOCKED_IDS)
def test_locked_device_dead_marker_is_use_after_free(target_id):
    target = create(target_id)
    payload = b"\xde\xadbody"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([1, 0]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "USE_AFTER_FREE"


@pytest.mark.parametrize("target_id", LOCKED_IDS)
def test_locked_device_timeout_on_oversized_declared_length(target_id):
    target = create(target_id)
    data = target.magic + (0xF000).to_bytes(2, "big") + bytes([1, 0]) + b"x"
    assert target.execute(data).outcome == Outcome.TIMEOUT


@pytest.mark.parametrize("target_id", LOCKED_IDS)
def test_locked_device_privileged_record_confusion(target_id):
    target = create(target_id)
    payload = b"body"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([0xC0, 0]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "TYPE_CONFUSION"
    # the confused type is described as privileged in the detail string
    assert "privileged" in res.detail


@pytest.mark.parametrize("target_id", LOCKED_IDS)
def test_locked_device_assert_record_type_is_assertion(target_id):
    target = create(target_id)
    payload = b"body"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([0x7E, 0]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "ASSERTION"


@pytest.mark.parametrize("target_id", LOCKED_IDS)
def test_locked_device_module_names_carry_taxonomy_keywords(target_id):
    """Module names let #58/#84 mapping propose the physical-access flag."""
    from ios_research.targetflags import DEFAULT_TAXONOMY
    flag = next(f for f in DEFAULT_TAXONOMY
                if f["id"] == "physical-access-sensitive-data")
    target = create(target_id)
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([1, 0]) + b"x"
    diag = target.execute(data).diagnostics
    haystack = " ".join(
        [str(m).lower() for m in diag.modules] + [target.target_id.lower()])
    assert any(k in haystack for k in flag["keywords"])


# --- end-to-end pipeline -------------------------------------------------------

def test_locked_device_fuzz_finds_multiple_classifications(workspace):
    exp = ExperimentStore(workspace).create(
        target="lockeddevice:lockdownd", device="mock:device",
        os_version="26.1", config_hash="cfg_l", seed=5)
    cs = CorpusStore(workspace)
    corpus = cs.create("locked-device")
    for s in create("lockeddevice:lockdownd").seeds():
        cs.add_bytes(corpus, s, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(experiment_id=exp.id,
                            target="lockeddevice:lockdownd",
                            corpus_id=corpus.id, seed=5, workers=1,
                            max_cases=300, duration_s=None)
    session = engine.advance(session)
    classifications = {
        engine.crash_store.get(cid).classification
        for cid in session.crash_ids
    }
    assert len(classifications) >= 3


def test_locked_device_diagnostics_are_deterministic():
    target = create("lockeddevice:mfi-auth")
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([1, 0]) + b"x"
    d1 = target.execute(data).diagnostics
    d2 = target.execute(data).diagnostics
    assert d1.to_dict() == d2.to_dict()
    assert d1.signature == d2.signature


def test_locked_device_structure_mutator_hits_defect_paths():
    hits = set()
    for i in range(60):
        target = create("lockeddevice:lockdownd")
        rng = mutation.rng_for(i + 11, i)
        mutated = target.structure_mutate(target.seeds()[0], rng)
        res = target.execute(mutated)
        if res.diagnostics is not None:
            hits.add(res.diagnostics.classification_hint)
        elif res.outcome == Outcome.TIMEOUT:
            hits.add("TIMEOUT")
    assert {"OUT_OF_BOUNDS_READ", "INTEGER_ERROR",
            "TYPE_CONFUSION"} <= hits


def test_analyze_proposes_physical_access_flag_candidate(workspace):
    """End-to-end: lockdownd crash evidence maps to the bounty category."""
    from ios_research.analysis import Analyzer
    from ios_research.crashes import CrashStore
    data = b"LCKD" + (0x00FF).to_bytes(2, "big") + bytes([1, 0]) + b"x"
    result = create("lockeddevice:lockdownd").execute(data)
    crash = CrashStore(workspace).record(
        experiment_id="e1", target="lockeddevice:lockdownd",
        fmt="lockdownd", data=data, exec_result=result)
    analysis = Analyzer(workspace).analyze(CrashStore(workspace).get(crash.id))
    assert "physical-access-sensitive-data" \
        in analysis.extra["candidate_target_flags"]
