"""XPC module tests: mock XPC/Mach message-schema research targets (#108)."""

from __future__ import annotations

import json

import pytest

from ios_research import mutation
from ios_research.cli import main
from ios_research.targets import create, list_targets
from ios_research.targets.xpc import XPC_TARGETS
from ios_research.targets.base import Outcome
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine


XPC_IDS = sorted(XPC_TARGETS)


@pytest.mark.parametrize("target_id", XPC_IDS)
def test_xpc_targets_registered(target_id):
    ids = [t["id"] for t in list_targets()]
    assert target_id in ids


@pytest.mark.parametrize("target_id", XPC_IDS)
def test_xpc_seed_is_accepted(target_id):
    target = create(target_id)
    seed = target.seeds()[0]
    assert target.execute(seed).outcome == Outcome.ACCEPTED


@pytest.mark.parametrize("target_id", XPC_IDS)
def test_xpc_rejects_foreign_input(target_id):
    assert create(target_id).execute(b"not-message-bytes").outcome == Outcome.REJECTED


@pytest.mark.parametrize("target_id", XPC_IDS)
def test_xpc_oob_read_on_oversized_declared_length(target_id):
    target = create(target_id)
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([1, 2]) + b"x"
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "OUT_OF_BOUNDS_READ"


@pytest.mark.parametrize("target_id", XPC_IDS)
def test_xpc_entry_type_zero_is_null_dereference(target_id):
    target = create(target_id)
    payload = b"body"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([0x00, 2]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "NULL_DEREFERENCE"


@pytest.mark.parametrize("target_id", XPC_IDS)
def test_xpc_zero_entry_count_is_integer_error(target_id):
    target = create(target_id)
    payload = b"body"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([1, 0]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "INTEGER_ERROR"


@pytest.mark.parametrize("target_id", XPC_IDS)
def test_xpc_dead_marker_is_use_after_free(target_id):
    target = create(target_id)
    payload = b"\xde\xadbody"
    data = target.magic + len(payload).to_bytes(2, "big") + bytes([1, 2]) + payload
    res = target.execute(data)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "USE_AFTER_FREE"


@pytest.mark.parametrize("target_id", XPC_IDS)
def test_xpc_timeout_on_oversized_declared_length(target_id):
    target = create(target_id)
    # declared >= 0xF000 takes the timeout path (checked before OOB).
    data = target.magic + (0xF000).to_bytes(2, "big") + bytes([1, 2]) + b"x"
    assert target.execute(data).outcome == Outcome.TIMEOUT


@pytest.mark.parametrize("target_id", XPC_IDS)
def test_xpc_type_confusion_path(target_id):
    target = create(target_id)
    payload = b"body"
    confused = target.magic + len(payload).to_bytes(2, "big") + bytes([0xC0, 2]) + payload
    assert target.execute(confused).diagnostics.classification_hint == "TYPE_CONFUSION"


def test_xpc_structure_mutate_is_format_aware():
    target = create("xpc:dict")
    rng = mutation.rng_for(1, 1)
    mutated = target.structure_mutate(target.seeds()[0], rng)
    assert mutated.startswith(target.magic)


def test_xpc_diagnostics_are_deterministic():
    target = create("xpc:endpoint")
    data = target.magic + (0x00FF).to_bytes(2, "big") + bytes([1, 2]) + b"x"
    d1 = target.execute(data).diagnostics
    d2 = target.execute(data).diagnostics
    assert d1.to_dict() == d2.to_dict()
    assert d1.signature == d2.signature


def test_xpc_fuzz_finds_multiple_classifications(workspace):
    exp = ExperimentStore(workspace).create(
        target="xpc:dict", device="mock:device", os_version="17.0",
        config_hash="cfg_x", seed=3)
    cs = CorpusStore(workspace)
    corpus = cs.create("xpc")
    for s in create("xpc:dict").seeds():
        cs.add_bytes(corpus, s, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(experiment_id=exp.id, target="xpc:dict",
                            corpus_id=corpus.id, seed=3, workers=1,
                            max_cases=300, duration_s=None)
    session = engine.advance(session)
    classifications = {
        engine.crash_store.get(cid).classification
        for cid in session.crash_ids
    }
    assert len(classifications) >= 3


def test_harvest_imports_schema_file_as_deterministic_seeds(tmp_path):
    f = tmp_path / "schema.json"
    f.write_text(json.dumps(
        [{"key": "service", "type": "string"}, {"key": "port"}]))
    rc = main(["target", "xpc", "harvest", str(f), "--json"])
    assert rc == 0


def test_harvest_missing_file_is_not_found(tmp_path):
    rc2 = main(["target", "xpc", "harvest",
                str(tmp_path / "nope.json"), "--json"])
    assert rc2 != 0  # NotFoundError -> NOT_FOUND exit code (3)
