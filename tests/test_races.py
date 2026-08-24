"""Feature #70 tests: TSan parsing, race store, perturbation hooks."""

from __future__ import annotations

import json

import pytest

from ios_research import targets
from ios_research.cli import main
from ios_research.corpus import CorpusStore
from ios_research.errors import NotFoundError, ValidationError
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine
from ios_research.races import (RaceStore, import_report, parse_tsan,
                                race_signature, validate_modes)
from ios_research.targets.base import ExecResult, Outcome, Target

TWO_STACK_REPORT = """\
==================
WARNING: ThreadSanitizer: data race (pid=4242)

  Read of size 4 at 0x7fff5fbff8f0 by thread T1:
  Stack of thread T1:
    #0 0x10A4 in reader_loop worker.c:42 (libworker:x86_64+0xa4)
    #1 0x10B0 in thread_start (libsystem_pthread.dylib:x86_64+0x1b00)

  Previous write of size 4 at 0x7fff5fbff8f0 by thread T2:
  Stack of thread T2:
    #0 0x11C8 in writer_loop worker.c:57 (libworker:x86_64+0x1c8)

  SUMMARY: ThreadSanitizer: data race (reader_loop) worker.c
==================
"""

NO_MARKER_REPORT = """\
WARNING: ThreadSanitizer: thread leak (pid=7)

  One pile of frames with no stack headers at all:
    #0 0x4444 in leaked_fn leaky.c:9 (libleak:x86_64+0x4444)
    #1 0x4544 in start_leaks leaky.c:20 (libleak:x86_64+0x4544)

  SUMMARY: ThreadSanitizer: thread leak
"""


# --- parser -------------------------------------------------------------------
def test_parse_tsan_extracts_kind_and_normalized_pcs():
    races = parse_tsan(TWO_STACK_REPORT)
    assert len(races) == 1
    race = races[0]
    assert race["kind"] == "data race"
    assert race["pc1"] == "0x00000000000010a4"
    assert race["pc2"] == "0x00000000000011c8"


def test_parse_tsan_splits_stacks_at_markers():
    race = parse_tsan(TWO_STACK_REPORT)[0]
    assert race["stack1"] == ["reader_loop", "thread_start"]
    assert race["stack2"] == ["writer_loop"]
    assert race["summary"] == "ThreadSanitizer: data race (reader_loop) worker.c"


def test_parse_tsan_defensive_no_marker_single_stack():
    race = parse_tsan(NO_MARKER_REPORT)[0]
    assert race["kind"] == "thread leak"
    assert race["stack1"] == ["leaked_fn", "start_leaks"]
    assert race["stack2"] == []
    assert race["pc2"] == ""
    assert race["pc1"] == "0x0000000000004444"


def test_parse_tsan_multiple_blocks_and_empty_text():
    races = parse_tsan(TWO_STACK_REPORT + NO_MARKER_REPORT)
    assert [r["kind"] for r in races] == ["data race", "thread leak"]
    assert parse_tsan("") == []
    assert parse_tsan("no sanitizer output here") == []


# --- signature ----------------------------------------------------------------
def test_race_signature_is_stable_and_ordered():
    race = parse_tsan(TWO_STACK_REPORT)[0]
    sig = race_signature(race)
    assert sig.startswith("tsan_") and len(sig) == len("tsan_") + 16
    assert race_signature(dict(race)) == sig
    swapped = dict(race, pc1=race["pc2"], pc2=race["pc1"])
    assert race_signature(swapped) != sig
    other = dict(race, pc2="0x000000000000dead")
    assert race_signature(other) != sig


# --- store --------------------------------------------------------------------
def _race(**over):
    base = {"kind": "data race",
            "pc1": "0x00000000000000aa", "pc2": "0x00000000000000bb",
            "stack1": ["a", "b"], "stack2": ["c"],
            "summary": "ThreadSanitizer: data race"}
    base.update(over)
    return base


def test_race_store_records_dedupes_and_bumps_count(workspace):
    store = RaceStore(workspace)
    first = store.record("mock:parser", _race(), sample_input_sha256="abc")
    assert first.id.startswith("rac_")
    assert first.count == 1 and first.status == "new"
    assert first.sample_input_sha256 == "abc"
    again = store.record("mock:parser", _race())
    assert again.id == first.id
    assert store.get(first.id).count == 2
    assert len(store.list()) == 1
    with pytest.raises(NotFoundError):
        store.get("rac_missingid00")


def test_race_store_list_orders_by_count_desc_then_id(workspace):
    store = RaceStore(workspace)
    hot = store.record("t", _race(pc1="0x0000000000000001"))
    mid = store.record("t", _race(pc1="0x0000000000000002"))
    cold = store.record("t", _race(pc1="0x0000000000000003"))
    for _ in range(2):
        store.record("t", _race(pc1=hot.pc1))
    store.record("t", _race(pc1=mid.pc1))
    assert [r.id for r in store.list()] == [hot.id, mid.id, cold.id]
    assert [r.count for r in store.list()] == [3, 2, 1]


# --- validate_modes -----------------------------------------------------------
def test_validate_modes_ok_and_dedupes_preserving_order():
    assert validate_modes(("random-delay", "yield")) == ("random-delay", "yield")
    assert validate_modes(["yield", "priority", "yield"]) == \
        ("yield", "priority")


def test_validate_modes_rejects_unknown_mode():
    from ios_research.races import PERTURB_MODES
    with pytest.raises(ValidationError) as exc:
        validate_modes(("yield", "usleep"))
    assert exc.value.exit_code == 4
    assert all(mode in str(exc.value) for mode in PERTURB_MODES)


def test_validate_modes_empty_sequence_yields_empty():
    assert validate_modes(()) == ()
    assert validate_modes([]) == ()


# --- import_report ------------------------------------------------------------
def test_import_report_counts_new_and_duplicate_blocks(workspace):
    store = RaceStore(workspace)
    text = TWO_STACK_REPORT + NO_MARKER_REPORT
    first = import_report(store, text, target="mac:parser")
    assert first == {"races": 2, "recorded": 2, "duplicates": 0}
    repeat = import_report(store, text)
    assert repeat == {"races": 2, "recorded": 0, "duplicates": 2}


# --- engine integration -------------------------------------------------------
PERTURB_CALLS: list[tuple[str, int]] = []


class RaceHookTarget(Target):
    target_id = "test:racehook"
    kind = "parser"
    description = "stub target exposing a scheduling-perturbation hook"
    formats = ("raw",)
    mock = True

    def perturb(self, mode, iteration):
        PERTURB_CALLS.append((mode, iteration))

    def _run(self, data):
        return ExecResult(outcome=Outcome.ACCEPTED, detail="ok")


class BrokenPerturbTarget(RaceHookTarget):
    target_id = "test:racehook-broken"

    def perturb(self, mode, iteration):
        raise RuntimeError("scheduler unavailable")


targets.register("test:racehook", lambda: RaceHookTarget())
targets.register("test:racehook-broken", lambda: BrokenPerturbTarget())


@pytest.fixture(autouse=True)
def _stub_targets():
    """Register stubs only while a test here runs; the global target
    registry must stay clean for cross-module inventory coverage tests."""
    PERTURB_CALLS.clear()
    targets.register("test:racehook", lambda: RaceHookTarget())
    targets.register("test:racehook-broken", lambda: BrokenPerturbTarget())
    yield
    PERTURB_CALLS.clear()
    targets._REGISTRY.pop("test:racehook", None)
    targets._REGISTRY.pop("test:racehook-broken", None)


def _make_session(workspace, *, target="test:racehook", seed=7,
                  max_cases=6, sched_modes=(), tag="a"):
    exp = ExperimentStore(workspace).create(
        target=target, device="mock:device", os_version="17.0",
        config_hash=f"cfg-race-{target}-{seed}-{max_cases}-{tag}", seed=seed)
    cs = CorpusStore(workspace)
    corpus = cs.create(f"race-corpus-{target}-{tag}")
    cs.add_bytes(corpus, b"MOCK\x01\x01\x00\x02ok", origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(experiment_id=exp.id, target=target,
                            corpus_id=corpus.id, seed=seed, workers=1,
                            max_cases=max_cases, duration_s=None,
                            sched_modes=sched_modes)
    return engine, session


def test_engine_applies_deterministic_perturb_schedule(workspace):
    engine, session = _make_session(workspace, sched_modes=("yield", "priority"),
                                    tag="hooked")
    baseline_engine, baseline = _make_session(workspace, seed=7, max_cases=6,
                                              tag="plain")
    baseline = baseline_engine.advance(baseline)

    PERTURB_CALLS.clear()
    session = engine.advance(session)
    assert PERTURB_CALLS == [("yield", 0), ("priority", 1),
                             ("yield", 2), ("priority", 3),
                             ("yield", 4), ("priority", 5)]
    assert session.sched_calls == 6
    assert session.outcomes == baseline.outcomes
    persisted = engine.get(session.id)
    assert persisted.sched_calls == 6
    assert tuple(persisted.sched_modes) == ("yield", "priority")


def test_engine_without_sched_modes_never_perturbs(workspace):
    engine, session = _make_session(workspace)
    session = engine.advance(session)
    assert PERTURB_CALLS == []
    assert session.sched_calls == 0

    plain_engine, plain = _make_session(workspace, target="mock:parser",
                                        sched_modes=("yield",))
    plain = plain_engine.advance(plain)
    assert plain.cursor == 6 and plain.sched_calls == 0


def test_engine_perturb_failure_keeps_campaign_running(workspace):
    engine, session = _make_session(workspace, target="test:racehook-broken",
                                    sched_modes=("affinity",))
    session = engine.advance(session)
    assert PERTURB_CALLS == []
    assert session.sched_calls == 0
    assert session.status == "completed"
    assert session.outcomes.get("accepted") == 6


# --- CLI surface --------------------------------------------------------------
def test_cli_fuzz_start_sched_perturb_roundtrip(workspace, capsys):
    ws = str(workspace.root)
    rc = main(["fuzz", "start", "--target", "test:racehook",
               "--sched-perturb", "priority,yield,priority",
               "--max-cases", "4", "--seed", "3", "--json",
               "--workspace", ws])
    assert rc == 0
    capsys.readouterr()
    session = FuzzEngine(workspace).latest()
    assert tuple(session.sched_modes) == ("priority", "yield")
    assert session.sched_calls == 4


def test_cli_fuzz_start_invalid_sched_mode_exit_code(workspace, capsys):
    ws = str(workspace.root)
    rc = main(["fuzz", "start", "--target", "test:racehook",
               "--sched-perturb", "yield,usleep", "--max-cases", "2",
               "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 4  # VALIDATION
    assert payload["ok"] is False
    assert "usleep" in payload["error"]
