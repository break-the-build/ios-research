"""Windowed/threaded execution semantics (#199).

Locks in the #199 contract on top of the #207 executor abstraction:

* workers>1 / window>1 fans executions out to a thread pool but the run stays
  a pure function of ``(seed, window)`` — a plain (non-coverage) target yields
  byte-identical sequences and state to the serial loop;
* pause/resume equivalence holds for threaded configurations;
* ``max_new``/case budgets are exact even when the window is wider;
* provenance (workers/window) is surfaced through ``session.stats()``.
"""

from __future__ import annotations

import time

import pytest

from ios_research.config import DEFAULT_CONFIG
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine, DEFAULT_BASE
from ios_research.targets import register as tgt_register
from ios_research.targets.base import ExecResult, Outcome, Target

W = DEFAULT_CONFIG["fuzz"]["strategy_weights"]

_corpus_seq = 0


class _BareStub(Target):
    """Deterministic target with NO coverage adapter.

    Without ``coverage_features`` there is no feedback lag, so a windowed
    threaded run must reproduce the serial run's input stream exactly.
    """

    target_id = "test:window-bare"
    kind = "parser"
    description = "deterministic crash/reject rule, no coverage hook"
    formats = ("bin",)

    def seeds(self):
        return [b"SEED\x00\x01"]

    def _run(self, data):
        if data.count(b"\xff") >= 2:
            return ExecResult(outcome=Outcome.CRASH, detail="bare-crash")
        return ExecResult(outcome=Outcome.REJECTED, detail="bare-reject")


@pytest.fixture(autouse=True)
def _unregister_bare_stub():
    yield
    from ios_research.targets import _REGISTRY
    _REGISTRY.pop(_BareStub.target_id, None)


def _make_session(workspace, *, seed=1, max_cases=200, workers=1, window=None,
                  target_id="mock:parser", seed_bytes=DEFAULT_BASE):
    global _corpus_seq
    _corpus_seq += 1
    exp = ExperimentStore(workspace).create(
        target=target_id, device="mock:device", os_version="17.0",
        config_hash="c", seed=seed)
    cs = CorpusStore(workspace)
    corpus = cs.create(f"f{_corpus_seq}", target=target_id)
    cs.add_bytes(corpus, seed_bytes, origin="seed")
    eng = FuzzEngine(workspace)
    session = eng.create(experiment_id=exp.id, target=target_id,
                         corpus_id=corpus.id, seed=seed, workers=workers,
                         window=window, max_cases=max_cases, duration_s=None,
                         strategy_weights=W)
    return eng, cs, corpus, session


def _manifest_shas(cs, corpus):
    return sorted(tc["sha256"] for tc in cs.get(corpus.id).testcases)


# --- equivalence: threaded windowed run == serial run -----------------------
def test_threaded_run_matches_serial_on_plain_target(workspace):
    from ios_research.targets import register as tgt_register
    tgt_register(_BareStub.target_id, lambda: _BareStub())

    eng1, cs1, c1, s1 = _make_session(workspace, max_cases=240,
                                      target_id=_BareStub.target_id)
    s1 = eng1.advance(s1)

    eng4, cs4, c4, s4 = _make_session(workspace, max_cases=240,
                                      workers=4, window=8,
                                      target_id=_BareStub.target_id)
    s4 = eng4.advance(s4)

    assert s4.outcomes == s1.outcomes
    assert s4.crash_ids == s1.crash_ids
    assert s4.cursor == s1.cursor == 240
    assert _manifest_shas(cs4, c4) == _manifest_shas(cs1, c1)


def test_resume_equivalence_at_window_8_workers_4(tmp_path):
    from ios_research.workspace import Workspace
    from ios_research import __version__
    from ios_research.targets import register as tgt_register
    tgt_register(_BareStub.target_id, lambda: _BareStub())

    def _fresh(name):
        ws = Workspace(tmp_path / name / ".ios-research")
        ws.init(framework_version=__version__, created_at="t")
        return ws

    ws_single = _fresh("single")
    e1, cs1, c1, s1 = _make_session(ws_single, max_cases=300, workers=4,
                                    window=8, target_id=_BareStub.target_id)
    s1 = e1.advance(s1)

    ws_chunk = _fresh("chunk")
    e2, cs2, c2, s2 = _make_session(ws_chunk, max_cases=300, workers=4,
                                    window=8, target_id=_BareStub.target_id)
    while s2.status != "completed":
        s2 = e2.advance(s2, max_new=90)

    assert s2.outcomes == s1.outcomes
    assert s2.crash_ids == s1.crash_ids
    assert _manifest_shas(cs2, c2) == _manifest_shas(cs1, c1)
    counts1 = {c.id: c.count for c in e1.crash_store.list()}
    counts2 = {c.id: c.count for c in e2.crash_store.list()}
    assert counts1 == counts2


# --- exact budgets despite wide windows -------------------------------------
def test_max_new_is_exact_even_when_wider_than_window(workspace):
    eng, cs, corpus, session = _make_session(workspace, max_cases=50,
                                             workers=4, window=8)
    executed = 0
    rounds = 0
    while session.status != "completed":
        before = session.cursor
        session = eng.advance(session, max_new=5)
        delta = session.cursor - before
        assert delta <= 5          # never overshoots the per-call budget
        executed += delta
        rounds += 1
        assert rounds < 100        # termination guard
    assert session.cursor == 50 == executed


def test_final_partial_window_covers_remaining_budget(workspace):
    eng, cs, corpus, session = _make_session(workspace, max_cases=37,
                                             workers=2, window=8)
    session = eng.advance(session)
    assert session.cursor == 37
    assert session.status == "completed"


# --- provenance --------------------------------------------------------------
def test_stats_and_create_surface_workers_and_window(workspace):
    _, _, _, session = _make_session(workspace, workers=3, window=12)
    stats = session.stats()
    assert stats["workers"] == 3
    assert stats["window"] == 12

    _, _, _, default_session = _make_session(workspace)
    assert default_session.window == 1      # None -> default

    _, _, _, clamped = _make_session(workspace, window=0)
    assert clamped.window >= 1              # never below one


# --- scaling smoke -----------------------------------------------------------
class _SlowStub(Target):
    target_id = "test:slow-window-stub"
    kind = "parser"
    description = "sleeps per execution to expose thread overlap"
    formats = ("bin",)

    def seeds(self):
        return [b"S"]

    def _run(self, data):
        time.sleep(0.02)
        return ExecResult(outcome=Outcome.ACCEPTED, detail="slow-ok")


@pytest.fixture(autouse=True)
def _unregister_slow_stub():
    yield
    from ios_research.targets import _REGISTRY
    _REGISTRY.pop(_SlowStub.target_id, None)


def test_threaded_execution_overlaps_slow_target(workspace):
    tgt_register(_SlowStub.target_id, lambda: _SlowStub())
    exp = ExperimentStore(workspace).create(
        target=_SlowStub.target_id, device="mock:device", os_version="17.0",
        config_hash="c", seed=3)
    cs = CorpusStore(workspace)
    corpus = cs.create("f")
    cs.add_bytes(corpus, b"SLOWSEED\x00\x01", origin="seed")

    def _timed(workers):
        eng = FuzzEngine(workspace)
        s = eng.create(experiment_id=exp.id, target=_SlowStub.target_id,
                       corpus_id=corpus.id, seed=3, workers=workers,
                       window=8, max_cases=24, duration_s=None,
                       strategy_weights=W)
        start = time.monotonic()
        eng.advance(s)
        return time.monotonic() - start

    serial = _timed(1)
    threaded = _timed(4)
    # Generous bound: 24 * 20ms = 480ms serial; 4 workers should land well
    # under 3/4 of that even on loaded CI machines.
    assert threaded < serial * 0.75
