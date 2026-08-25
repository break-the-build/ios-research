"""Periodic checkpoint flushes during advance() (#208).

Locks in that mid-run checkpoints (a) persist crash discoveries even when the
run dies before the end-of-call flush, (b) are state-neutral — a checkpointed
run finishes with exactly the same records and manifest as a plain run — and
(c) never double-count thanks to accumulator resets.
"""

from __future__ import annotations

import pytest

from ios_research.config import DEFAULT_CONFIG
from ios_research.corpus import CorpusStore
from ios_research.crashes import CrashStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine, DEFAULT_BASE, checkpoint_due
from ios_research.targets import ExecResult, Outcome, Target, diagnostics

W = DEFAULT_CONFIG["fuzz"]["strategy_weights"]

_corpus_seq = 0


class _CrashyStub(Target):
    """Deterministic always-crashy target with two signature families."""

    target_id = "test:ckpt-crashy"
    kind = "parser"
    description = "crashes on most inputs, alternating signature families"
    formats = ("bin",)

    def seeds(self):
        return [b"K\x00\x01"]

    def _run(self, data):
        classification = ("NULL_DEREFERENCE" if sum(data) % 2 == 0
                          else "OUT_OF_BOUNDS_READ")
        d = diagnostics.build(data, classification, "CkptMod", ["sym_x"])
        return ExecResult(outcome=Outcome.CRASH, detail="ckpt-crash",
                          diagnostics=d)


class _AbortAfter(_CrashyStub):
    """Raises SystemExit on the Nth execution, simulating process death."""

    budget = 10
    executed = 0

    def _run(self, data):
        type(self).executed += 1
        if type(self).executed >= self.budget:
            raise SystemExit("simulated kill mid-advance")
        return super()._run(data)


@pytest.fixture(autouse=True)
def _register_and_cleanup():
    from ios_research.targets import _REGISTRY
    _REGISTRY[_CrashyStub.target_id] = _CrashyStub
    _REGISTRY[_AbortAfter.target_id] = _AbortAfter
    yield
    _REGISTRY.pop(_CrashyStub.target_id, None)
    _REGISTRY.pop(_AbortAfter.target_id, None)


_AbortAfter.target_id = "test:ckpt-abort"


def _make_session(workspace, *, seed=5, max_cases=40, checkpoint_cases=None,
                  checkpoint_seconds=None, target_id=None):
    global _corpus_seq
    _corpus_seq += 1
    target_id = target_id or _CrashyStub.target_id
    exp = ExperimentStore(workspace).create(
        target=target_id, device="mock:device",
        os_version="17.0", config_hash="c", seed=seed)
    cs = CorpusStore(workspace)
    corpus = cs.create(f"ck{_corpus_seq}", target=target_id)
    cs.add_bytes(corpus, DEFAULT_BASE, origin="seed")
    eng = FuzzEngine(workspace)
    kwargs = {}
    if checkpoint_cases is not None:
        kwargs["checkpoint_cases"] = checkpoint_cases
    if checkpoint_seconds is not None:
        kwargs["checkpoint_seconds"] = checkpoint_seconds
    session = eng.create(experiment_id=exp.id, target=target_id,
                         corpus_id=corpus.id, seed=seed, workers=1,
                         max_cases=max_cases, duration_s=None,
                         strategy_weights=W, **kwargs)
    return eng, cs, corpus, session


def _manifest_shas(cs, corpus):
    return sorted(tc["sha256"] for tc in cs.get(corpus.id).testcases)


# --- the point of the feature: death mid-run keeps discoveries ---------------
def test_abort_mid_run_keeps_checkpointed_crashes(workspace):
    _AbortAfter.budget = 9
    _AbortAfter.executed = 0
    eng, cs, corpus, session = _make_session(
        workspace, checkpoint_cases=4, target_id=_AbortAfter.target_id)

    with pytest.raises(SystemExit):
        eng.advance(session)

    # Fresh store instance = what a post-crash process would see on disk.
    fresh = CrashStore(workspace)
    records = fresh.list()
    assert len(records) >= 1
    assert sum(r.count for r in records) >= 1


def test_no_checkpoint_config_still_loses_on_abort(workspace):
    """Control: with checkpoints disabled by threshold=0, nothing persists."""
    _AbortAfter.budget = 6
    _AbortAfter.executed = 0
    eng, cs, corpus, session = _make_session(
        workspace, checkpoint_cases=0, target_id=_AbortAfter.target_id)
    with pytest.raises(SystemExit):
        eng.advance(session)
    assert CrashStore(workspace).list() == []


# --- neutrality: early flushes never change outcomes -------------------------
def test_checkpointed_run_matches_plain_run(tmp_path):
    from ios_research.workspace import Workspace
    from ios_research import __version__

    def _fresh(name):
        ws = Workspace(tmp_path / name / ".ios-research")
        ws.init(framework_version=__version__, created_at="t")
        return ws

    eng_a, cs_a, c_a, s_a = _make_session(_fresh("plain"), seed=7,
                                          max_cases=60)
    s_a = eng_a.advance(s_a)

    eng_b, cs_b, c_b, s_b = _make_session(_fresh("ckpt"), seed=7,
                                          max_cases=60, checkpoint_cases=7)
    s_b = eng_b.advance(s_b)

    assert s_b.outcomes == s_a.outcomes
    assert s_b.crashes == s_a.crashes
    assert s_b.crash_ids == s_a.crash_ids
    counts_a = {r.id: r.count for r in eng_a.crash_store.list()}
    counts_b = {r.id: r.count for r in eng_b.crash_store.list()}
    assert counts_b == counts_a                      # no double-counting
    assert sum(counts_b.values()) == s_b.outcomes["crash"]
    assert _manifest_shas(cs_b, c_b) == _manifest_shas(cs_a, c_a)


def test_final_flush_after_checkpoints_completes_accounting(workspace):
    eng, cs, corpus, session = _make_session(workspace, max_cases=30,
                                             checkpoint_cases=5)
    session = eng.advance(session)
    counts = {r.id: r.count for r in CrashStore(workspace).list()}
    assert set(counts) == set(session.crash_ids)
    assert sum(counts.values()) == session.outcomes["crash"]


# --- defaults & provenance ----------------------------------------------------
def test_session_defaults_and_overrides_persist(workspace):
    _, _, _, s_default = _make_session(workspace)
    assert s_default.checkpoint_cases == 256
    assert s_default.checkpoint_seconds == 30.0

    _, _, _, s_custom = _make_session(workspace, checkpoint_cases=11,
                                      checkpoint_seconds=0)
    assert s_custom.checkpoint_cases == 11
    assert s_custom.checkpoint_seconds == 0.0        # time mechanism off


# --- threshold truth table -----------------------------------------------------
def test_checkpoint_due_truth_table():
    pending = True
    assert checkpoint_due(pending=True, cases_since_flush=256,
                          elapsed_s=0.0, checkpoint_cases=256,
                          checkpoint_seconds=30.0) is True
    assert checkpoint_due(pending=pending, cases_since_flush=255,
                          elapsed_s=31.0, checkpoint_cases=256,
                          checkpoint_seconds=30.0) is True   # time branch
    assert checkpoint_due(pending=True, cases_since_flush=255,
                          elapsed_s=5.0, checkpoint_cases=256,
                          checkpoint_seconds=30.0) is False  # below both
    assert checkpoint_due(pending=False, cases_since_flush=999,
                          elapsed_s=999.0, checkpoint_cases=256,
                          checkpoint_seconds=30.0) is False  # nothing to flush
    assert checkpoint_due(pending=True, cases_since_flush=999_999,
                          elapsed_s=999.0, checkpoint_cases=0,
                          checkpoint_seconds=0.0) is False   # all disabled
