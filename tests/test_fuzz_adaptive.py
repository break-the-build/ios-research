"""Online strategy-weight adaptation (#203).

Locks in that ``adapt_strategies`` (a) is fully opt-in — disabled runs are
byte-identical to baseline — (b) reweights deterministically at fixed case
checkpoints using bounded multiplicative updates with floors and caps, and
(c) resumes deterministically since yield counters ride on the session.
"""

from __future__ import annotations

import pytest

from ios_research.config import DEFAULT_CONFIG
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine, adapted_weights
from ios_research.targets import ExecResult, Outcome, Target
from ios_research.workspace import Workspace
from ios_research import __version__

W_BASE = dict(DEFAULT_CONFIG["fuzz"]["strategy_weights"])

_corpus_seq = 0


class _LengthFeatureStub(Target):
    """Coverage features keyed by input length bucket.

    Truncation/deletion quickly produce short inputs; insertion/byte flips
    wander across buckets — deterministic skew without randomness.
    """

    target_id = "test:adapt-lenfeat"
    kind = "parser"
    description = "novel feature per unseen length bucket"
    formats = ("bin",)

    def seeds(self):
        return [b"ABCDEFGH"]

    def coverage_features(self, data, result):
        return (f"len:{min(len(data), 12)}",)

    def _run(self, data):
        return ExecResult(outcome=Outcome.REJECTED, detail="len-stub")


@pytest.fixture(autouse=True)
def _register_and_cleanup():
    from ios_research.targets import _REGISTRY
    _REGISTRY[_LengthFeatureStub.target_id] = _LengthFeatureStub
    yield
    _REGISTRY.pop(_LengthFeatureStub.target_id, None)


def _fresh(tmp_path, name):
    ws = Workspace(tmp_path / name / ".ios-research")
    ws.init(framework_version=__version__, created_at="t")
    return ws


def _make_session(workspace, *, seed=13, max_cases=96, adapt=False,
                  adapt_every=None):
    global _corpus_seq
    _corpus_seq += 1
    exp = ExperimentStore(workspace).create(
        target=_LengthFeatureStub.target_id, device="mock:device",
        os_version="17.0", config_hash="c", seed=seed)
    cs = CorpusStore(workspace)
    corpus = cs.create(f"ad{_corpus_seq}", target=_LengthFeatureStub.target_id)
    cs.add_bytes(corpus, b"ABCDEFGH", origin="seed")
    eng = FuzzEngine(workspace)
    kwargs = {}
    if adapt_every is not None:
        kwargs["strategy_adapt_every"] = adapt_every
    session = eng.create(experiment_id=exp.id,
                         target=_LengthFeatureStub.target_id,
                         corpus_id=corpus.id, seed=seed, workers=1,
                         max_cases=max_cases, duration_s=None,
                         strategy_weights=dict(W_BASE),
                         adapt_strategies=adapt, **kwargs)
    return eng, cs, corpus, session


# --- pure helper ---------------------------------------------------------------
def test_adapted_weights_truth_table():
    stats = {"byte": {"executions": 10, "features": 5},
             "deletion": {"executions": 10, "features": 0}}
    out = adapted_weights({"byte": 2, "deletion": 4}, stats)
    assert out["byte"] > 2                       # winner grows
    assert out["byte"] <= 64                     # cap holds
    assert out["deletion"] == max(1, int(round(4 * 0.5)))   # bounded shrink

    # no measurements -> unchanged
    assert adapted_weights({"byte": 3}, {}) == {"byte": 3}
    # floor keeps starved strategies alive
    out2 = adapted_weights({"truncation": 1},
                           {"truncation": {"executions": 50, "features": 0}})
    assert out2["truncation"] >= 1


# --- end-to-end -----------------------------------------------------------------
def test_adaptation_changes_weights_and_respects_bounds(tmp_path):
    eng, cs, corpus, s = _make_session(_fresh(tmp_path, "on"), max_cases=192,
                                       adapt=True, adapt_every=16)
    start_weights = dict(s.strategy_weights)
    s = eng.advance(s)
    assert s.strategy_weights != start_weights          # something moved
    for strat, w in s.strategy_weights.items():
        assert w >= 1                                   # floors
        assert w <= 64                                  # caps
        assert isinstance(w, int)
    assert s.stats().get("outcomes") is not None


def test_disabled_run_is_byte_identical_to_baseline(tmp_path):
    base_ws = _fresh(tmp_path, "base")
    e1, cs1, c1, s1 = _make_session(base_ws, max_cases=120)
    s1 = e1.advance(s1)

    off_ws = _fresh(tmp_path, "off-explicit")
    e2, cs2, c2, s2 = _make_session(off_ws, max_cases=120, adapt=False)
    s2 = e2.advance(s2)

    assert s2.strategy_weights == s1.strategy_weights == W_BASE
    assert s2.strategy_yield in ({}, None) or s2.strategy_yield == {}
    assert s2.outcomes == s1.outcomes
    assert sorted(tc["sha256"] for tc in cs2.get(c2.id).testcases) == \
        sorted(tc["sha256"] for tc in cs1.get(c1.id).testcases)


def test_resume_matches_single_run_with_adaptation(tmp_path):
    single = _fresh(tmp_path, "single")
    e1, cs1, c1, s1 = _make_session(single, max_cases=128, adapt=True,
                                    adapt_every=16)
    s1 = e1.advance(s1)

    chunked = _fresh(tmp_path, "chunk")
    e2, cs2, c2, s2 = _make_session(chunked, max_cases=128, adapt=True,
                                    adapt_every=16)
    while s2.status != "completed":
        s2 = e2.advance(s2, max_new=30)

    assert s2.outcomes == s1.outcomes
    assert s2.strategy_weights == s1.strategy_weights
    assert s2.cases_since_adapt == s1.cases_since_adapt
    assert s2.crash_ids == s1.crash_ids


def test_session_document_round_trips_adapt_state(workspace):
    _, _, _, s = _make_session(workspace, adapt=True, adapt_every=8)
    doc = s.to_dict()
    for key in ("adapt_strategies", "strategy_adapt_every",
                "cases_since_adapt", "strategy_yield"):
        assert key in doc
