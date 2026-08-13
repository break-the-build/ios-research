"""Tests for configurable mutation-strategy weighting (issue #1).

The default weighting is tuned via the experiment-loop 'ios_research_fuzzer'
environment to improve fuzz effectiveness while keeping every strategy active.
These tests lock in that behavior and guard against regressions.
"""

from __future__ import annotations

import pytest

from ios_research import mutation
from ios_research.config import Config
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine, DEFAULT_BASE
from ios_research.targets import create
from ios_research.targets.base import Outcome

STRATEGIES = mutation.STRATEGIES


def _unique_crashes(weights, *, target_id="mock:parser", budget=60,
                    seeds=range(30)):
    target = create(target_id)
    base = target.seeds()[0] if target.seeds() else DEFAULT_BASE
    totals = []
    for s in seeds:
        sigs = set()
        for i in range(budget):
            data, _ = mutation.mutate(base, 100003 * s + 7, i,
                                      struct_fn=target.structure_mutate,
                                      weights=weights)
            r = target.execute(data)
            if r.outcome in (Outcome.CRASH, Outcome.ABNORMAL) and r.diagnostics:
                sigs.add(r.diagnostics.signature)
        totals.append(len(sigs))
    return sum(totals) / len(totals)


# --- weighted_strategies --------------------------------------------------
def test_weighted_strategies_repeats_by_weight():
    pool = mutation.weighted_strategies({"byte": 0, "structure_aware": 3})
    assert pool.count("structure_aware") == 3
    assert pool.count("byte") == 0
    assert "boundary" in pool  # unspecified defaults to weight 1


def test_weighted_strategies_none_is_identity():
    assert mutation.weighted_strategies(None) == STRATEGIES


def test_all_zero_weights_fall_back_to_uniform():
    assert mutation.weighted_strategies({s: 0 for s in STRATEGIES}) == STRATEGIES


# --- backward compatibility -----------------------------------------------
def test_mutate_without_weights_is_unchanged():
    # weights=None must reproduce the exact prior selection sequence.
    for i in range(50):
        a = mutation.mutate(DEFAULT_BASE, 42, i)
        b = mutation.mutate(DEFAULT_BASE, 42, i, weights=None)
        assert a == b


def test_mutate_with_weights_is_deterministic():
    w = {"structure_aware": 3, "boundary": 2}
    for i in range(50):
        assert mutation.mutate(DEFAULT_BASE, 7, i, weights=w) == \
            mutation.mutate(DEFAULT_BASE, 7, i, weights=w)


# --- effectiveness improvement (the promoted change) ----------------------
def test_default_weights_beat_uniform_on_mock_and_audio():
    uniform = {s: 1 for s in STRATEGIES}
    default = Config().get("fuzz.strategy_weights")
    # Default keeps every strategy active (no strategy disabled).
    assert all(default[s] >= 1 for s in STRATEGIES)
    for target_id in ("mock:parser", "audio:wav", "audio:aac"):
        u = _unique_crashes(uniform, target_id=target_id)
        d = _unique_crashes(default, target_id=target_id)
        assert d >= u, f"{target_id}: default {d} !>= uniform {u}"


def test_reproducibility_constraint_holds_under_default_weights():
    # Every discovered crash must reproduce (goal 06 hard constraint >= 0.95).
    target = create("mock:parser")
    default = Config().get("fuzz.strategy_weights")
    reproduced = total = 0
    for i in range(120):
        data, _ = mutation.mutate(DEFAULT_BASE, 3, i,
                                  struct_fn=target.structure_mutate,
                                  weights=default)
        r = target.execute(data)
        if r.outcome == Outcome.CRASH and r.diagnostics:
            total += 1
            r2 = target.execute(data)
            if r2.diagnostics.signature == r.diagnostics.signature:
                reproduced += 1
    assert total > 0 and reproduced / total >= 0.95


# --- engine wiring --------------------------------------------------------
def test_engine_persists_and_uses_weights(workspace):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="cfg_x", seed=1)
    cs = CorpusStore(workspace)
    corpus = cs.create("w")
    cs.add_bytes(corpus, DEFAULT_BASE, origin="seed")
    engine = FuzzEngine(workspace)
    weights = Config().get("fuzz.strategy_weights")
    session = engine.create(experiment_id=exp.id, target="mock:parser",
                            corpus_id=corpus.id, seed=1, workers=1,
                            max_cases=100, duration_s=None,
                            strategy_weights=weights)
    assert session.strategy_weights == weights
    session = engine.advance(session)
    # Persisted and reloadable.
    assert engine.get(session.id).strategy_weights == weights
    assert session.unique_crashes > 0
