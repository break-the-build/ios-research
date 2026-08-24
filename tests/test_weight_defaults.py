"""Locks the goal-05 engine-throughput default weighting (issue #164).

The 2026-08-23 experiment-loop run measured {deletion: 4, integer: 2,
structure_aware: 4} (others at their goal-06 values) at +27.05% end-to-end
executions_per_second through the real FuzzEngine with the hard guardrail
crash_detection_rate >= 0.99 held (baseline 1f25151, seed 20260823, Welch
t-test). These tests pin those promoted values so they cannot drift silently.
"""

from __future__ import annotations

from ios_research import mutation
from ios_research.config import DEFAULT_CONFIG, Config

EXPECTED_WEIGHTS = {
    "byte": 1,
    "truncation": 1,
    "insertion": 1,
    "deletion": 4,
    "boundary": 2,
    "integer": 2,
    "structure_aware": 4,
}


# --- (a) the shipped default equals the tuned values exactly ---------------
def test_default_config_weights_match_tuned_values():
    assert DEFAULT_CONFIG["fuzz"]["strategy_weights"] == EXPECTED_WEIGHTS


def test_merged_config_exposes_the_same_defaults():
    # Config() deep-merges DEFAULT_CONFIG with user overrides; with none, the
    # tuned block must survive verbatim (the way other tests read it).
    assert Config().get("fuzz.strategy_weights") == EXPECTED_WEIGHTS


def test_no_extra_or_missing_weight_keys():
    assert set(DEFAULT_CONFIG["fuzz"]["strategy_weights"]) \
        == set(mutation.STRATEGIES)


# --- (b) the weighted pool encodes the tuned multiplicities ----------------
def test_weighted_pool_counts_match_default_weights():
    pool = mutation.weighted_strategies(
        dict(DEFAULT_CONFIG["fuzz"]["strategy_weights"]))
    assert len(pool) == sum(EXPECTED_WEIGHTS.values())  # 15 slots total
    assert pool.count("deletion") == 4
    assert pool.count("integer") == 2
    assert pool.count("structure_aware") == 4
    assert pool.count("boundary") == 2
    assert pool.count("byte") == 1
    assert pool.count("truncation") == 1
    assert pool.count("insertion") == 1


def test_weighted_pool_order_is_deterministic():
    # Pool order follows mutation.STRATEGIES so uniform draws stay stable
    # across (seed, iteration) pairs even after a re-weighting.
    weights = DEFAULT_CONFIG["fuzz"]["strategy_weights"]
    expected = tuple(s for s in mutation.STRATEGIES
                     for _ in range(weights[s]))
    assert mutation.weighted_strategies(dict(weights)) == expected


# --- (c) empty weights still fall back to uniform ---------------------------
def test_none_weights_fall_back_to_uniform_identity():
    assert mutation.weighted_strategies(None) == mutation.STRATEGIES


def test_empty_dict_weights_fall_back_to_uniform_identity():
    assert mutation.weighted_strategies({}) == mutation.STRATEGIES


def test_all_zero_weights_fall_back_to_uniform_identity():
    zeroed = {s: 0 for s in mutation.STRATEGIES}
    assert mutation.weighted_strategies(zeroed) == mutation.STRATEGIES
