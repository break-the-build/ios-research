"""Goals 21-24: new bounty/detection/CVE/latency environments and their goals."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).parents[1] / "tools" / "experiment_loop"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

# The ios_env plugins build on the optional external experiment-loop harness
# (a local editable install, not a PyPI dependency). Without it the module
# cannot even be collected, which used to turn CI red on every push (#192).
pytest.importorskip("experiment_loop",
                    reason="optional experiment-loop harness not installed")

import ios_env  # noqa: E402,F401  (registers all environments)
from experiment_loop.environments.base import get_environment  # noqa: E402


NEW_GOALS = [
    ("21-bounty-evidence-readiness.json", "ios_research_bounty_readiness"),
    ("22-detection-quality.json", "ios_research_detection"),
    ("23-cve-regression-integrity.json", "ios_research_cve_regression"),
    ("24-pipeline-latency.json", "ios_research_pipeline_latency"),
]


@pytest.mark.parametrize("filename,env_name", NEW_GOALS)
def test_goal_declares_registered_environment_and_metrics(filename, env_name):
    goal = json.loads((Path(__file__).parents[1] / "goals" / filename)
                      .read_text())
    env = get_environment(env_name)
    assert goal["environment"] == env.name
    declared = {m["name"] for m in goal["metrics"]}
    implemented = {m.name for m in env.metric_list}
    assert declared == implemented, (filename, declared ^ implemented)
    # Constraints may only reference declared metrics.
    assert {c["metric"] for c in goal["constraints"]} <= declared
    # Knob defaults must be valid values for their kind.
    for knob in env.knob_list:
        if knob.values:
            assert knob.default in knob.values


@pytest.mark.parametrize("filename,env_name", NEW_GOALS)
def test_environment_run_is_deterministic(filename, env_name):
    goal = json.loads((Path(__file__).parents[1] / "goals" / filename)
                      .read_text())
    env = get_environment(env_name)
    config = {k.name: k.default for k in env.knob_list}
    a = env.run(config, samples=3, seed=11)
    b = env.run(config, samples=3, seed=11)
    # Ratio/count metrics must be bit-identical; wall-clock throughput and
    # duration metrics are measurements and only need to be finite.
    temporal = ("seconds", "per_second")
    for name, summary in a.metrics.items():
        if any(marker in name for marker in temporal):
            assert summary.mean >= 0.0
            continue
        assert summary.mean == b.metrics[name].mean, (env_name, name)


class TestBountyReadinessEnv:
    def test_knobs_on_reach_higher_pass_rate_than_control(self):
        env = get_environment("ios_research_bounty_readiness")
        control = env.run({}, samples=4, seed=3)
        tuned = env.run({"reproduce_before_export": True,
                         "minimize_before_export": True}, samples=4, seed=3)
        assert tuned.metrics["validation_pass_rate"].mean >= \
            control.metrics["validation_pass_rate"].mean
        # Hard invariant from the goal holds in both arms.
        assert tuned.metrics["export_determinism"].mean == 1.0
        assert control.metrics["export_determinism"].mean == 1.0

    def test_known_missing_check_is_documented(self):
        # The affected_versions provenance gap surfaced by this environment;
        # see docs/GOALS-REVIEW.md section 2. If this starts passing at 1.0,
        # the framework fix landed - update GOALS-REVIEW accordingly.
        env = get_environment("ios_research_bounty_readiness")
        tuned = env.run({"reproduce_before_export": True,
                         "minimize_before_export": True}, samples=4, seed=5)
        assert tuned.metrics["validation_pass_rate"].mean < 1.0


class TestDetectionEnv:
    def test_builtin_rules_perfect_on_self_consistency_set(self):
        env = get_environment("ios_research_detection")
        obs = env.run({"min_severity": "info", "dedupe_by_family": False},
                      samples=10, seed=1)
        assert obs.metrics["detection_recall"].mean == 1.0
        assert obs.metrics["false_positive_rate"].mean == 0.0
        assert obs.metrics["rules_loaded"].mean >= 5.0

    def test_severity_threshold_still_catches_critical_family(self):
        env = get_environment("ios_research_detection")
        strict = env.run({"min_severity": "critical",
                          "dedupe_by_family": False}, samples=10, seed=1)
        # The spyware combo rule is critical; persistence/keychain are not.
        assert strict.metrics["detection_recall"].mean < 1.0


class TestCveRegressionEnv:
    def test_catalog_fully_passes_with_integrity(self):
        env = get_environment("ios_research_cve_regression")
        obs = env.run({"reverify_inputs": True, "skip_unregistered": True},
                      samples=2, seed=0)
        assert obs.metrics["regression_pass_rate"].mean == 1.0
        assert obs.metrics["registry_integrity"].mean == 1.0


class TestPipelineLatencyEnv:
    def test_stage_timings_always_emitted(self):
        env = get_environment("ios_research_pipeline_latency")
        obs = env.run({}, samples=3, seed=2)
        for metric in ("pipeline_total_seconds", "triage_stage_seconds",
                       "report_stage_seconds", "validation_stage_seconds"):
            assert metric in obs.metrics
            assert obs.metrics[metric].n == 3

    def test_more_stages_cost_more_time(self):
        env = get_environment("ios_research_pipeline_latency")
        minimal = env.run({}, samples=3, seed=4)
        full = env.run({"do_analyze": True, "do_reproduce": True,
                        "do_minimize": True}, samples=3, seed=4)
        assert full.metrics["pipeline_total_seconds"].mean >= \
            minimal.metrics["pipeline_total_seconds"].mean
