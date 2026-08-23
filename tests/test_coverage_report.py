"""Coverage, corpus-quality, and target-reachability reports (#34)."""

from __future__ import annotations

import json

import pytest

from ios_research.coverage_report import CoverageReporter
from ios_research.corpus import CorpusStore
from ios_research.errors import NotFoundError, ValidationError
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine
from tests.test_constraint_guided import (
    GATED_MAGIC, GatedMagicTarget, gated_target  # noqa: F401 (fixture)
)


def _run_session(workspace, target_id, *, seed=9, max_cases=300,
                 dictionary=None):
    exp = ExperimentStore(workspace).create(
        target=target_id, device="mock:device", os_version="17.0",
        config_hash=f"cov-{seed}-{max_cases}", seed=seed)
    store = CorpusStore(workspace)
    corpus = store.create(f"cov-{seed}-{max_cases}", target=target_id)
    store.add_bytes(corpus, b"AAAAAAAABBBBBBBB", origin="seed")
    engine = FuzzEngine(workspace)
    kwargs = {}
    if dictionary:
        kwargs["dictionary_tokens"] = dictionary
    session = engine.create(
        experiment_id=exp.id, target=target_id, corpus_id=corpus.id,
        seed=seed, workers=1, max_cases=max_cases, duration_s=None, **kwargs)
    return engine.advance(session)


# --- attribution / quality ---------------------------------------------------

def test_report_attributes_features_to_inputs(workspace, gated_target):
    from ios_research.dictionary import DictionaryToken
    session = _run_session(
        workspace, gated_target,
        dictionary=[DictionaryToken(name="gate", value=GATED_MAGIC)])
    report = CoverageReporter(workspace).build(session)

    assert report["coverage"]["measured"] is True
    assert "gate:secret" in report["attribution"]
    assert report["attribution"]["gate:entry"]  # entry feature attributed too
    assert report["corpus_quality"]["inputs"] >= 1


def test_attribution_lists_only_feature_introducing_inputs(
        workspace, gated_target):
    """An input that merely reaches a feature is not its introducer."""
    from types import SimpleNamespace

    from ios_research.dictionary import DictionaryToken
    session = _run_session(
        workspace, gated_target,
        dictionary=[DictionaryToken(name="gate", value=GATED_MAGIC)])
    reporter = CoverageReporter(workspace)
    stub_corpus = SimpleNamespace(testcases=[
        {"sha256": "a" * 64, "size": 4,
         "coverage_features": ["gate:entry"],
         "coverage_new_features": ["gate:entry"]},
        {"sha256": "b" * 64, "size": 4,
         "coverage_features": ["gate:entry", "gate:secret"],
         "coverage_new_features": []},
    ])
    reporter.corpus_store = SimpleNamespace(
        get=lambda corpus_id: stub_corpus)
    report = reporter.build(session)
    assert report["attribution"] == {"gate:entry": ["a" * 64]}


def test_report_hot_inputs_and_minimization_savings(workspace, gated_target):
    from ios_research.dictionary import DictionaryToken
    session = _run_session(
        workspace, gated_target,
        dictionary=[DictionaryToken(name="gate", value=GATED_MAGIC)])
    report = CoverageReporter(workspace).build(session)
    savings = report["corpus_quality"]["minimization_savings"]

    assert set(savings) == {"features_retained", "kept", "removable",
                            "reduction_ratio"}
    assert savings["features_retained"] <= \
        report["coverage"]["unique_features"]
    assert savings["kept"] + savings["removable"] == \
        report["corpus_quality"]["inputs"]
    assert 0.0 <= savings["reduction_ratio"] <= 1.0
    assert isinstance(report["corpus_quality"]["hot_inputs"], list)


def test_minimization_savings_on_synthetic_redundant_corpus(workspace):
    """Redundant inputs (same features) are removable; unique ones retained."""
    testcases = [
        {"sha256": "a" * 64, "size": 10, "coverage_features": ["f1", "f2"]},
        {"sha256": "b" * 64, "size": 10, "coverage_features": ["f1"]},
        {"sha256": "c" * 64, "size": 10, "coverage_features": []},
        {"sha256": "d" * 64, "size": 10, "coverage_features": ["f3"]},
    ]
    savings = CoverageReporter._minimization_savings(testcases)
    assert savings["features_retained"] == 3
    assert savings["kept"] == 2          # {f1,f2} and {f3}
    assert savings["removable"] == 2     # duplicate + empty


def test_plateau_tracked_when_measured(workspace, gated_target):
    session = _run_session(workspace, gated_target)
    report = CoverageReporter(workspace).build(session)
    # Adapter present -> plateau counter is live.
    assert report["coverage"]["measured"] is True
    assert report["plateau"]["cases_since_new_feature"] >= 1
    assert report["plateau"]["plateaued"] in (True, False)


# --- black-box honesty ---------------------------------------------------------

class NoAdapterTarget(GatedMagicTarget):
    def coverage_features(self, data, result):
        return None


def test_blackbox_session_reports_no_fabricated_coverage(workspace):
    target_registry_id = "test:no-adapter"
    from ios_research import targets as target_registry
    target_registry.register(target_registry_id, lambda: NoAdapterTarget())
    try:
        session = _run_session(workspace, target_registry_id, max_cases=20)
        report = CoverageReporter(workspace).build(session)
        assert report["coverage"]["measured"] is False
        assert "not fabricated" in report["coverage"]["note"]
        assert report["coverage"]["unique_features"] == 0
        assert report["plateau"]["cases_since_new_feature"] == 0
    finally:
        target_registry._REGISTRY.pop(target_registry_id, None)


# --- comparison ---------------------------------------------------------------

def test_compare_detects_growth_and_regression():
    base = {"session": {"id": "s1"}, "coverage": {"features": ["f1", "f2"],
            "measured": True},
            "corpus_quality": {"inputs": 5}}
    head = {"session": {"id": "s2"}, "coverage": {"features": ["f2", "f3"],
            "measured": True},
            "corpus_quality": {"inputs": 7}}
    out = CoverageReporter.compare(base, head)
    assert out["growth"] == ["f3"]
    assert out["regression"] == ["f1"]
    assert out["delta"] == 0
    assert out["shared"] == 1


def test_compare_two_real_campaigns(workspace, gated_target):
    s1 = _run_session(workspace, gated_target, seed=5, max_cases=30)
    s2 = _run_session(workspace, gated_target, seed=5, max_cases=120)
    r1 = CoverageReporter(workspace).build(s1)
    r2 = CoverageReporter(workspace).build(s2)
    out = CoverageReporter.compare(r1, r2)
    assert out["head_session"] != out["base_session"]
    assert out["delta"] >= 0  # longer deterministic run never loses features


# --- reachability --------------------------------------------------------------

def test_reachability_flags_harness_gaps():
    report = {"session": {"id": "s"},
              "coverage": {"features": ["fn:parse_header", "fn:parse_body"],
                           "measured": True}}
    analysis = CoverageReporter.reachability(
        report, ["fn:parse_header", "fn:parse_body", "fn:decode_huffman"])
    assert analysis["likely_harness_gaps"] == ["fn:decode_huffman"]
    assert analysis["dynamically_reached"] == 2
    assert analysis["reach_ratio"] == round(2 / 3, 4)
    assert analysis["dynamic_unmapped"] == []


def test_reachability_reports_dynamic_unmapped_separately():
    report = {"session": {"id": "s"},
              "coverage": {"features": ["fn:a", "surprise:feature"],
                           "measured": True}}
    analysis = CoverageReporter.reachability(report, ["fn:a"])
    assert analysis["dynamic_unmapped"] == ["surprise:feature"]
    assert analysis["likely_harness_gaps"] == []
    assert analysis["reach_ratio"] == 1.0


# --- markdown / redaction / CLI plumbing ----------------------------------------

def test_markdown_renders_key_sections(workspace, gated_target):
    session = _run_session(workspace, gated_target, max_cases=40)
    md = CoverageReporter.markdown(CoverageReporter(workspace).build(session))
    for section in ("# Coverage report", "## Feature attribution",
                    "## Corpus quality", "## Plateau"):
        assert section in md


def test_report_redacts_secret_shaped_keys():
    from ios_research.bounty import redact_value
    blob = redact_value({"api_key": "hunter2", "nested":
                         {"password": "x", "safe": "y"}})
    assert blob["api_key"] == "***REDACTED***"
    assert blob["nested"]["password"] == "***REDACTED***"
    assert blob["nested"]["safe"] == "y"


def test_from_session_id_unknown_raises(workspace):
    with pytest.raises(NotFoundError):
        CoverageReporter(workspace).from_session_id("fz_missing")


def test_cli_reachability_inventory_validation(workspace):
    import pytest
    from ios_research.context import Context
    from ios_research.commands.report_cmd import cmd_reachability
    from ios_research.errors import ValidationError

    class Args:
        session_id = None
        inventory = "/nonexistent/inventory.json"

    with pytest.raises(ValidationError):
        cmd_reachability(Context(workspace_path=str(workspace.root),
                                 assume_yes=True), Args())
