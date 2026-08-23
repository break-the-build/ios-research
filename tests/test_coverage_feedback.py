"""Coverage feedback remains optional, deterministic, and evidence-preserving."""

from __future__ import annotations

from ios_research import targets
from ios_research.corpus import CorpusStore
from ios_research.coverage import normalize_features
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import DEFAULT_BASE, FuzzEngine
from ios_research.targets.base import ExecResult, Outcome, Target


def _session(workspace, target="mock:parser", cases=80):
    exp = ExperimentStore(workspace).create(
        target=target, device="mock:device", os_version="17.0",
        config_hash="coverage", seed=19)
    store = CorpusStore(workspace)
    corpus = store.create("coverage", target=target)
    store.add_bytes(corpus, DEFAULT_BASE, origin="seed")
    engine = FuzzEngine(workspace)
    return engine, engine.create(experiment_id=exp.id, target=target,
                                 corpus_id=corpus.id, seed=19, workers=1,
                                 max_cases=cases, duration_s=None)


def test_feature_normalization_is_stable_and_rejects_invalid_provider_output():
    assert normalize_features(["z:branch", "a:branch", "z:branch"]) == (
        "a:branch", "z:branch")
    assert normalize_features("not-an-iterable-of-features") is None
    assert normalize_features(["has whitespace"]) is None
    assert normalize_features([1]) is None


def test_coverage_feedback_retains_novel_inputs_with_metadata(workspace):
    engine, session = _session(workspace)
    session = engine.advance(session)
    coverage = session.stats()["coverage"]
    assert coverage["available"] is True
    assert coverage["unique_features"] > 0
    assert coverage["retained_inputs"] > 0
    corpus = engine.corpus_store.get(session.corpus_id)
    retained = [tc for tc in corpus.testcases if tc.get("coverage_new_features")]
    assert retained
    assert all(tc["coverage_features"] for tc in retained)
    assert set(session.coverage_retained_shas) <= corpus.shas


def test_coverage_selection_and_resume_are_deterministic(tmp_path):
    from ios_research import __version__
    from ios_research.workspace import Workspace

    results = []
    for name, split in (("single", None), ("split", 31)):
        ws = Workspace(tmp_path / name / ".ios-research")
        ws.init(framework_version=__version__, created_at="t")
        engine, session = _session(ws, cases=90)
        if split:
            session = engine.advance(session, max_new=split)
            session = engine.resume(session)
        else:
            session = engine.advance(session)
        results.append((session.outcomes, session.coverage_features,
                        session.coverage_retained_shas,
                        session.coverage_selection_counts))
    assert results[0] == results[1]


class _NoCoverageTarget(Target):
    target_id = "test:no-coverage"
    mock = True

    def _run(self, data: bytes) -> ExecResult:
        return ExecResult(outcome=Outcome.ACCEPTED)


def test_target_without_adapter_keeps_deterministic_fallback(workspace):
    targets.register("test:no-coverage", _NoCoverageTarget)
    try:
        engine, session = _session(workspace, target="test:no-coverage", cases=12)
        session = engine.advance(session)
        coverage = session.stats()["coverage"]
        assert coverage["available"] is None
        assert coverage["unique_features"] == 0
        assert coverage["retained_inputs"] == 0
        assert coverage["selection_counts"] == {}
    finally:
        targets._REGISTRY.pop("test:no-coverage", None)


def test_minimize_preserves_each_coverage_feature(workspace):
    store = CorpusStore(workspace)
    corpus = store.create("minimize")
    store.add_bytes(corpus, b"one", origin="seed",
                    coverage_features=["target:shared", "target:one"])
    store.add_bytes(corpus, b"two", origin="seed",
                    coverage_features=["target:shared", "target:two"])
    target = _NoCoverageTarget()
    stats = store.minimize(corpus, target)
    minimized = store.get(corpus.id)
    features = {feature for tc in minimized.testcases
                for feature in tc.get("coverage_features", ())}
    assert stats["coverage_features"] == 3
    assert features == {"target:shared", "target:one", "target:two"}
