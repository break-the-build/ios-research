"""Device/OS/build matrix reproduction with reliability scoring (#37)."""

from __future__ import annotations

import pytest

from ios_research import targets as target_registry
from ios_research.errors import NotFoundError, ValidationError
from ios_research.matrix import (MatrixCell, ReproductionMatrixEngine,
                                 parse_cells)
from ios_research.targets.base import Diagnostics, ExecResult, Outcome, Target

CRASHING_INPUT = b"MOCK\x01\xff\x00\x00"   # mock:parser null-dispatch crash


def _cells(*versions):
    return [
        {"device_id": "mock:device", "model": "MockPhone15,1",
         "os_name": "MockOS", "os_version": version, "build": f"21{v}01"}
        for v, version in enumerate(versions or ("17.0",), start=1)
    ]


# --- cell validation -----------------------------------------------------------

def test_missing_provenance_fails_validation():
    for field in ("device_id", "model", "os_name", "os_version", "build"):
        spec = _cells("17.0")[0]
        spec.pop(field)
        with pytest.raises(ValidationError) as exc:
            parse_cells([spec])
        assert field in str(exc.value)


def test_unknown_fields_rejected_and_duplicates_dropped():
    bad = _cells("17.0")[0] | {"jailbroken": True}
    with pytest.raises(ValidationError):
        parse_cells([bad])
    dupes = _cells("17.0") + [_cells("17.0")[0]]
    assert len(parse_cells(dupes)) == 1
    with pytest.raises(ValidationError):
        parse_cells([])


def test_lockdown_and_beta_recorded_as_evidence_only():
    cells = parse_cells([_cells("17.1")[0] | {
        "lockdown_mode": True, "beta": False}])
    assert cells[0].lockdown_mode is True
    assert cells[0].beta is False


# --- deterministic reproduction --------------------------------------------------

def test_stable_crash_scores_full_reliability(workspace):
    engine = ReproductionMatrixEngine(workspace)
    run = engine.create(target="mock:parser", input_bytes=CRASHING_INPUT,
                        trials=5, seed=0, cells=_cells("17.0"))
    summary = engine.run(run)
    cell = summary["per_cell"][0]
    assert cell["reproduction_rate"] == 1.0
    assert cell["signature_stability"] == 1.0
    assert cell["stable"] is True
    assert cell["crashes"] == 5
    assert summary["reproducible_cells"] == 1


class FlakyTarget(Target):
    """Crashes on every second execution — an unstable finding."""

    target_id = "test:flaky"
    kind = "mock-parser"
    description = "alternating crash/accept for reliability tests"
    _calls = 0

    def _run(self, data: bytes) -> ExecResult:
        FlakyTarget._calls += 1
        if FlakyTarget._calls % 2 == 1:
            return ExecResult(
                outcome=Outcome.CRASH,
                diagnostics=Diagnostics(signature="sig_flaky",
                                        classification_hint="UNKNOWN"))
        return ExecResult(outcome=Outcome.ACCEPTED)


@pytest.fixture()
def flaky_target():
    FlakyTarget._calls = 0
    target_registry.register("test:flaky", lambda: FlakyTarget())
    yield "test:flaky"
    target_registry._REGISTRY.pop("test:flaky", None)


def test_flaky_finding_is_flagged_not_promoted(workspace, flaky_target):
    engine = ReproductionMatrixEngine(workspace)
    run = engine.create(target=flaky_target, input_bytes=b"anything",
                        trials=6, seed=0, cells=_cells("17.0"))
    summary = engine.run(run)
    cell = summary["per_cell"][0]
    assert cell["reproduction_rate"] == pytest.approx(0.5)
    assert cell["stable"] is False
    # Unstable findings are counted separately from reproducible ones.
    assert summary["one_off_cells"] == 1
    assert summary["reproducible_cells"] == 0


def test_non_crashing_input_scores_zero(workspace):
    engine = ReproductionMatrixEngine(workspace)
    run = engine.create(target="mock:parser", input_bytes=b"MOCK\x01\x01\x00\x02ok",
                        trials=3, seed=0, cells=_cells("17.0"))
    summary = engine.run(run)
    assert summary["non_reproducing_cells"] == 1
    assert summary["per_cell"][0]["time_to_crash_ms"] is None


# --- affected versions / no inference ---------------------------------------------

def test_first_last_affected_across_tested_versions_only(workspace):
    engine = ReproductionMatrixEngine(workspace)
    run = engine.create(target="mock:parser", input_bytes=CRASHING_INPUT,
                        trials=2, seed=0,
                        cells=_cells("16.4", "17.0", "17.4"))
    summary = engine.run(run)
    affected = summary["affected_versions"]
    assert [v["os_version"] for v in affected["tested_versions"]] == \
        ["16.4", "17.0", "17.4"]
    assert affected["first_affected"] == "16.4"
    assert affected["last_affected"] == "17.4"
    assert any("untested" in note for note in summary["limitations"])


def test_unaffected_version_excluded_from_range(workspace):
    class FixedTarget(FlakyTarget):
        target_id = "test:fixed"
        _calls = 0

        def _run(self, data):
            return ExecResult(outcome=Outcome.ACCEPTED)

    target_registry.register("test:fixed", lambda: FixedTarget())
    try:
        crashing = ReproductionMatrixEngine(workspace)
        run = crashing.create(
            target="mock:parser", input_bytes=CRASHING_INPUT, trials=2,
            seed=0, cells=_cells("16.4"))
        summary = crashing.run(run)
        assert summary["affected_versions"]["first_affected"] == "16.4"
    finally:
        target_registry._REGISTRY.pop("test:fixed", None)


# --- persistence / bounds -----------------------------------------------------------

def test_matrix_persists_input_and_round_trips(workspace):
    engine = ReproductionMatrixEngine(workspace)
    run = engine.create(target="mock:parser", input_bytes=CRASHING_INPUT,
                        trials=2, seed=0, cells=_cells("17.0"))
    loaded = engine.get(run.id)
    assert loaded.target == "mock:parser"
    assert workspace.path(f"matrices/{run.id}/input.bin").read_bytes() == \
        CRASHING_INPUT
    engine.run(engine.get(run.id))
    results = engine.results(run.id)
    assert results["schema_version"] == 1
    with pytest.raises(NotFoundError):
        engine.results("mtx_missing")


def test_trials_bounded_and_unknown_target_rejected(workspace):
    engine = ReproductionMatrixEngine(workspace)
    with pytest.raises(ValidationError):
        engine.create(target="mock:parser", input_bytes=b"x", trials=101,
                      seed=0, cells=_cells("17.0"))
    with pytest.raises(NotFoundError):
        engine.create(target="nope:not-here", input_bytes=b"x", trials=2,
                      seed=0, cells=_cells("17.0"))


def test_cell_key_is_canonical_and_stable():
    a = MatrixCell(device_id="d", model="m", os_name="o", os_version="1",
                   build="b")
    b = MatrixCell(device_id="d", model="m", os_name="o", os_version="1",
                   build="b", lockdown_mode=True)
    assert a.key != b.key          # configuration changes identity
    assert MatrixCell(device_id="d", model="m", os_name="o", os_version="1",
                      build="b").key == a.key
