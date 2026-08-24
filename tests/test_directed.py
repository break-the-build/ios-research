"""Tests for directed greybox fuzzing (#73): distance computation, power
scheduling hook, CLI wiring and experiment-record integration."""

from __future__ import annotations

import json

import pytest

from ios_research.cli import main
from ios_research.clock import now_iso
from ios_research.corpus import CorpusStore
from ios_research.directed import (
    MIN_ENERGY_WEIGHT,
    UNREACHABLE_DISTANCE,
    CallGraph,
    build_plan,
    energy_weight,
    focus_arguments,
    input_distance,
)
from ios_research.errors import ValidationError
from ios_research.experiment import ExperimentStore
from ios_research.findings import FindingRecord, FindingsStore
from ios_research.fuzz import FuzzEngine, DEFAULT_BASE


def callgraph_doc() -> dict:
    """Small deterministic call graph matching the mock-parser semantics."""
    return {
        "schema": 1,
        "functions": [
            {"name": "parse_record", "file": "parser.c", "line": 10,
             "end_line": 200},
            {"name": "copy_payload", "file": "parser.c", "line": 60,
             "end_line": 85},
            {"name": "read_bytes", "file": "parser.c", "line": 88,
             "end_line": 95},
            {"name": "dispatch_handler", "file": "parser.c", "line": 120,
             "end_line": 140},
            {"name": "accepted_path", "file": "parser.c", "line": 150,
             "end_line": 160},
        ],
        "calls": [
            ["parse_record", "copy_payload"],
            ["copy_payload", "read_bytes"],
            ["parse_record", "dispatch_handler"],
            ["parse_record", "accepted_path"],
        ],
        "feature_functions": {
            "mock-parser:v1:null-dispatch": "dispatch_handler",
            "mock-parser:v1:accepted": "accepted_path",
        },
    }


def write_callgraph(tmp_path, doc=None) -> str:
    path = tmp_path / "callgraph.json"
    path.write_text(json.dumps(doc or callgraph_doc()), encoding="utf-8")
    return str(path)


def add_finding(workspace, fid="fin_dispatch", *, file="parser.c", line=130):
    rec = FindingRecord(
        id=fid, tool="semgrep", rule_id="c.null-deref", cwe="CWE-476",
        severity="error", file_path=file, start_line=line, end_line=line,
        message="handler may be null", status="confirmed", created_at=now_iso())
    FindingsStore(workspace).save(rec)
    return rec


# --- call-graph ingestion -------------------------------------------------------
def test_load_callgraph_rejects_bad_documents(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema": 99, "functions": []}', encoding="utf-8")
    with pytest.raises(ValidationError):
        CallGraph.load(bad)
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(ValidationError):
        CallGraph.load(bad)
    with pytest.raises(ValidationError):
        CallGraph.load(tmp_path / "missing.json")


def test_resolve_location_prefers_exact_then_containment(workspace):
    graph = CallGraph.from_doc(callgraph_doc())
    assert graph.resolve_location("", 0, "read_bytes") == "read_bytes"
    assert graph.resolve_location("src/parser.c", 90) == "read_bytes"
    assert graph.resolve_location("other.c", 1, "zzz_suffix") is None


def test_objectives_from_findings_and_build_plan(workspace):
    add_finding(workspace)
    finding = FindingsStore(workspace).get("fin_dispatch")
    from ios_research.directed import objectives_from_findings
    objectives = objectives_from_findings([finding])
    plan = build_plan(CallGraph.from_doc(callgraph_doc()), objectives)
    assert plan["target_functions"] == ["dispatch_handler"]
    assert plan["reachable_targets"] is True
    assert plan["focus_function"] == "dispatch_handler"
    assert plan["function_distance"]["dispatch_handler"] == 0.0
    assert plan["function_distance"]["parse_record"] == 1.0
    assert plan["function_distance"]["copy_payload"] == 2.0
    assert plan["function_distance"]["read_bytes"] == 3.0
    assert plan["objectives"][0]["id"] == "fin_dispatch"
    assert plan["objectives"][0]["function"] == "dispatch_handler"


# --- distance + energy math -----------------------------------------------------
def test_function_distances_walk_call_edges_in_both_directions():
    graph = CallGraph.from_doc({
        "schema": 1,
        "functions": [{"name": n} for n in ("a", "b", "c", "lonely")],
        "calls": [["a", "b"], ["b", "c"]],
    })
    distances = graph.function_distances(["c"])
    assert distances == {"a": 2.0, "b": 1.0, "c": 0.0,
                         "lonely": UNREACHABLE_DISTANCE}
    reversed_distances = graph.function_distances(["a"])
    assert reversed_distances["c"] == 2.0
    assert reversed_distances["b"] == 1.0


def test_input_distance_is_aflgo_log_mean_over_mapped_features():
    func_dist = {"near": 0.0, "far": 2.0}
    import math
    expected_far = math.log2(3.0)
    assert input_distance(func_dist, ["near"]) == 0.0
    assert input_distance(func_dist, ["near", "far"]) == expected_far / 2
    assert input_distance(func_dist, ["unmapped"]) is None
    assert input_distance(func_dist, []) is None


def test_energy_weight_decays_and_floors_unmapped_inputs():
    assert energy_weight(0.0) == 1.0
    assert 0.0 < energy_weight(4.0) < energy_weight(1.0)
    assert energy_weight(None) == MIN_ENERGY_WEIGHT


def test_feature_function_exact_map_then_longest_substring():
    graph = CallGraph.from_doc(callgraph_doc())
    assert graph.feature_function("mock-parser:v1:null-dispatch") == \
        "dispatch_handler"
    assert graph.feature_function("cov:copy_payload:12") == "copy_payload"
    assert graph.feature_function("mock-parser:v1:reject-header") is None


def test_focus_arguments_only_apply_to_libfuzzer():
    assert focus_arguments("dispatch_handler") == \
        ["-focus_function=dispatch_handler"]
    assert focus_arguments("dispatch_handler", engine="aflpp") == []
    assert focus_arguments("") == []


# --- engine integration ---------------------------------------------------------
def _engine_with_plan(workspace, tmp_path, *, max_cases):
    add_finding(workspace)
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="cfg-directed", seed=5)
    cs = CorpusStore(workspace)
    corpus = cs.create("directed-corpus")
    cs.add_bytes(corpus, DEFAULT_BASE, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(
        experiment_id=exp.id, target="mock:parser", corpus_id=corpus.id,
        seed=5, workers=1, max_cases=max_cases, duration_s=None,
        targets_of_interest=["fin_dispatch"],
        callgraph_path=write_callgraph(tmp_path))
    return engine, session, corpus


def test_engine_create_resolves_directed_plan(workspace, tmp_path):
    _, session, _ = _engine_with_plan(workspace, tmp_path, max_cases=8)
    assert [o["id"] for o in session.directed_objectives] == ["fin_dispatch"]
    assert session.directed_target_functions == ["dispatch_handler"]
    assert session.directed_focus_function == "dispatch_handler"
    assert session.directed_function_distance["dispatch_handler"] == 0.0
    assert session.directed_feature_distance[
        "mock-parser:v1:null-dispatch"] == 0.0
    assert session.directed_feature_distance["mock-parser:v1:accepted"] == 2.0
    persisted = FuzzEngine(workspace).get(session.id)
    assert persisted.directed_target_functions == ["dispatch_handler"]
    stats = persisted.stats()
    assert stats["directed"]["active"] is True
    assert stats["directed"]["engine_args"] == \
        ["-focus_function=dispatch_handler"]
    assert stats["directed"]["scheduled_cases"] == 0


def test_engine_create_without_callgraph_records_inactive_objective(
        workspace):
    add_finding(workspace)
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="cfg-directed-plain", seed=5)
    cs = CorpusStore(workspace)
    corpus = cs.create("directed-plain")
    cs.add_bytes(corpus, DEFAULT_BASE, origin="seed")
    session = FuzzEngine(workspace).create(
        experiment_id=exp.id, target="mock:parser", corpus_id=corpus.id,
        seed=5, workers=1, max_cases=4, duration_s=None,
        targets_of_interest=["fin_dispatch"])
    assert session.directed_objectives
    assert session.directed_target_functions == []
    assert session.stats()["directed"]["active"] is False


def test_unknown_finding_id_raises_not_found(workspace, tmp_path):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="cfg-missing", seed=5)
    cs = CorpusStore(workspace)
    corpus = cs.create("directed-missing")
    from ios_research.errors import NotFoundError
    with pytest.raises(NotFoundError):
        FuzzEngine(workspace).create(
            experiment_id=exp.id, target="mock:parser", corpus_id=corpus.id,
            seed=5, workers=1, max_cases=4, duration_s=None,
            targets_of_interest=["fin_absent"],
            callgraph_path=write_callgraph(tmp_path))


def test_callgraph_without_targets_of_interest_is_a_validation_error(
        workspace):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="cfg-cg-only", seed=5)
    cs = CorpusStore(workspace)
    corpus = cs.create("directed-cg-only")
    with pytest.raises(ValidationError):
        FuzzEngine(workspace).create(
            experiment_id=exp.id, target="mock:parser", corpus_id=corpus.id,
            seed=5, workers=1, max_cases=4, duration_s=None,
            callgraph_path="/unused.json")


def test_directed_schedule_concentrates_energy_on_near_inputs(
        workspace, tmp_path):
    from ios_research.targets import register as register_target
    from ios_research.targets.base import ExecResult, Outcome, Target

    class FixedFeaturesTarget(Target):
        """Stub whose coverage features depend only on the input prefix,
        so the selection pool stays exactly {near, far}."""

        target_id = "test:directed"
        kind = "parser"
        formats = ("raw",)
        mock = True

        def seeds(self):
            return [b"near", b"far"]

        def structure_mutate(self, data, rng):
            return data, "structure_aware"

        def coverage_features(self, data, result):
            if data.startswith(b"near"):
                return ("mock-parser:v1:null-dispatch",)
            return ("mock-parser:v1:accepted",)

        def _run(self, data):
            return ExecResult(outcome=Outcome.ACCEPTED, detail="ok",
                              duration_ms=1)

    register_target("test:directed", lambda: FixedFeaturesTarget())
    try:
        add_finding(workspace)
        exp = ExperimentStore(workspace).create(
            target="test:directed", device="mock:device", os_version="17.0",
            config_hash="cfg-directed-fixed", seed=5)
        cs = CorpusStore(workspace)
        corpus = cs.create("directed-fixed")
        cs.add_bytes(corpus, b"near", origin="seed",
                     coverage_features=["mock-parser:v1:null-dispatch"])
        cs.add_bytes(corpus, b"far", origin="seed",
                     coverage_features=["mock-parser:v1:accepted"])
        engine = FuzzEngine(workspace)
        session = engine.create(
            experiment_id=exp.id, target="test:directed",
            corpus_id=corpus.id, seed=5, workers=1, max_cases=60,
            duration_s=None, targets_of_interest=["fin_dispatch"],
            callgraph_path=write_callgraph(tmp_path))
        session = engine.advance(session)
    finally:
        from ios_research.targets import _REGISTRY
        _REGISTRY.pop("test:directed", None)

    assert session.status == "completed"
    # Coverage is available from the first executed case on.
    assert session.directed_scheduled_cases == session.max_cases - 1
    counts = session.coverage_selection_counts
    entries = {tc["sha256"]: tc for tc in cs.get(corpus.id).testcases}
    near_sha = next(s for s in entries if cs.read_bytes(corpus, s) == b"near")
    far_sha = next(s for s in entries if cs.read_bytes(corpus, s) == b"far")
    # near sits on the objective (weight 1.0), far two calls away
    # (weight 2**-log2(3) ~ 0.33): smooth fair scheduling gives near at least
    # twice the selections.
    assert counts[near_sha] > counts[far_sha]
    assert counts[near_sha] >= 2 * counts[far_sha]


# --- CLI surface ----------------------------------------------------------------
def test_cli_fuzz_start_directed_roundtrip(workspace, tmp_path, capsys):
    add_finding(workspace)
    ws = str(workspace.root)
    rc = main(["fuzz", "start", "--target", "mock:parser",
               "--targets-of-interest", "fin_dispatch",
               "--callgraph", write_callgraph(tmp_path),
               "--max-cases", "6", "--seed", "3", "--json",
               "--workspace", ws])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    directed = payload["data"]["stats"]["directed"]
    assert directed["active"] is True
    assert directed["target_functions"] == ["dispatch_handler"]
    assert directed["focus_function"] == "dispatch_handler"
    experiment = ExperimentStore(workspace).get(
        payload["data"]["experiment_id"])
    stored = experiment.params["directed"]
    assert stored["targets_of_interest"] == ["fin_dispatch"]
    assert stored["objectives"][0]["function"] == "dispatch_handler"
    assert stored["callgraph"].endswith("callgraph.json")


def test_cli_fuzz_start_targets_without_callgraph_still_records(
        workspace, capsys):
    add_finding(workspace)
    ws = str(workspace.root)
    rc = main(["fuzz", "start", "--target", "mock:parser",
               "--targets-of-interest", " fin_dispatch ",
               "--max-cases", "3", "--seed", "3", "--json",
               "--workspace", ws])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    directed = payload["data"]["stats"]["directed"]
    assert directed["active"] is False
    assert directed["objectives"][0]["id"] == "fin_dispatch"


def test_cli_fuzz_start_unknown_finding_exit_code(workspace, tmp_path,
                                                  capsys):
    ws = str(workspace.root)
    rc = main(["fuzz", "start", "--target", "mock:parser",
               "--targets-of-interest", "fin_absent",
               "--callgraph", write_callgraph(tmp_path),
               "--max-cases", "2", "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 3  # NOT_FOUND
    assert payload["ok"] is False
    assert "fin_absent" in payload["error"]


def test_cli_fuzz_start_callgraph_requires_targets(workspace, tmp_path,
                                                   capsys):
    ws = str(workspace.root)
    rc = main(["fuzz", "start", "--target", "mock:parser",
               "--callgraph", write_callgraph(tmp_path),
               "--max-cases", "2", "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 4  # VALIDATION
    assert payload["ok"] is False
    assert "targets-of-interest" in payload["error"]


def test_cli_fuzz_start_empty_targets_list_exit_code(workspace, capsys):
    ws = str(workspace.root)
    rc = main(["fuzz", "start", "--target", "mock:parser",
               "--targets-of-interest", ", ,", "--max-cases", "2",
               "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 2  # USAGE
    assert payload["ok"] is False
