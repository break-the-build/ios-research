"""Phase 05 tests: root-cause and exploitability analysis."""

from __future__ import annotations

from ios_research.analysis import (
    Analyzer, CRASH_ONLY, CONTROLLED_MEMORY_ACCESS_INDICATOR,
    CODE_EXECUTION_INDICATOR, MEDIUM, LOW,
)
from ios_research.crashes import CrashStore
from ios_research.targets import create
from ios_research.targets.base import Outcome


def _record(workspace, data, target="mock:parser", experiment_id="exp1"):
    store = CrashStore(workspace)
    res = create(target).execute(data)
    assert res.outcome == Outcome.CRASH
    return store.record(experiment_id=experiment_id, target=target,
                        fmt="mock-record", data=data, exec_result=res)


def test_oob_read_yields_controlled_access_indicator(workspace):
    crash = _record(workspace, b"MOCK\x01\x01\xff\xff")
    analysis = Analyzer(workspace).analyze(crash)
    assert analysis.exploitability_classification == \
        CONTROLLED_MEMORY_ACCESS_INDICATOR
    assert analysis.confidence == MEDIUM
    assert analysis.memory_safety_classification == "spatial"
    assert analysis.reproducibility == "reproducible"


def test_null_deref_is_crash_only(workspace):
    crash = _record(workspace, b"MOCK\x01\xff\x00\x00")
    analysis = Analyzer(workspace).analyze(crash)
    assert analysis.exploitability_classification == CRASH_ONLY
    assert analysis.confidence == LOW


def test_analysis_requires_evidence_and_never_claims_code_exec(workspace):
    # No mock crash should ever yield a code-execution indicator.
    for data in (b"MOCK\x01\x01\xff\xff", b"MOCK\x01\xff\x00\x00",
                 b"MOCK\x01\x01\x00\x02\xde\xad"):
        crash = _record(workspace, data, experiment_id=data.hex())
        analysis = Analyzer(workspace).analyze(crash)
        assert analysis.exploitability_classification != CODE_EXECUTION_INDICATOR
        assert analysis.exploitability_evidence  # evidence is always recorded
        assert "input_attacker_controlled=true" in analysis.exploitability_evidence


def test_analysis_is_persisted_and_backlinked(workspace):
    crash = _record(workspace, b"MOCK\x01\x01\xff\xff")
    analysis = Analyzer(workspace).analyze(crash)
    # backlink on crash
    assert CrashStore(workspace).get(crash.id).analysis_id == analysis.id
    # retrievable from store
    assert Analyzer(workspace).get(analysis.id).id == analysis.id


def test_analyze_batch_covers_all_crashes(workspace):
    _record(workspace, b"MOCK\x01\x01\xff\xff", experiment_id="e1")
    _record(workspace, b"MOCK\x01\xff\x00\x00", experiment_id="e2")
    analyses = Analyzer(workspace).analyze_batch()
    assert len(analyses) == 2


def test_list_ignores_foreign_record_kinds_in_analysis_dir(workspace):
    # regression: analysis/ is a shared directory (novelty scans, surface
    # plans, ...). Foreign records must not break or pollute list().
    crash = _record(workspace, b"MOCK\x01\x01\xff\xff")
    Analyzer(workspace).analyze(crash)
    workspace.write_json("analysis/nov_54d2e50f1158.json",
                         {"id": "nov_54d2e50f1158", "kind": "novelty-scan",
                          "created_at": "2026-08-23T00:00:00Z",
                          "advisories_loaded": 3})
    workspace.write_json("analysis/sur_c3527d620553.json",
                         {"id": "sur_c3527d620553", "kind": "surface-plan",
                          "created_at": "2026-08-23T00:00:00Z"})
    analyses = Analyzer(workspace).list()
    assert len(analyses) == 1
    assert analyses[0].crash_id == crash.id


def test_uaf_has_reallocation_question(workspace):
    crash = _record(workspace, b"MOCK\x01\x01\x00\x02\xde\xad")
    analysis = Analyzer(workspace).analyze(crash)
    assert any("realloc" in q.lower() for q in analysis.exploitability_questions)
