"""Phase 09 tests: research orchestration."""

from __future__ import annotations

import json

from ios_research.cli import main
from ios_research.errors import ExitCode
from ios_research.research import ResearchOrchestrator, STAGES, COMPLETED, PAUSED


def _create(workspace, **kw):
    orch = ResearchOrchestrator(workspace)
    run = orch.create(name=kw.get("name", "r"), target=kw.get("target", "mock:parser"),
                      seed=kw.get("seed", 1), max_cases=kw.get("max_cases", 200),
                      limits=kw.get("limits"))
    return orch, run


def test_full_run_completes_all_stages(workspace):
    orch, run = _create(workspace)
    run = orch.run(run)
    assert run.status == COMPLETED
    assert run.cursor == len(STAGES)
    assert all(s["status"] == "done" for s in run.stages)


def test_run_produces_pipeline_artifacts(workspace):
    orch, run = _create(workspace)
    run = orch.run(run)
    assert run.refs["experiment_id"]
    assert run.refs["fuzz_session_id"]
    assert run.refs["crash_ids"]
    assert run.refs["analysis_ids"]


def test_summary_has_required_fields(workspace):
    orch, run = _create(workspace)
    run = orch.run(run)
    summary = orch.summarize(run)
    for key in ("experiments_performed", "targets_tested", "testcases_generated",
                "crashes_found", "unique_crashes", "reproducible_crashes",
                "minimized_crashes", "potential_memory_safety_issues",
                "differential_findings", "recommended_next_steps"):
        assert key in summary
    assert summary["reproducible_crashes"] == summary["unique_crashes"]


def test_run_is_resumable_and_matches_single_run(tmp_path):
    from ios_research.workspace import Workspace
    from ios_research import __version__

    ws1 = Workspace(tmp_path / "single" / ".ios-research")
    ws1.init(framework_version=__version__, created_at="t")
    o1, r1 = _create(ws1, seed=4, max_cases=180)
    r1 = o1.run(r1)

    ws2 = Workspace(tmp_path / "chunk" / ".ios-research")
    ws2.init(framework_version=__version__, created_at="t")
    o2, r2 = _create(ws2, seed=4, max_cases=180)
    r2 = o2.run(r2, max_stages=4)
    assert r2.status == PAUSED and r2.cursor == 4
    r2 = o2.run(r2, max_stages=4)
    r2 = o2.run(r2)  # finish
    assert r2.status == COMPLETED

    assert o1.summarize(r1) == o2.summarize(r2)


def test_storage_limit_blocks_run(workspace):
    orch, run = _create(workspace, limits={"max_storage_mb": 0.0})
    run = orch.run(run)
    # Blocked at the fuzz stage due to the storage guard.
    assert run.status == "blocked"
    assert run.stages[STAGES.index("fuzz")]["status"] == "blocked"


def test_max_testcases_limit_caps_cases(workspace):
    orch, run = _create(workspace, max_cases=5000, limits={"max_testcases": 50})
    assert run.max_cases == 50


def test_fuzz_stage_records_configured_workers(workspace):
    from ios_research.fuzz import FuzzEngine

    orch, run = _create(workspace)
    run = orch.run(run)
    assert run.status == COMPLETED
    # DEFAULT_LIMITS advertises 8; use sites cap at 6.
    assert run.stats["fuzz_workers"] == 6
    session = FuzzEngine(workspace).get(run.refs["fuzz_session_id"])
    assert session.workers == run.stats["fuzz_workers"]


def test_fuzz_worker_cap_enforced_and_floor_respected(workspace):
    from ios_research.fuzz import FuzzEngine

    orch = ResearchOrchestrator(workspace)

    _, capped = _create(workspace, name="cap", limits={"max_workers": 64})
    capped = orch.run(capped)
    assert capped.status == COMPLETED
    assert capped.stats["fuzz_workers"] == 6
    session = FuzzEngine(workspace).get(capped.refs["fuzz_session_id"])
    assert session.workers == 6

    for name, limits in (("zero", {"max_workers": 0}),
                         ("absent", None)):
        _, run = _create(workspace, name=name, limits=limits)
        if limits is None:
            # Exercise the absent-key path (bypasses create()'s merge).
            run.limits.pop("max_workers")
        run = orch.run(run)
        assert run.status == COMPLETED
        assert run.stats["fuzz_workers"] >= 1


def test_cli_run_requires_confirmation(workspace):
    main(["research", "create", "--target", "mock:parser",
          "--json", "--workspace", str(workspace.root)])
    code = main(["research", "run", "--json", "--workspace", str(workspace.root)])
    assert code == ExitCode.INTERRUPTED


def test_cli_run_with_yes_completes(workspace, capsys):
    main(["research", "create", "--target", "mock:parser", "--max-cases", "150",
          "--json", "--workspace", str(workspace.root)])
    capsys.readouterr()
    code = main(["research", "run", "--yes", "--json",
                 "--workspace", str(workspace.root)])
    payload = json.loads(capsys.readouterr().out)
    assert code == ExitCode.OK
    assert payload["data"]["status"] == "completed"
