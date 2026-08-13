"""Phase 10 integration tests: full CLI verification and artifact chain.

Exercises the commands listed in docs/PROMPT-RUN-ALL.md 'Final Verification'
through the real CLI with --json, and walks the complete artifact chain:

    experiment -> testcase -> crash -> minimized -> analysis -> report
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from ios_research.cli import main
from ios_research.errors import ExitCode


@pytest.fixture
def cli(tmp_path):
    ws = tmp_path / ".ios-research"
    code = main(["init", "--json", "--workspace", str(ws)])
    assert code == ExitCode.OK

    def run(*argv, expect=ExitCode.OK):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main([*argv, "--json", "--workspace", str(ws)])
        payload = json.loads(buf.getvalue())
        if expect is not None:
            assert code == expect, (argv, code, payload)
        assert set(payload) >= {"ok", "command", "data", "exit_code"}
        return payload

    return run


def test_final_verification_commands_all_json(cli):
    # A sweep mirroring the RUN-ALL final verification list.
    cli("doctor")
    cli("info")
    cli("device", "list")
    cli("target", "list")
    cli("target", "audio", "list")
    cli("corpus", "list")
    cli("crash", "list")
    cli("analysis", "list")
    cli("diff", "list")
    cli("report", "list")
    cli("research", "status")
    cli("agent", "status")
    cli("agent", "inspect")


def test_full_artifact_chain(cli):
    # experiment
    exp = cli("experiment", "create", "--target", "mock:parser")
    assert exp["data"]["experiment"]["id"]

    # testcase + crash (via fuzzing)
    fuzz = cli("fuzz", "start", "--target", "mock:parser",
               "--max-cases", "200", "--seed", "1")
    assert fuzz["data"]["stats"]["unique_crashes"] > 0

    crashes = cli("crash", "list")
    assert crashes["data"]["count"] > 0
    crash_id = crashes["data"]["crashes"][0]["id"]

    # reproduce + classify
    repro = cli("crash", "reproduce", crash_id)
    assert repro["data"]["reproduced"] is True
    cli("crash", "classify", crash_id)

    # minimized testcase
    mini = cli("crash", "minimize", crash_id)
    assert mini["data"]["minimized"] is True

    # analysis
    analysis = cli("analyze", crash_id)
    assert analysis["data"]["analysis"]["exploitability_classification"]

    # report tracing back to evidence
    report = cli("report", "create", crash_id)
    assert report["data"]["valid"] is True
    report_id = report["data"]["report_id"]
    shown = cli("report", "show", report_id)
    ev = shown["data"]["report"]["evidence"]
    assert ev["crash_id"] == crash_id
    assert ev["input_sha256"]
    validate = cli("report", "validate", report_id)
    assert validate["data"]["valid"] is True


def test_differential_via_cli(cli):
    created = cli("diff", "create", "--target-a", "mock:parser",
                  "--target-b", "mock:parser-v2")
    diff_id = created["data"]["diff"]["id"]
    run = cli("diff", "run", diff_id)
    assert run["data"]["summary"]["regressions"] >= 1
    report = cli("diff", "report", diff_id)
    assert report["data"]["regression_count"] >= 1


def test_research_run_and_summary_via_cli(cli):
    cli("research", "create", "--target", "mock:parser", "--max-cases", "150")
    run = cli("research", "run", "--yes")
    assert run["data"]["status"] == "completed"
    summary = cli("research", "summarize")
    assert summary["data"]["summary"]["unique_crashes"] > 0


def test_interrupted_fuzz_resumes_via_cli(cli):
    # Start bounded by a chunk (pauses), then resume to completion.
    started = cli("fuzz", "start", "--target", "mock:parser",
                  "--max-cases", "200", "--seed", "2", "--chunk", "50")
    session_id = started["data"]["session"]["id"]
    assert started["data"]["session"]["status"] == "paused"
    resumed = cli("fuzz", "resume", session_id)
    assert resumed["data"]["session"]["status"] == "completed"
    assert resumed["data"]["session"]["cursor"] == 200


def test_unknown_ids_return_not_found(cli):
    cli("crash", "show", "crash_missing", expect=ExitCode.NOT_FOUND)
    cli("report", "show", "rep_missing", expect=ExitCode.NOT_FOUND)
    cli("experiment", "show", "exp_missing", expect=ExitCode.NOT_FOUND)


def test_safety_boundary_is_reported(cli):
    info = cli("info")
    boundary = info["data"]["safety_boundary"]
    assert "weaponized_exploit_chain" in boundary["forbidden"]
    assert "fuzzing" in boundary["allowed"]
