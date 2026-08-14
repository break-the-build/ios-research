"""CLI-handler coverage for the command modules (goal 01).

Exercises command handlers through the real CLI (`main` with `--json`), which
are otherwise only tested at the engine level.
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from ios_research.cli import main
from ios_research.errors import ExitCode


@pytest.fixture
def run(tmp_path):
    ws = tmp_path / ".ios-research"
    main(["init", "--json", "--workspace", str(ws)])

    def _run(*argv, expect=ExitCode.OK):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main([*argv, "--json", "--workspace", str(ws), "--yes"])
        payload = json.loads(buf.getvalue())
        if expect is not None:
            assert code == expect, (argv, code, payload)
        return payload

    return _run


# --- corpus ---------------------------------------------------------------
def test_corpus_handlers(run):
    created = run("corpus", "create", "mycorpus", "--seed-default")
    cid = created["data"]["corpus"]["id"]
    run("corpus", "list")
    inspected = run("corpus", "inspect", cid)
    assert inspected["data"]["size"] >= 1
    run("corpus", "dedupe", cid)
    minimized = run("corpus", "minimize", cid, "--target", "mock:parser")
    assert "kept" in minimized["data"]


def test_corpus_import(run, tmp_path):
    d = tmp_path / "seeds"
    d.mkdir()
    (d / "a.bin").write_bytes(b"MOCK\x01\x01\x00\x02ok")
    created = run("corpus", "create", "imp")
    cid = created["data"]["corpus"]["id"]
    imported = run("corpus", "import", cid, str(d))
    assert imported["data"]["added"] == 1


# --- audio ----------------------------------------------------------------
def test_audio_handlers(run):
    listed = run("target", "audio", "list")
    assert listed["data"]["count"] == 4
    inspected = run("target", "audio", "inspect", "wav")
    assert inspected["data"]["target"]["id"] == "audio:wav"
    run("target", "audio", "inspect", "nope", expect=ExitCode.NOT_FOUND)


# --- agent ----------------------------------------------------------------
def test_agent_handlers(run, tmp_path):
    run("agent", "status")
    run("agent", "inspect")
    exp = run("agent", "experiment", "--target", "mock:parser")
    assert exp["data"]["experiment"]["id"]
    schema = run("agent", "schema", "--out", str(tmp_path / "s.json"))
    assert schema["data"]["commands"] >= 1
    ran = run("agent", "run", "--target", "mock:parser", "--max-cases", "150")
    assert ran["data"]["unique_crashes"] > 0
    run("agent", "analyze")


def test_agent_run_unknown_target(run):
    run("agent", "run", "--target", "bogus:x", expect=ExitCode.USAGE)


# --- research -------------------------------------------------------------
def test_research_handlers(run):
    created = run("research", "create", "--target", "mock:parser",
                  "--max-cases", "120")
    rid = created["data"]["research"]["id"]
    run("research", "status", rid)
    # pause a freshly-created run, then run it to completion
    run("research", "pause", rid)
    done = run("research", "run", rid)
    assert done["data"]["status"] == "completed"
    summary = run("research", "summarize", rid)
    assert summary["data"]["summary"]["unique_crashes"] >= 0


def test_research_run_partial_then_resume(run):
    run("research", "create", "--target", "mock:parser", "--max-cases", "120")
    partial = run("research", "run", "--max-stages", "3")
    assert partial["data"]["status"] == "paused"
    resumed = run("research", "resume")
    assert resumed["data"]["status"] in ("paused", "completed")


# --- diff / report extra paths -------------------------------------------
def test_diff_and_report_list_handlers(run):
    run("diff", "list")
    run("report", "list")
    created = run("diff", "create", "--target-a", "mock:parser",
                  "--target-b", "mock:parser-v2")
    did = created["data"]["diff"]["id"]
    run("diff", "run", did)
    run("diff", "compare", did)
    run("diff", "report", did)


# --- fuzz control + crash + analyze + report CLI paths -------------------
def _first_crash(run):
    run("fuzz", "start", "--target", "mock:parser", "--max-cases", "200",
        "--seed", "1")
    crashes = run("crash", "list")
    return crashes["data"]["crashes"][0]["id"]


def test_fuzz_control_commands(run):
    started = run("fuzz", "start", "--target", "mock:parser",
                  "--max-cases", "200", "--seed", "2", "--chunk", "50")
    sid = started["data"]["session"]["id"]
    assert started["data"]["session"]["status"] == "paused"
    run("fuzz", "stats", sid)
    run("fuzz", "pause", sid)
    resumed = run("fuzz", "resume", sid)
    assert resumed["data"]["session"]["status"] == "completed"
    run("fuzz", "stop", sid)


def test_crash_and_analyze_handlers(run):
    cid = _first_crash(run)
    run("crash", "show", cid)
    run("crash", "reproduce", cid)
    run("crash", "classify", cid)
    run("crash", "minimize", cid)
    analyzed = run("analyze", cid)
    aid = analyzed["data"]["analysis"]["id"]
    shown = run("analysis", "show", aid)
    assert shown["data"]["analysis"]["id"] == aid


def test_crash_compare_handler(run):
    run("fuzz", "start", "--target", "mock:parser", "--max-cases", "250",
        "--seed", "3")
    crashes = run("crash", "list")["data"]["crashes"]
    if len(crashes) >= 2:
        cmp = run("crash", "compare", crashes[0]["id"], crashes[1]["id"])
        assert "same_signature" in cmp["data"]


def test_report_export_handler(run, tmp_path):
    cid = _first_crash(run)
    run("report", "create", cid)
    reports = run("report", "list")["data"]["reports"]
    rid = reports[0]["id"]
    run("report", "show", rid)
    run("report", "validate", rid)
    exported = run("report", "export", rid, "--format", "json",
                   "--out", str(tmp_path / "r.json"))
    assert exported["data"]["format"] == "json"
    inline = run("report", "export", rid, "--format", "markdown")
    assert "content" in inline["data"]


# --- config edge paths ----------------------------------------------------
def test_config_get_unknown_key(run):
    run("config", "get", "no.such.key", expect=ExitCode.USAGE)
