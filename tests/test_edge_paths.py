"""Coverage for error-handling and control-flow edge paths (goals 01/18)."""

from __future__ import annotations

import json

import pytest

from ios_research.context import Context
from ios_research.errors import NotFoundError, StateError, UsageError
from ios_research.corpus import CorpusStore
from ios_research.crashes import CrashStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import (
    FuzzEngine, DEFAULT_BASE, COMPLETED, PAUSED, STOPPED,
)
from ios_research.report import ReportGenerator
from ios_research.targets import create
from ios_research.targets.base import Outcome


# --- context --------------------------------------------------------------
def test_context_required_workspace_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ctx = Context()
    with pytest.raises(NotFoundError):
        ctx.workspace(required=True)


def test_context_workspace_path_uninitialized(tmp_path):
    ctx = Context(workspace_path=str(tmp_path / "nope"))
    with pytest.raises(NotFoundError):
        ctx.workspace(required=True)


def test_context_config_reads_workspace_file(workspace):
    workspace.write_json("config/config.json", {"fuzz": {"workers": 9}})
    ctx = Context(workspace_path=str(workspace.root))
    assert ctx.config().get("fuzz.workers") == 9


def test_context_confirm_follows_assume_yes(workspace):
    assert Context(workspace_path=str(workspace.root), assume_yes=True).confirm("x")
    assert not Context(workspace_path=str(workspace.root)).confirm("x")


# --- report export / validate edge paths ---------------------------------
def _crash(workspace):
    store = CrashStore(workspace)
    data = b"MOCK\x01\x01\xff\xff" + b"A" * 20
    res = create("mock:parser").execute(data)
    return store.record(experiment_id="e1", target="mock:parser",
                        fmt="mock-record", data=data, exec_result=res)


def test_report_export_json_and_markdown(workspace):
    gen = ReportGenerator(workspace)
    report = gen.create(_crash(workspace).id)
    js = gen.export(report, "json")
    assert json.loads(js)["crash_id"] == report.crash_id
    assert gen.export(report, "markdown").startswith("#")


def test_report_export_unknown_format(workspace):
    gen = ReportGenerator(workspace)
    report = gen.create(_crash(workspace).id)
    with pytest.raises(UsageError):
        gen.export(report, "pdf")


def test_report_get_missing(workspace):
    with pytest.raises(NotFoundError):
        ReportGenerator(workspace).get("rep_missing")


def test_report_validate_flags_missing_input_artifact(workspace):
    gen = ReportGenerator(workspace)
    report = gen.create(_crash(workspace).id)
    report.evidence["input_sha256"] = "deadbeef" * 8  # nonexistent artifact
    result = gen.validate(report)
    assert result["valid"] is False
    assert any("artifact" in i for i in result["issues"])


# --- fuzz control transitions --------------------------------------------
def _session(workspace, max_cases=120):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="c", seed=1)
    cs = CorpusStore(workspace)
    corpus = cs.create("f")
    cs.add_bytes(corpus, DEFAULT_BASE, origin="seed")
    engine = FuzzEngine(workspace)
    return engine, engine.create(
        experiment_id=exp.id, target="mock:parser", corpus_id=corpus.id,
        seed=1, workers=1, max_cases=max_cases, duration_s=None)


def test_fuzz_pause_and_stop(workspace):
    engine, session = _session(workspace)
    engine.pause(session)
    assert engine.get(session.id).status == PAUSED
    engine.stop(session)
    assert engine.get(session.id).status == STOPPED


def test_fuzz_resume_after_stop_raises(workspace):
    engine, session = _session(workspace)
    engine.stop(session)
    with pytest.raises(StateError):
        engine.resume(session)


def test_fuzz_resume_after_complete_raises(workspace):
    engine, session = _session(workspace)
    session = engine.advance(session)
    assert session.status == COMPLETED
    with pytest.raises(StateError):
        engine.resume(session)


def test_fuzz_latest_and_list(workspace):
    engine, session = _session(workspace)
    engine.advance(session)
    assert engine.latest().id == session.id
    assert len(engine.list()) == 1


def test_fuzz_get_missing(workspace):
    engine = FuzzEngine(workspace)
    with pytest.raises(NotFoundError):
        engine.get("fz_missing")


def test_advance_on_stopped_is_noop(workspace):
    engine, session = _session(workspace)
    engine.stop(session)
    session = engine.get(session.id)
    result = engine.advance(session)
    assert result.status == STOPPED and result.cursor == 0
