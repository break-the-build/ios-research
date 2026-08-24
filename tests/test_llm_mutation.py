"""Tests for LLM-in-the-loop proposal mutation (#71)."""

from __future__ import annotations

import json

import pytest

from ios_research import targets as tgt
from ios_research.cli import main
from ios_research.corpus import CorpusStore
from ios_research.crashes import CrashStore
from ios_research.errors import NotFoundError, StateError, UsageError
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine
from ios_research.llmmutate import (
    FileProposalSource, Proposal, empty_stats, repair_with_target,
    summarize_round, validate_proposal_bytes,
)
from ios_research.targets.base import Outcome

# mock:parser crasher: declared length 0xFFFF > payload -> OOB read.
CRASHER_HEX = "4d4f434b0101ffff" + "41414141".lower()
VALID_HEX = "4d4f434b01010004" + "6f6b6f6b"          # clean MOCK record
JUNK_HEX = "00" * 8                                   # rejected by parser


def _write_proposals(tmp_path, entries, name="props.jsonl"):
    path = tmp_path / name
    lines = [json.dumps(e) for e in entries]
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def _campaign(ctx, tmp_path, *, entries=None, budget=None, max_new=6,
              target="mock:parser"):
    entries = entries if entries is not None else [
        {"input_hex": VALID_HEX, "note": "clean"},
        {"input_hex": CRASHER_HEX, "note": "should crash"},
        {"input_hex": JUNK_HEX, "note": "rejected"},
    ]
    path = _write_proposals(tmp_path, entries)
    corpus = CorpusStore(ctx.workspace()).create("llm-corpus",
                                                 target=target)
    for seed in tgt.create(target).seeds():
        CorpusStore(ctx.workspace()).add_bytes(corpus, seed, origin="seed")
    experiment = ExperimentStore(ctx.workspace()).create(
        target=target, device="dev", os_version="1", config_hash="h",
        seed=7, params={})
    engine = FuzzEngine(ctx.workspace())
    session = engine.create(
        experiment_id=experiment.id, target=target, corpus_id=corpus.id,
        seed=7, workers=1, max_cases=100, duration_s=None,
        llm_proposal_file=path, llm_budget=budget if budget is not None
        else len(entries))
    session = engine.advance(session, max_new=max_new)
    return engine, session, path


# --- proposal source -----------------------------------------------------------
def test_file_proposal_source_parses_and_counts():
    import tempfile, os
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "p.jsonl")
    with open(path, "w") as fh:
        fh.write('{"input_hex": "deadbeef", "note": "n1"}\n')
        fh.write("not json\n")
        fh.write('{"note": "missing hex"}\n')
        fh.write('{"input_hex": "zzzz"}\n')
        fh.write("\n")
        fh.write('{"input_hex": "00ff"}\n')
    src = FileProposalSource(path)
    seen = list(src.proposals_from(0))
    valid = [p for _, p in seen if p is not None]
    invalid = [1 for _, p in seen if p is None]
    assert len(valid) == 2 and len(invalid) == 4
    assert valid[0].data == b"\xde\xad\xbe\xef"
    assert valid[-1].next_line == 6


def test_file_proposal_source_resume_cursor():
    import tempfile, os
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "p.jsonl")
    with open(path, "w") as fh:
        fh.write('{"input_hex": "aa"}\n{"input_hex": "bb"}\n'
                 '{"input_hex": "cc"}\n')
    src = FileProposalSource(path)
    rest = [p for _, p in src.proposals_from(1)]
    assert [p.data for p in rest] == [b"\xbb", b"\xcc"]


def test_file_proposal_source_missing_file():
    with pytest.raises(NotFoundError):
        FileProposalSource("/nonexistent/proposals.jsonl")


def test_proposal_bad_hex_raises_on_access():
    prop = Proposal(input_hex="nothex")
    with pytest.raises(ValueError):
        prop.data


# --- validation / repair ---------------------------------------------------------
def test_validate_proposal_bytes_bounds():
    assert validate_proposal_bytes(b"") is None
    assert validate_proposal_bytes(b"x" * 10) == b"x" * 10
    assert validate_proposal_bytes(b"x" * 3, max_bytes=2) is None


def test_repair_with_target_hook_variants():
    class Repairing:
        def repair(self, data):
            return b"repaired"

    class Broken:
        def repair(self, data):
            raise RuntimeError("boom")

    class Plain:
        pass

    assert repair_with_target(b"raw", Repairing()) == b"repaired"
    assert repair_with_target(b"raw", Broken()) == b"raw"
    assert repair_with_target(b"raw", Plain()) == b"raw"
    # Base-class hook is identity.
    assert tgt.create("mock:parser").repair(b"abc") == b"abc"


# --- stats helpers -----------------------------------------------------------------
def test_empty_stats_and_round_summary():
    stats = empty_stats()
    assert stats["proposals_used"] == 0 and stats["rounds"] == []
    summary = summarize_round(3, ["sig_b", "sig_a"])
    assert summary == {"round": 3, "new_crashes": ["sig_a", "sig_b"]}


# --- engine integration --------------------------------------------------------------
def test_engine_consumes_proposals_and_records_llm_crash(ctx, tmp_path):
    engine, session, _ = _campaign(ctx, tmp_path)
    stats = session.llm_stats
    assert stats["proposals_used"] == 3
    assert session.llm_cursor >= 3          # raw cursor advanced
    assert session.llm_round == 1
    # The crasher proposal produced a real crash with llm lineage.
    assert session.crashes >= 1
    store = CrashStore(ctx.workspace())
    llm_crashes = [c for c in store.list(experiment_id=session.experiment_id)
                   if c.lineage.get("origin") == "llm-proposal"]
    assert llm_crashes, "crashing proposal must carry llm lineage"
    assert llm_crashes[0].lineage["round"] == 1
    assert llm_crashes[0].lineage["note"] == "should crash"
    assert llm_crashes[0].lineage["mutation"] == "llm-proposal"
    # Round feedback captured the new signature.
    assert stats["rounds"], "new crashes must append a round summary"
    assert stats["rounds"][0]["round"] == 1
    assert len(stats["rounds"][0]["new_crashes"]) >= 1


def test_engine_budget_bounds_proposal_use(ctx, tmp_path):
    engine, session, _ = _campaign(ctx, tmp_path, budget=2, max_new=8)
    stats = session.llm_stats
    assert stats["proposals_used"] == 2
    assert stats["fallback_iterations"] >= 1  # rest of run mutates normally
    assert session.outcomes.get(Outcome.ACCEPTED, 0) + \
        session.outcomes.get(Outcome.REJECTED, 0) + \
        session.outcomes.get(Outcome.CRASH, 0) >= 3


def test_engine_determinism_same_inputs(ctx, tmp_path):
    _, s1, _ = _campaign(ctx, tmp_path)
    # Fresh workspace state for a second identical run.
    import tempfile
    from ios_research.context import Context
    from ios_research.workspace import Workspace
    from ios_research import __version__
    from ios_research.clock import now_iso
    ws2 = Workspace(tmp_path / "second" / ".ios-research")
    ws2.init(framework_version=__version__, created_at=now_iso())
    ctx2 = Context(workspace_path=str(ws2.root), assume_yes=True)
    _, s2, _ = _campaign(ctx2, tmp_path)
    assert s1.llm_stats == s2.llm_stats
    assert s1.outcomes == s2.outcomes


def test_engine_resume_continues_stream(ctx, tmp_path):
    engine, session, _ = _campaign(ctx, tmp_path, max_new=2, budget=3)
    assert session.llm_stats["proposals_used"] == 2
    assert session.status == "paused"
    resumed = engine.resume(session, max_new=4)
    # Third proposal consumed after resume; no re-consumption of old lines.
    assert resumed.llm_stats["proposals_used"] == 3
    assert resumed.llm_stats["fallback_iterations"] >= 1


def test_session_without_llm_flags_untouched(ctx, tmp_path):
    corpus = CorpusStore(ctx.workspace()).create("plain", target="mock:parser")
    for seed in tgt.create("mock:parser").seeds():
        CorpusStore(ctx.workspace()).add_bytes(corpus, seed, origin="seed")
    experiment = ExperimentStore(ctx.workspace()).create(
        target="mock:parser", device="dev", os_version="1", config_hash="h",
        seed=1, params={})
    engine = FuzzEngine(ctx.workspace())
    session = engine.create(experiment_id=experiment.id,
                            target="mock:parser", corpus_id=corpus.id,
                            seed=1, workers=1, max_cases=10, duration_s=None)
    assert session.llm_proposal_file == "" and session.llm_budget == 0
    assert session.llm_stats == {}
    out = engine.advance(session, max_new=5)
    assert out.llm_stats == {} and out.cursor == 5


def test_create_rejects_mismatched_llm_args(ctx, tmp_path):
    corpus = CorpusStore(ctx.workspace()).create("c2", target="mock:parser")
    experiment = ExperimentStore(ctx.workspace()).create(
        target="mock:parser", device="dev", os_version="1", config_hash="h",
        seed=1, params={})
    engine = FuzzEngine(ctx.workspace())
    with pytest.raises(StateError):
        engine.create(experiment_id=experiment.id, target="mock:parser",
                      corpus_id=corpus.id, seed=1, workers=1, max_cases=5,
                      duration_s=None, llm_proposal_file="/tmp/x.jsonl",
                      llm_budget=0)
    with pytest.raises(StateError):
        engine.create(experiment_id=experiment.id, target="mock:parser",
                      corpus_id=corpus.id, seed=1, workers=1, max_cases=5,
                      duration_s=None, llm_budget=5)


# --- CLI surface -----------------------------------------------------------------------
def test_cli_fuzz_start_llm_flags_roundtrip(ctx, tmp_path, capsys):
    path = _write_proposals(tmp_path, [{"input_hex": VALID_HEX}])
    rc = main(["fuzz", "start", "--target", "mock:parser",
               "--llm-proposals", path, "--llm-budget", "1",
               "--max-cases", "5", "--json",
               "--workspace", str(ctx.workspace().root)])
    envelope = json.loads(capsys.readouterr().out.strip())
    assert rc == 0, envelope
    stats = envelope["data"]["session"]["llm_stats"]
    assert stats["proposals_used"] == 1


def test_cli_fuzz_start_llm_flags_require_each_other(ctx, capsys):
    rc = main(["fuzz", "start", "--target", "mock:parser",
               "--llm-budget", "3", "--json",
               "--workspace", str(ctx.workspace().root)])
    envelope = json.loads(capsys.readouterr().out.strip())
    assert rc == 2 and envelope["ok"] is False  # USAGE: flag misuse
