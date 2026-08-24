"""LLM-in-the-loop mutation: proposer interface, feedback rounds, provenance.

Issue #71. The acceptance criteria are exercised end to end with a scripted
fake proposer (no network, no SDKs): crash-aware refinement between rounds,
budget caps enforced in code, provenance-tagged corpus entries, format-aware
repair, and campaigns that complete without any model attached.
"""

from __future__ import annotations

import base64
import json
import shlex
import struct
import sys

import pytest

from ios_research import llmmutate
from ios_research.cli import main
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine
from ios_research.grammar import PluginHost
from ios_research.llmmutate import (
    CommandProposer, EchoProposer, ProposerError, ScriptedProposer,
    redact_text, short_hash, summarize_crash, validate_budget)
from ios_research.plugins_builtin import ChunkedBinPlugin, NestedTlvPlugin
from ios_research.hashing import sha256_bytes
from ios_research.workspace import Workspace

SEED = b"MOCK\x01\x01\x00\x02ok"
CRASH_OOB = b"MOCK\x01\x01\xff\xff" + b"A" * 20          # OUT_OF_BOUNDS_READ
CRASH_NULL = b"MOCK\x01\xff\x00\x00"                     # NULL_DEREFERENCE


# --- budget caps -----------------------------------------------------------------

def test_validate_budget_rejects_non_positive():
    for rounds, budget in ((0, 5), (2, 0), (-1, 5), (2, -3)):
        with pytest.raises(Exception) as exc:
            validate_budget(rounds, budget)
        assert ">= 1" in str(exc.value)


def test_validate_budget_enforces_caps_like_worker_limits():
    with pytest.raises(Exception) as exc:
        validate_budget(llmmutate.DEFAULT_MAX_LLM_ROUNDS + 1, 4)
    assert "exceeds limit" in str(exc.value)
    with pytest.raises(Exception) as exc:
        validate_budget(2, llmmutate.DEFAULT_MAX_LLM_BUDGET + 1)
    assert "exceeds limit" in str(exc.value)
    validate_budget(llmmutate.DEFAULT_MAX_LLM_ROUNDS,
                    llmmutate.DEFAULT_MAX_LLM_BUDGET)


# --- sanitization / redaction ------------------------------------------------------

def test_redact_text_collapses_roots_hashes_and_paths():
    root = "/Users/researcher/x/.ios-research"
    text = (f"input {root}/crashes/crash_abc/crash.json "
            "sha 0123456789abcdef0123456789abcdef "
            "at /usr/local/lib/libFuzzer.so")
    out = redact_text(text, roots=[root])
    assert root not in out
    assert "<workspace>" in out
    assert "0123456789abcdef" not in out
    assert "0123456789ab " in out
    assert "/usr/local" not in out
    assert "libFuzzer.so" in out


def test_short_hash_truncates_deterministically():
    assert short_hash("crash_1234567890abcdef") == "crash_123456"
    assert short_hash("") == ""


def test_summarize_crash_is_bounded_and_redacted():
    root = "/Users/researcher/x/.ios-research"
    summary = summarize_crash(
        crash_id="crash_" + "a" * 16,
        signature="sig_" + "b" * 40,
        classification="OUT_OF_BOUNDS_READ",
        detail=f"declared_length=65535 exceeds payload=20 ({root}/artifacts/"
               "0123456789abcdef0123456789abcdef.bin)",
        count=7,
        input_sha256="c" * 64,
        example_bytes=b"\xde\xad" * 200,
        roots=[root])
    dumped = json.dumps(summary)
    assert root not in dumped
    assert "c" * 64 not in dumped
    assert len(summary["input_sha256"]) == llmmutate.HASH_KEEP
    assert len(summary["signature"]) == llmmutate.HASH_KEEP
    assert len(summary["detail"]) <= llmmutate.MAX_DETAIL_CHARS
    assert len(summary["example_hex"]) <= llmmutate.MAX_FEW_SHOT_HEX
    assert summary["classification"] == "OUT_OF_BOUNDS_READ"
    assert summary["count"] == 7


# --- bundled proposers --------------------------------------------------------------

def test_scripted_proposer_records_contexts_and_cycles_batches():
    proposer = ScriptedProposer([[b"a"], [b"b", b"c"]],
                                proposer_id="scripted-test")
    assert proposer.propose({"round": 1}) == [b"a"]
    assert proposer.propose({"round": 2}) == [b"b", b"c"]
    assert proposer.propose({"round": 3}) == []
    assert [ctx["round"] for ctx in proposer.contexts] == [1, 2, 3]
    # Contexts are snapshots: later calls cannot rewrite feedback history.
    proposer.contexts[0]["round"] = 99
    assert proposer.contexts[1]["round"] == 2
    assert proposer.proposer_id == "scripted-test"


def test_echo_proposer_echoes_corpus_samples_from_context():
    proposer = EchoProposer()
    context = {"corpus": {"sample_hex": ["deadbeef", "00"]}}
    assert proposer.propose(context) == [b"\xde\xad\xbe\xef", b"\x00"]
    assert proposer.proposer_id == "echo"


def _proposer_script(body: str) -> str:
    return f"{sys.executable} -c {shlex.quote(body)}"


def test_command_proposer_parses_base64_lines_and_skips_garbage():
    script = ("import base64\n"
              "print(base64.b64encode(b'candidate-A').decode())\n"
              "print('# comment')\n"
              "print('not-base64!!')\n"
              "print(base64.b64encode(b'candidate-B').decode())\n")
    proposer = CommandProposer(_proposer_script(script))
    assert proposer.propose({"round": 1}) == [b"candidate-A", b"candidate-B"]
    assert "not-base64" in proposer.last_error


def test_command_proposer_receives_context_as_json_on_stdin():
    script = ("import sys, json, base64\n"
              "ctx = json.load(sys.stdin)\n"
              "print(base64.b64encode(ctx['corpus']['id'].encode()).decode())\n")
    proposer = CommandProposer(_proposer_script(script))
    context = {"corpus": {"id": "cor_abc123"}}
    assert list(proposer.propose(context))[0] == b"cor_abc123"


def test_command_proposer_surfaces_failure_and_timeout():
    failing = CommandProposer(_proposer_script("import sys; sys.exit(3)"))
    with pytest.raises(ProposerError):
        failing.propose({})
    slow = CommandProposer("sleep 2", timeout_s=0.05)
    with pytest.raises(ProposerError):
        slow.propose({})


def test_command_proposer_identity_derives_from_template():
    one = CommandProposer("echo hi")
    two = CommandProposer("echo bye")
    assert one.proposer_id.startswith("cmd:")
    assert one.proposer_id != two.proposer_id


# --- format-aware repair --------------------------------------------------------

def _tlv_blob(count: int) -> bytes:
    return NestedTlvPlugin().serialize(
        [(0x01, bytes([item])) for item in range(count)])


def test_plugin_host_repair_bytes_fixes_corrupted_chunked_container():
    host = PluginHost()
    host.plugins = [ChunkedBinPlugin()]
    corrupted = struct.pack(">H", 3) + struct.pack(">H", 2) + b"ab"
    repaired = host.repair_bytes(corrupted)
    assert repaired is not None and repaired != corrupted
    assert ChunkedBinPlugin().validity_score(repaired) == 1.0


def test_plugin_host_repair_bytes_leaves_foreign_formats_alone():
    host = PluginHost()
    host.plugins = [NestedTlvPlugin()]
    mock_record = SEED + b"extra"
    assert NestedTlvPlugin().parse(mock_record) is None
    assert host.repair_bytes(mock_record) is None


# --- engine integration ----------------------------------------------------------

def _build_session(workspace, *, batches, rounds, budget, max_cases,
                   proposer_id="scripted-test"):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="llm-mutate", seed=5)
    store = CorpusStore(workspace)
    corpus = store.create("llm-seeds", target="mock:parser")
    store.add_bytes(corpus, SEED, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(
        experiment_id=exp.id, target="mock:parser", corpus_id=corpus.id,
        seed=5, workers=1, max_cases=max_cases, duration_s=None,
        mutator_mode="llm", proposer_id=proposer_id,
        llm_rounds=rounds, llm_budget=budget)
    proposer = ScriptedProposer(batches, proposer_id=proposer_id)
    return engine, session, corpus, proposer


def test_engine_runs_crash_aware_feedback_rounds(workspace):
    engine, session, corpus, proposer = _build_session(
        workspace, batches=[[CRASH_OOB], [CRASH_NULL]],
        rounds=3, budget=4, max_cases=6)
    session = engine.advance(session, proposer=proposer)

    assert session.status == "completed"
    assert session.llm_cases_used == 2
    assert session.llm_rounds_done == 3          # third round saw no candidates
    stats = session.stats()["llm_mutator"]
    assert stats["accepted"] == 2 and stats["rejected"] == 0
    assert stats["budget"] == 4 and stats["cases_used"] == 2

    # Closed loop: round 2 was shown the crash that round 1 produced.
    first, second, third = proposer.contexts
    assert first["crashes"] == []
    assert [c["classification"] for c in second["crashes"]] == \
        ["OUT_OF_BOUNDS_READ"]
    assert second["crashes"][0]["example_hex"]
    assert second["schema"] == llmmutate.CONTEXT_SCHEMA_VERSION
    assert second["round"] == 2
    assert second["corpus"]["origins"] == {"llm": 1, "seed": 1}
    # Round 3 accumulated both crashes as few-shot summaries.
    assert sorted(c["classification"] for c in third["crashes"]) == \
        ["NULL_DEREFERENCE", "OUT_OF_BOUNDS_READ"]
    # Nothing shipped to the proposer leaks layout paths or full hashes; the
    # bounded few-shot hex of the crashing input is the intended payload.
    for context in proposer.contexts:
        dumped = json.dumps(context)
        assert str(workspace.root) not in dumped
        assert sha256_bytes(CRASH_OOB) not in dumped
        for crash_summary in context["crashes"]:
            assert len(crash_summary["example_hex"]) <= \
                llmmutate.MAX_FEW_SHOT_HEX
    assert session.unique_crashes == 2


def test_engine_tags_provenance_on_every_executed_proposal(workspace):
    engine, session, corpus, proposer = _build_session(
        workspace, batches=[[CRASH_OOB], [CRASH_NULL]],
        rounds=2, budget=2, max_cases=4)
    store = engine.corpus_store
    session = engine.advance(session, proposer=proposer)
    manifest = store.get(corpus.id)
    llm_entries = [tc for tc in manifest.testcases if tc["origin"] == "llm"]
    assert len(llm_entries) == 2
    by_mutation = {tc["mutation"]: tc for tc in llm_entries}
    for label, data in (("llm:scripted-test@r1", CRASH_OOB),
                        ("llm:scripted-test@r2", CRASH_NULL)):
        entry = by_mutation[label]
        assert entry["parent"] is None
        assert entry["iteration"] is not None
        assert store.read_bytes(manifest, entry["sha256"]) == data


def test_campaign_completes_without_the_model_after_reload(tmp_path,
                                                           workspace):
    """Pause mid-campaign, reload from disk, resume with NO proposer."""
    engine, session, corpus, proposer = _build_session(
        workspace, batches=[[CRASH_OOB], [CRASH_NULL]],
        rounds=2, budget=2, max_cases=8)
    session = engine.advance(session, max_new=2, proposer=proposer)
    assert session.llm_cases_used == 2

    resumed = FuzzEngine(workspace).get(session.id)
    resumed_engine = FuzzEngine(workspace)
    while resumed.status != "completed":
        resumed = resumed_engine.resume(resumed)   # no proposer attached

    ws2 = Workspace(tmp_path / "rerun-ws")
    ws2.init(framework_version="test", created_at="2023-11-14T22:13:20Z")
    engine2, session2, _, proposer2 = _build_session(
        ws2, batches=[[CRASH_OOB], [CRASH_NULL]],
        rounds=2, budget=2, max_cases=8)
    done = engine2.advance(session2, proposer=proposer2)

    assert resumed.outcomes == done.outcomes
    assert resumed.crash_ids == done.crash_ids
    assert resumed.cursor == done.cursor == 8
    assert resumed.coverage_features == done.coverage_features
    shas_a = sorted(tc["sha256"] for tc in
                    engine.corpus_store.get(corpus.id).testcases)
    shas_b = sorted(tc["sha256"] for tc in
                    engine2.corpus_store.get(corpus.id).testcases)
    assert shas_a == shas_b


def test_budget_cap_limits_executed_proposals(workspace):
    engine, session, corpus, proposer = _build_session(
        workspace,
        batches=[[CRASH_OOB, CRASH_NULL,
                  b"MOCK\x01\x01\x00\x04" + b"\xde\xadbeef"]],
        rounds=1, budget=1, max_cases=4)
    session = engine.advance(session, proposer=proposer)
    assert session.llm_cases_used == 1
    assert session.llm_accepted == 3              # all queued after validation
    assert session.llm_rounds_done == 1           # rounds exhausted anyway
    assert session.unique_crashes == 1            # only the executed proposal


def test_round_cap_stops_proposals_even_with_budget_left(workspace):
    engine, session, corpus, proposer = _build_session(
        workspace, batches=[[CRASH_OOB]],
        rounds=1, budget=5, max_cases=3)
    session = engine.advance(session, proposer=proposer)
    assert session.llm_cases_used == 1
    assert session.llm_rounds_done == 1
    assert session.cursor == 3                    # rest ran generic mutation


def test_oversize_and_duplicate_candidates_are_rejected_not_executed(workspace):
    engine, session, corpus, proposer = _build_session(
        workspace, batches=[[b"x" * 64, SEED, b""]],
        rounds=1, budget=5, max_cases=2)
    session.max_input_bytes = 8                   # shrink hardening bound
    session = engine.advance(session, proposer=proposer)
    assert session.llm_accepted == 0
    assert session.llm_rejected == 3              # oversize, duplicate, empty
    assert session.llm_cases_used == 0
    entries = [tc for tc in
               engine.corpus_store.get(corpus.id).testcases
               if tc["origin"] == "llm"]
    assert entries == []


class ExplodingProposer:
    proposer_id = "exploding"

    def propose(self, context):
        raise RuntimeError("model offline")


def test_exploding_proposer_degrades_to_generic_mutation(workspace):
    engine, session, corpus, _ = _build_session(
        workspace, batches=[], rounds=2, budget=4, max_cases=3)
    session = engine.advance(session, proposer=ExplodingProposer())
    assert session.status == "completed"
    assert session.cursor == 3
    # Both round attempts failed; the surfaced error is the latest one.
    assert session.llm_last_error.startswith("round")
    assert "model offline" in session.llm_last_error
    assert session.llm_rounds_done == 2
    assert session.llm_cases_used == 0
    assert sum(session.outcomes.values()) >= 3    # generic mutation ran


def test_format_aware_repair_applies_to_eligible_proposals(workspace, tmp_path):
    plugin_path = tmp_path / "tlv_plugin.py"
    plugin_path.write_text(
        "from ios_research.plugins_builtin import NestedTlvPlugin\n"
        "PLUGIN = NestedTlvPlugin()\n")
    foreign = CRASH_OOB                       # not TLV: must stay verbatim
    sloppy_tlv = _tlv_blob(80)                # >64 items: repair trims to 64
    engine, session, corpus, proposer = _build_session(
        workspace, batches=[[foreign], [sloppy_tlv]],
        rounds=2, budget=2, max_cases=3)
    session.mutator_plugin_path = str(plugin_path)
    session = engine.advance(session, proposer=proposer)

    assert session.llm_cases_used == 2
    store = engine.corpus_store
    manifest = store.get(corpus.id)
    llm_entries = {tc["mutation"]: tc for tc in manifest.testcases
                   if tc["origin"] == "llm"}
    executed_foreign = store.read_bytes(
        manifest, llm_entries["llm:scripted-test@r1"]["sha256"])
    executed_tlv = store.read_bytes(
        manifest, llm_entries["llm:scripted-test@r2"]["sha256"])
    assert executed_foreign == foreign         # untouched: no format match
    assert executed_tlv != sloppy_tlv          # normalized by repair
    assert len(NestedTlvPlugin().parse(executed_tlv)) == 64


def test_plain_sessions_expose_zeroed_llm_stats_block(workspace):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="plain", seed=1)
    store = CorpusStore(workspace)
    corpus = store.create("plain-seeds", target="mock:parser")
    basic = FuzzEngine(workspace).create(
        experiment_id=exp.id, target="mock:parser", corpus_id=corpus.id,
        seed=1, workers=1, max_cases=1, duration_s=None)
    assert basic.stats()["llm_mutator"] == {
        "mode": "", "proposer_id": "", "rounds_requested": 0,
        "rounds_done": 0, "budget": 0, "cases_used": 0,
        "accepted": 0, "rejected": 0, "last_error": ""}


# --- CLI wiring -------------------------------------------------------------------

def _start_cmd(*extra):
    return ["--json", "fuzz", "start", "--target", "mock:parser",
            "--max-cases", "6", *extra]


def test_cli_mutator_llm_requires_proposer_source(workspace):
    rc = main(["--workspace", str(workspace.root), *_start_cmd(),
               "--mutator", "llm"])
    assert rc == 2


def test_cli_rejects_llm_budget_and_round_violations(workspace):
    template = _proposer_script(
        "print(base64.b64encode(b'x').decode())")
    argv = ["--workspace", str(workspace.root), *_start_cmd(),
            "--mutator", "llm", "--llm-proposer-cmd", template]
    assert main([*argv, "--llm-rounds", "2", "--llm-budget", "999999"]) == 2
    assert main([*argv, "--llm-rounds", "0", "--llm-budget", "4"]) == 2
    assert main([*argv, "--llm-rounds", "2", "--llm-budget", "-1"]) == 2


def test_cli_llm_round_trip_produces_tagged_corpus_and_crash(workspace):
    body = ("import base64\n"
            f"data = {CRASH_OOB!r}\n"
            "print(base64.b64encode(data).decode())\n")
    template = _proposer_script(body)
    rc = main(["--workspace", str(workspace.root), *_start_cmd(),
               "--mutator", "llm", "--llm-rounds", "2",
               "--llm-budget", "3",
               "--llm-proposer-cmd", template])
    assert rc == 0
    engine = FuzzEngine(workspace)
    sessions = engine.list()
    assert len(sessions) == 1
    session = sessions[0]
    assert session.mutator_mode == "llm"
    assert session.proposer_id.startswith("cmd:")
    assert session.llm_cases_used == 1
    assert session.unique_crashes == 1
    store = engine.corpus_store
    corpus = store.get(session.corpus_id)
    llm_entries = [tc for tc in corpus.testcases if tc["origin"] == "llm"]
    assert len(llm_entries) == 1
    assert llm_entries[0]["mutation"].startswith("llm:cmd:")
    assert store.read_bytes(corpus, llm_entries[0]["sha256"]) == CRASH_OOB


def test_cli_generic_mutator_keeps_default_behavior(workspace):
    rc = main(["--workspace", str(workspace.root), *_start_cmd(),
               "--mutator", "generic"])
    assert rc == 0
    session = FuzzEngine(workspace).list()[0]
    assert session.mutator_mode == ""
    assert session.stats()["llm_mutator"]["mode"] == ""


def test_base64_round_trip_helper_matches_command_proposer_contract():
    payload = base64.b64encode(CRASH_OOB).decode()
    assert base64.b64decode(payload, validate=True) == CRASH_OOB
