"""Tests for LLM-assisted harness generation (`harness` command group)."""

from __future__ import annotations

import json

import pytest

from ios_research.errors import IosResearchError, NotFoundError
from ios_research.harness import (
    STATUS_ACCEPTED, STATUS_REJECTED, STATUS_VALIDATED,
    FileProposalProvider, HarnessGenerator, HarnessStore, TemplateProvider,
    create_provider, validate_code,
)
from ios_research.cli import main


# --- providers ---------------------------------------------------------------
def test_template_provider_is_deterministic():
    a = TemplateProvider().propose({"id": "mock:parser"}, 3)
    b = TemplateProvider().propose({"id": "mock:parser"}, 3)
    assert [p["code"] for p in a] == [p["code"] for p in b]
    assert len(a) == 3
    kinds = {p["kind"] for p in a}
    assert {"whole_buffer", "header_fielding", "dictionary_seeded"} <= kinds


def test_template_provider_respects_max_candidates():
    out = TemplateProvider().propose({"id": "mock:parser"}, 1)
    assert len(out) == 1 and out[0]["kind"] == "whole_buffer"


def test_create_provider_unknown_and_file(tmp_path):
    with pytest.raises(IosResearchError):
        create_provider("nope")
    with pytest.raises(IosResearchError):
        create_provider("file")  # missing path
    path = tmp_path / "props.json"
    path.write_text(json.dumps([{"kind": "k", "code": "def fuzz(d):\n"
                                            "    return 'accepted'\n"}]))
    provider = create_provider("file", path=str(path))
    assert provider.name == "file"
    props = provider.propose({"id": "x"}, 5)
    assert len(props) == 1 and "def fuzz(" in props[0]["code"]


def test_file_provider_bad_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    with pytest.raises(IosResearchError):
        FileProposalProvider(str(path)).propose({"id": "x"}, 3)


# --- validation --------------------------------------------------------------
def test_validate_code_flags_missing_entrypoint_and_syntax():
    ok = validate_code("def fuzz(data):\n    return data\n")
    assert ok["ok"] is True and ok["problems"] == []
    assert validate_code("")[ "ok"] is False
    missing = validate_code("def other():\n    pass\n")
    assert any("fuzz" in p for p in missing["problems"])
    broken = validate_code("def fuzz(\n")
    assert any("syntax" in p for p in broken["problems"])


# --- generator / store -------------------------------------------------------
def test_generate_validates_and_persists(ctx):
    gen = HarnessGenerator(ctx.workspace())
    created = gen.generate(target_id="mock:parser",
                           provider=TemplateProvider(), max_candidates=3)
    assert len(created) == 3
    assert all(c.status == STATUS_VALIDATED for c in created)
    ids = [c.id for c in created]
    # Deterministic ids: regenerating identical proposals reuses the records.
    again = gen.generate(target_id="mock:parser",
                         provider=TemplateProvider(), max_candidates=3)
    assert [c.id for c in again] == ids

    store = HarnessStore(ctx.workspace())
    assert len(store.list()) == 3
    assert store.get(created[0].id).target == "mock:parser"


def test_generate_unknown_target(ctx):
    gen = HarnessGenerator(ctx.workspace())
    with pytest.raises(NotFoundError):
        gen.generate(target_id="nope:none", provider=TemplateProvider(),
                     max_candidates=1)


def test_generate_smoke_executes_driver(ctx):
    gen = HarnessGenerator(ctx.workspace())
    created = gen.generate(target_id="mock:parser",
                           provider=TemplateProvider(), max_candidates=1,
                           smoke=True)
    smoke = created[0].validation.get("smoke", {})
    assert smoke.get("ok") is True
    assert smoke.get("outcome") in ("accepted", "rejected")


def test_rejected_proposal_status(tmp_path, ctx):
    bad = tmp_path / "props.json"
    bad.write_text(json.dumps([{"kind": "broken", "code": "def fuzz(\n"}]))
    gen = HarnessGenerator(ctx.workspace())
    created = gen.generate(target_id="mock:parser",
                           provider=create_provider("file", path=str(bad)),
                           max_candidates=2)
    assert created[0].status == STATUS_REJECTED
    assert any("syntax" in p
               for p in created[0].validation["problems"])


def test_accept_requires_validation_then_transitions(ctx):
    gen = HarnessGenerator(ctx.workspace())
    (cand,) = gen.generate(target_id="mock:parser",
                           provider=TemplateProvider(), max_candidates=1)
    cand = gen.store.get(cand.id)
    assert cand.status == STATUS_VALIDATED  # template candidates auto-validate
    accepted = gen.transition(cand.id, "accept")
    assert accepted.status == STATUS_ACCEPTED
    with pytest.raises(IosResearchError):
        gen.transition(cand.id, "reject")  # terminal state
    with pytest.raises(IosResearchError):
        gen.transition(cand.id, "frobnicate")


# --- CLI surface -------------------------------------------------------------
def test_cli_harness_roundtrip(ctx, capsys):
    ws = str(ctx.workspace().root)
    rc = main(["harness", "generate", "--target", "mock:parser",
               "--max-candidates", "2", "--workspace", ws])
    assert rc == 0
    capsys.readouterr()  # drain human output

    rc = main(["harness", "list", "--json", "--workspace", ws])
    assert rc == 0
    envelope = json.loads(_last_json(capsys))
    assert envelope["ok"] is True
    assert envelope["command"] == "harness list"
    assert envelope["data"]["count"] >= 2

    cid = envelope["data"]["candidates"][0]["id"]
    rc = main(["harness", "show", cid, "--json", "--workspace", ws])
    payload = json.loads(_last_json(capsys))
    assert rc == 0 and "def fuzz(" in payload["data"]["code"]

    rc = main(["harness", "accept", cid, "--json", "--workspace", ws])
    payload = json.loads(_last_json(capsys))
    assert rc == 0
    assert payload["data"]["status"] == STATUS_ACCEPTED


def test_cli_harness_json_error_envelope(ctx, capsys):
    ws = str(ctx.workspace().root)
    rc = main(["harness", "generate", "--target", "missing:t",
               "--json", "--workspace", ws])
    envelope = json.loads(_last_json(capsys))
    assert rc == 3  # NOT_FOUND
    assert envelope["ok"] is False and envelope["error"]


def _last_json(capsys) -> str:
    return capsys.readouterr().out.strip()
