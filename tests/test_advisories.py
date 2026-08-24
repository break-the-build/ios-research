"""Advisory corpus and novelty-scoring tests (#59)."""

from __future__ import annotations

import json

import pytest

from ios_research.advisories import (
    KNOWN_FIXED, KNOWN_UNFIXED, NOVEL, Advisory, AdvisoryStore, NoveltyIndex,
    match_crash,
)
from ios_research.crashes import CrashStore
from ios_research.errors import ValidationError
from ios_research.targets import create


def _crash(workspace, target="mock:parser", data=None):
    data = data or b"MOCK\x01\x01\xff\xff" + b"A" * 20
    result = create(target).execute(data)
    return CrashStore(workspace).record(
        experiment_id="e1", target=target, fmt="mock-record",
        data=data, exec_result=result)


def _advisory_file(tmp_path, payload):
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


ADVISORIES = {
    "source": "fixture-feed",
    "advisories": [
        {"id": "CVE-2026-0001", "components": ["mock-parser"],
         "classifications": ["OUT_OF_BOUNDS_READ"],
         "signature_patterns": [], "summary": "known OOB read"},
        {"id": "CVE-2026-0002", "components": ["mock:parser-v2"],
         "classifications": ["USE_AFTER_FREE"],
         "signature_patterns": ["sig_uaf"], "fixed_in": "18.1"},
    ],
}


# --- import ---------------------------------------------------------------------

def test_import_is_validated_and_pinned(workspace, tmp_path):
    store = AdvisoryStore(workspace)
    result = store.import_file(_advisory_file(tmp_path, ADVISORIES))
    assert result["imported"] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert len(result["source_sha256"]) == 64
    first = store.get("CVE-2026-0001")
    assert first.source == "fixture-feed"
    # Re-import is idempotent on ids.
    store.import_file(_advisory_file(tmp_path, ADVISORIES))
    assert len(store.list()) == 2


@pytest.mark.parametrize("payload", [
    [],                       # not an object
    {"advisories": []},       # empty corpus
    {"advisories": [{"no": "id"}]},
    {"advisories": [1]},
])
def test_corrupt_imports_fail_safely(workspace, tmp_path, payload):
    with pytest.raises(ValidationError):
        AdvisoryStore(workspace).import_file(
            _advisory_file(tmp_path, payload))
    assert AdvisoryStore(workspace).list() == []


# --- matching and scoring ---------------------------------------------------------

def test_match_confidence_levels():
    crash = CrashStore.__new__(CrashStore)  # not needed; build a fake record
    from ios_research.crashes import CrashRecord
    record = CrashRecord(
        id="c1", experiment_id="e", target="mock-parser", fmt="mock-record",
        input_sha256="x", input_size=3, outcome="crash", detail="d",
        classification="OUT_OF_BOUNDS_READ", signature="sig_oob_read_abc",
        diagnostics={"modules": ["MockParser"]})
    advisory = Advisory(id="A", components=["mock-parser"],
                        classifications=["out_of_bounds_read"])
    confidence, reasons = match_crash(record, advisory)
    assert confidence == "MEDIUM"
    assert set(reasons) == {"component match", "classification match"}

    advisory_full = Advisory(id="B", components=["mock-parser"],
                             classifications=["OUT_OF_BOUNDS_READ"],
                             signature_patterns=["oob_read"])
    confidence, reasons = match_crash(record, advisory_full)
    assert confidence == "HIGH"


def test_scan_orders_novel_first_and_known_fixed_last(workspace, tmp_path):
    AdvisoryStore(workspace).import_file(_advisory_file(tmp_path, ADVISORIES))
    index = NoveltyIndex(workspace)

    known_unfixed = _crash(workspace)                    # OOB read ~ CVE-0001
    # v2 OOB-write regression input: component-only match => stays novel
    novel = _crash(workspace, target="mock:parser-v2",
                   data=b"MOCK\x02\x01\x00\x02payload")
    # v2 use-after-free input matching fixed advisory CVE-2026-0002
    known_fixed = _crash(workspace, target="mock:parser-v2",
                         data=b"MOCK\x01\x01\x00\x02\xde\xad")

    result = index.scan()
    order = result["priority_order"]
    by_id = {item["crash_id"]: item for item in result["results"]}
    assert by_id[known_unfixed.id]["novelty"] == KNOWN_UNFIXED
    assert by_id[novel.id]["novelty"] == NOVEL
    assert by_id[known_fixed.id]["novelty"] == KNOWN_FIXED
    assert order.index(novel.id) < order.index(known_unfixed.id) \
        < order.index(known_fixed.id)
    assert result["counts"] == {NOVEL: 1, KNOWN_UNFIXED: 1, KNOWN_FIXED: 1}
    # Scan artifacts persist separately; crash records untouched.
    assert workspace.path(f"analysis/{result['scan_id']}.json").is_file()


def test_low_confidence_candidates_do_not_demote_novelty(workspace):
    from ios_research.crashes import CrashRecord
    AdvisoryStore(workspace).put(Advisory(
        id="WEAK-1", components=["Mock Parser"]))  # component-only hit
    crash = CrashRecord(
        id="c9", experiment_id="e", target="mock:parser", fmt="mock-record",
        input_sha256="x", input_size=3, outcome="crash", detail="d",
        classification="OUT_OF_BOUNDS_READ", signature="sig_oob_read_abc",
        diagnostics={"modules": ["MockParser"]})
    scored = NoveltyIndex(workspace).score(crash)
    assert scored["candidates"][0]["confidence"] == "LOW"
    assert scored["candidates"][0]["affects_novelty"] is False
    assert scored["novelty"] == NOVEL


def test_scoring_is_deterministic(workspace, tmp_path):
    AdvisoryStore(workspace).import_file(_advisory_file(tmp_path, ADVISORIES))
    crash = _crash(workspace)
    first = NoveltyIndex(workspace).scan()
    second = NoveltyIndex(workspace).scan()
    assert first["results"] == second["results"]


def test_missing_advisory_lookup_raises_not_found(workspace):
    from ios_research.errors import NotFoundError
    with pytest.raises(NotFoundError):
        AdvisoryStore(workspace).get("does-not-exist")


# --- CLI ----------------------------------------------------------------------

def test_advisory_cli_roundtrip(workspace, tmp_path):
    from ios_research.cli import main
    path = _advisory_file(tmp_path, ADVISORIES)
    ws = ["--workspace", str(workspace.root)]
    assert main([*ws, "advisory", "import", path, "--json"]) == 0
    assert main([*ws, "advisory", "list", "--json"]) == 0
    assert main([*ws, "advisory", "scan", "--json"]) == 0
