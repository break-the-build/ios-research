"""Beta-release differential pipeline tests (#56)."""

from __future__ import annotations

import json

import pytest

from ios_research.betadiff import (
    BetaDiffEngine, dictionary_bytes, load_release,
)
from ios_research.corpus import CorpusStore
from ios_research.errors import ValidationError


def _release(tmp_path, name, files, provenance=None):
    root = tmp_path / name
    root.mkdir()
    manifest = provenance or {"os_name": "macOS", "os_version": "17.6",
                              "build": "26G100"}
    (root / "release.json").write_text(json.dumps(manifest), encoding="utf-8")
    for rel, symbols in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(symbols) + "\n", encoding="utf-8")
    return str(root)


RELEASE_A = {
    "System/Renderer.symbols": ["renderer_draw", "renderer_flush",
                                "util_crc32"],
    "System/Parser.symbols": ["parser_feed", "parser_reset"],
}
RELEASE_B = {
    "System/Renderer.symbols": ["renderer_draw", "renderer_flush",
                                "renderer_flush_v2",
                                "renderer_raytrace", "util_crc32"],
    "System/Parser.symbols": ["parser_feed", "parser_reset",
                              "parser_zero_copy"],
    "System/Codec.symbols": ["codec_decode_av1"],
}


# --- loading and validation ------------------------------------------------------

def test_load_release_requires_provenance_manifest(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValidationError, match="release.json"):
        load_release(str(empty))
    bad = _release(tmp_path, "bad", {}, provenance={"os_name": "iOS"})
    with pytest.raises(ValidationError, match="missing provenance"):
        load_release(bad)


def test_load_release_reads_symbol_files_and_hashes(tmp_path):
    root = _release(tmp_path, "relA", RELEASE_A)
    release = load_release(root)
    assert release.files["System/Parser.symbols"] == [
        "parser_feed", "parser_reset"]
    assert all(len(h) == 64 for h in release.file_hashes.values())
    assert release.label == "macOS 17.6 (26G100)"


# --- diffing -----------------------------------------------------------------

def test_diff_is_deterministic_and_ranks_novel_surfaces(tmp_path):
    engine = BetaDiffEngine.__new__(BetaDiffEngine)  # not needed; use module fn
    from ios_research.betadiff import diff_releases
    a = load_release(_release(tmp_path, "a", RELEASE_A))
    b = load_release(_release(tmp_path, "b", RELEASE_B))
    first = diff_releases(a, b)
    second = diff_releases(a, b)
    assert first == second

    components = first["components"]
    assert components["System/Codec.symbols"]["status"] == "added-component"
    assert components["System/Renderer.symbols"]["status"] == "changed"
    assert components["System/Renderer.symbols"]["removed"] == []
    assert set(components["System/Renderer.symbols"]["added"]) == {
        "renderer_flush_v2", "renderer_raytrace"}

    plan = first["novel_surface_plan"]
    assert plan[0]["component"] == "System/Renderer.symbols"
    assert plan[0]["added_symbols"] == 2
    assert [entry["rank"] for entry in plan] == list(range(1, len(plan) + 1))

    # Dictionary tokens derive from added symbols only.
    tokens = [t.lower() for t in first["dictionary_tokens"]]
    assert "raytrace" in tokens and "zero" in tokens
    assert "crc32" not in tokens          # unchanged symbol excluded
    assert len(tokens) == len(set(tokens))


def test_dictionary_bytes_are_deterministic():
    blob = dictionary_bytes(["Alpha", "beta"])
    assert blob == dictionary_bytes(["Alpha", "beta"])
    assert b"Alpha" in blob


def test_engine_pins_provenance_and_rejects_drift(workspace, tmp_path):
    engine = BetaDiffEngine(workspace)
    a = _release(tmp_path, "ra", RELEASE_A)
    b = _release(tmp_path, "rb", RELEASE_B)
    first = engine.run(release_a_path=a, release_b_path=b)
    again = engine.run(release_a_path=a, release_b_path=b)
    assert first["id"] == again["id"]           # identical inputs -> same id

    # Mutating an input changes its hash; the record must not silently drift.
    (tmp_path / "rb" / "System/Codec.symbols").write_text(
        "codec_decode_av1\ntampered\n", encoding="utf-8")
    drifted = engine.run(release_a_path=a, release_b_path=b)
    assert drifted["id"] != first["id"]

    # A stored record's provenance can never be rewritten by a re-run.
    record = engine.get(first["id"])
    assert record["release_b"]["file_hashes"][
        "System/Codec.symbols"] != drifted["release_b"]["file_hashes"][
        "System/Codec.symbols"]
    assert workspace.path(f"analysis/{first['id']}.dict").is_file()


# --- provenance flow into reports -----------------------------------------------

def test_tag_corpus_flows_beta_provenance_into_reports(workspace, tmp_path):
    from ios_research.crashes import CrashStore
    from ios_research.report import ReportGenerator
    from ios_research.experiment import ExperimentStore
    from ios_research.targets import create

    engine = BetaDiffEngine(workspace)
    a = _release(tmp_path, "ra2", RELEASE_A)
    b = _release(tmp_path, "rb2", RELEASE_B)
    diff = engine.run(release_a_path=a, release_b_path=b)

    corpus = CorpusStore(workspace).create("beta-campaign", target="mock:parser")
    engine.tag_corpus(diff_id=diff["id"], corpus_id=corpus.id)

    experiment = ExperimentStore(workspace).create(
        target="mock:parser", device="test-device", os_version="17.6",
        config_hash="cfg_test", params={"corpus": corpus.id})
    data = b"MOCK\x01\x01\xff\xff" + b"A" * 20
    crash = CrashStore(workspace).record(
        experiment_id=experiment.id, target="mock:parser", fmt="mock-record",
        data=data, exec_result=create("mock:parser").execute(data))

    report = ReportGenerator(workspace).create(crash.id)
    beta = report.sections.get("beta_provenance")
    assert beta is not None
    assert beta["diff_id"] == diff["id"]
    assert beta["release_a"]["os_name"] == "macOS"
    # Reports without tagged corpora carry no beta section. The second crash
    # uses a DIFFERENT defect rule (null dispatch vs OOB read): since #264 the
    # record id is (target, signature)-global, so the same signature would
    # merge into the tagged canonical record instead of forming an untagged one.
    plain_experiment = ExperimentStore(workspace).create(
        target="mock:parser", device="d", os_version="17.6",
        config_hash="cfg_plain")
    crash2_data = b"MOCK\x01\xff\x00\x00"
    crash2 = CrashStore(workspace).record(
        experiment_id=plain_experiment.id, target="mock:parser", fmt="m",
        data=crash2_data,
        exec_result=create("mock:parser").execute(crash2_data))
    report2 = ReportGenerator(workspace).create(crash2.id)
    assert "beta_provenance" not in report2.sections
