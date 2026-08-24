"""Versioned protocol/format suite catalog (#47)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from ios_research.suites import (
    SuiteCatalog, parse_suite_manifest, validate_suite,
    write_example_suite)
from ios_research.errors import NotFoundError, StateError, ValidationError


def _workspace():
    from ios_research.workspace import Workspace
    from ios_research import __version__, clock
    ws = Workspace(Path(tempfile.mkdtemp()) / ".ios-research")
    ws.init(framework_version=__version__, created_at=clock.now_iso())
    return ws


def _example(tmp_path):
    return write_example_suite(tmp_path / "mock-record")


# --- manifest parsing / validation ---------------------------------------------

def test_example_suite_validates(tmp_path):
    suite = _example(tmp_path)
    report = validate_suite(suite)
    assert report["valid"], report["problems"]
    assert report["name"] == "mock-record"
    assert report["problems"] == []
    manifest = parse_suite_manifest(suite)
    assert manifest["license"] == "MIT"
    assert manifest["compatibility"]["framework"] == "ios-research"


def test_unknown_manifest_field_is_rejected(tmp_path):
    suite = _example(tmp_path)
    manifest = json.loads((suite / "suite.json").read_text())
    manifest["surprise"] = True
    (suite / "suite.json").write_text(json.dumps(manifest))
    with pytest.raises(ValidationError, match="unknown field"):
        parse_suite_manifest(suite)
    report = validate_suite(suite)          # never raises
    assert not report["valid"]
    assert any("unknown field" in p for p in report["problems"])


def test_bad_version_string_is_rejected(tmp_path):
    suite = _example(tmp_path)
    manifest = json.loads((suite / "suite.json").read_text())
    manifest["version"] = "1.0"
    (suite / "suite.json").write_text(json.dumps(manifest))
    report = validate_suite(suite)
    assert any("semver-ish" in p for p in report["problems"])


def test_incompatible_min_framework_returns_structured_problem(tmp_path):
    suite = _example(tmp_path)
    manifest = json.loads((suite / "suite.json").read_text())
    manifest["compatibility"]["min_framework_version"] = "99.0.0"
    (suite / "suite.json").write_text(json.dumps(manifest))
    report = validate_suite(suite)          # must NOT raise
    assert not report["valid"]
    assert any("requires framework >= 99.0.0" in p for p in report["problems"])


def test_wrong_framework_name_flagged(tmp_path):
    suite = _example(tmp_path)
    manifest = json.loads((suite / "suite.json").read_text())
    manifest["compatibility"]["framework"] = "other-framework"
    (suite / "suite.json").write_text(json.dumps(manifest))
    report = validate_suite(suite)
    assert not report["valid"]
    assert any("other-framework" in p for p in report["problems"])


def test_version_tuple_helper_tolerates_non_numeric_parts():
    from ios_research.suites import version_tuple
    assert version_tuple("0.1.0") == (0, 1, 0)
    assert version_tuple("1.0.0-rc2") > version_tuple("0.99.9")
    assert version_tuple("0.2rc1") == (0, 2)
    assert version_tuple("") == (0,)
    assert version_tuple("abc") == (0,)


def test_path_escape_never_reads_the_file(tmp_path):
    suite = _example(tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET")
    manifest = json.loads((suite / "suite.json").read_text())
    manifest["contents"]["dictionary"] = "../secret.txt"
    (suite / "suite.json").write_text(json.dumps(manifest))
    with pytest.raises(ValidationError, match=r"\.\."):
        parse_suite_manifest(suite)
    report = validate_suite(suite)          # structured problems only
    assert not report["valid"]
    assert any("'..'" in p for p in report["problems"])
    assert secret.read_text() == "TOP SECRET"   # untouched


def test_absolute_path_in_manifest_rejected(tmp_path):
    suite = _example(tmp_path)
    manifest = json.loads((suite / "suite.json").read_text())
    manifest["contents"]["dictionary"] = "/etc/passwd"
    (suite / "suite.json").write_text(json.dumps(manifest))
    report = validate_suite(suite)
    assert any("absolute" in p for p in report["problems"])


def test_broken_plugin_reports_problem_and_catalog_stays_usable(
        tmp_path, workspace):
    suite = write_example_suite(tmp_path / "with-plugin")
    plugins = suite / "plugins"
    plugins.mkdir()
    (plugins / "broken.py").write_text("def broken(:\n")
    manifest = json.loads((suite / "suite.json").read_text())
    manifest["contents"]["plugins"] = ["plugins/broken.py"]
    (suite / "suite.json").write_text(json.dumps(manifest))

    report = validate_suite(suite)
    assert not report["valid"]
    assert any("plugin failed to load" in p for p in report["problems"])

    catalog = SuiteCatalog(workspace)
    with pytest.raises(ValidationError, match="plugin failed to load"):
        catalog.install(suite)               # invalid suites fail safely
    # Catalog itself remains fully usable.
    good = catalog.install(_example(tmp_path))
    assert good["name"] == "mock-record"
    assert len(catalog.list()) == 1


def test_missing_seeds_dir_is_a_problem(tmp_path):
    suite = _example(tmp_path)
    manifest = json.loads((suite / "suite.json").read_text())
    manifest["contents"]["seeds_dir"] = "nope"
    (suite / "suite.json").write_text(json.dumps(manifest))
    report = validate_suite(suite)
    assert any("seeds_dir" in p for p in report["problems"])


def test_state_machine_and_oracles_must_be_json_objects(tmp_path):
    suite = write_example_suite(tmp_path / "sm-suite")
    (suite / "state_machine.json").write_text("[1, 2]")
    (suite / "oracles.json").write_text("{not json")
    manifest = json.loads((suite / "suite.json").read_text())
    manifest["contents"]["state_machine"] = "state_machine.json"
    manifest["contents"]["oracles"] = "oracles.json"
    (suite / "suite.json").write_text(json.dumps(manifest))
    report = validate_suite(suite)
    assert any("state_machine" in p for p in report["problems"])
    assert any("oracles" in p for p in report["problems"])


# --- catalog lifecycle ----------------------------------------------------------

def test_install_list_get_round_trip(tmp_path, workspace):
    suite = _example(tmp_path)
    catalog = SuiteCatalog(workspace)
    installed = catalog.install(suite)
    assert installed["name"] == "mock-record"
    assert installed["version"] == "1.0.0"

    items = catalog.list()
    assert [i["name"] for i in items] == ["mock-record"]
    record = catalog.get("mock-record")
    assert record["version"] == "1.0.0"
    assert record["description"].startswith("Built-in example")
    assert Path(record["path"]).is_dir()

    receipt = record["install_receipt"]
    assert receipt["provenance"]["source"] == "built-in-example"
    hashes = {f["path"]: f["sha256"] for f in receipt["files"]}
    assert set(hashes) == {"suite.json", "dictionary.txt",
                           "seeds/seed_00.bin", "seeds/seed_01.bin",
                           "seeds/seed_02.bin", "seeds/seed_03.bin"}
    from ios_research.hashing import sha256_bytes
    for rel, digest in hashes.items():
        assert sha256_bytes((Path(record["path"]) / rel).read_bytes()) == digest


def test_duplicate_install_refused(tmp_path, workspace):
    suite = _example(tmp_path)
    catalog = SuiteCatalog(workspace)
    catalog.install(suite)
    with pytest.raises(StateError, match="already installed"):
        catalog.install(suite)


def test_remove_then_get_raises_not_found(tmp_path, workspace):
    catalog = SuiteCatalog(workspace)
    catalog.install(_example(tmp_path))
    removed = catalog.remove("mock-record", "1.0.0")
    assert removed["removed"] is True
    with pytest.raises(NotFoundError):
        catalog.get("mock-record")
    with pytest.raises(NotFoundError):
        catalog.remove("mock-record", "1.0.0")


def test_get_latest_version_wins(tmp_path, workspace):
    catalog = SuiteCatalog(workspace)
    v1 = _example(tmp_path)
    v2 = write_example_suite(tmp_path / "mock-record-v2")
    manifest = json.loads((v2 / "suite.json").read_text())
    manifest["version"] = "2.1.0"
    (v2 / "suite.json").write_text(json.dumps(manifest))
    catalog.install(v1)
    catalog.install(v2)
    latest = catalog.get("mock-record")
    assert latest["version"] == "2.1.0"
    pinned = catalog.get("mock-record", version="1.0.0")
    assert pinned["version"] == "1.0.0"


def test_seed_corpus_returns_seed_bytes(tmp_path, workspace):
    suite = _example(tmp_path)
    catalog = SuiteCatalog(workspace)
    seeds = catalog.seed_corpus(suite)
    assert len(seeds) == 4
    assert all(blob.startswith(b"MOCK") for blob in seeds)
    installed = catalog.install(suite)
    again = catalog.seed_corpus(catalog.get(installed["name"]))
    assert again == seeds


# --- benchmark ------------------------------------------------------------------

def test_benchmark_deterministic_across_runs_and_workspaces(tmp_path):
    suite = _example(tmp_path)
    stats_a = SuiteCatalog(_workspace()).run_benchmark(
        suite, "mock:parser", cases=25, seed=7)
    stats_b = SuiteCatalog(_workspace()).run_benchmark(
        suite, "mock:parser", cases=25, seed=7)
    for key in ("executed", "unique_features", "outcomes"):
        assert stats_a[key] == stats_b[key], key
    assert stats_a["executed"] == 25
    assert sum(stats_a["outcomes"].values()) == 25


def test_benchmark_uses_suite_dictionary_and_bounds_cases(
        tmp_path, workspace):
    suite = _example(tmp_path)
    catalog = SuiteCatalog(workspace)
    with pytest.raises(Exception, match="limited to 200"):
        catalog.run_benchmark(suite, "mock:parser", cases=201, seed=0)
    stats = catalog.run_benchmark(suite, "mock:parser", cases=10, seed=3)
    assert stats["suite"] == {"name": "mock-record", "version": "1.0.0"}
    assert stats["executed"] == 10


def test_benchmark_rejects_unknown_target(tmp_path, workspace):
    with pytest.raises(Exception, match="unknown target"):
        SuiteCatalog(workspace).run_benchmark(
            _example(tmp_path), "no:such-target", cases=5, seed=0)


def test_benchmark_refuses_invalid_suite(tmp_path, workspace):
    suite = _example(tmp_path)
    manifest = json.loads((suite / "suite.json").read_text())
    manifest["compatibility"]["min_framework_version"] = "99.0.0"
    (suite / "suite.json").write_text(json.dumps(manifest))
    with pytest.raises(ValidationError, match="invalid suite"):
        SuiteCatalog(workspace).run_benchmark(
            suite, "mock:parser", cases=5, seed=0)


# --- CLI ------------------------------------------------------------------------

def _ctx(workspace, assume_yes=True):
    from ios_research.context import Context
    return Context(workspace_path=str(workspace.root),
                   assume_yes=assume_yes)


class _Args:
    def __init__(self, **kwargs):
        self.directory = None
        self.name = None
        self.version = None
        self.out = None
        self.target = None
        self.cases = 50
        self.seed = 0
        self.suite_version = None
        for key, value in kwargs.items():
            setattr(self, key, value)


def test_cli_round_trip(tmp_path, workspace):
    from ios_research.commands import suite_cmd
    suite = _example(tmp_path)

    out = suite_cmd.cmd_validate(_ctx(workspace), _Args(directory=str(suite)))
    assert out.ok and out.data["report"]["valid"]

    out = suite_cmd.cmd_install(_ctx(workspace),
                                _Args(directory=str(suite)))
    assert out.ok

    out = suite_cmd.cmd_list(_ctx(workspace), _Args())
    assert out.data["count"] == 1

    out = suite_cmd.cmd_show(_ctx(workspace), _Args(name="mock-record"))
    assert out.data["suite"]["version"] == "1.0.0"

    out = suite_cmd.cmd_benchmark(
        _ctx(workspace),
        _Args(name="mock-record", target="mock:parser", cases=10, seed=5))
    assert out.ok and out.data["benchmark"]["executed"] == 10

    ctx = _ctx(workspace, assume_yes=False)   # removal requires confirmation
    args = _Args(name="mock-record", version="1.0.0")
    from ios_research.errors import InterruptedError_
    with pytest.raises(InterruptedError_):
        suite_cmd.cmd_remove(ctx, args)
    out = suite_cmd.cmd_remove(_ctx(workspace), args)
    assert out.ok
    with pytest.raises(NotFoundError):
        suite_cmd.cmd_show(_ctx(workspace), _Args(name="mock-record"))


def test_cli_validate_invalid_reports_failure_envelope(tmp_path, workspace):
    from ios_research.commands import suite_cmd
    from ios_research.errors import ExitCode
    suite = _example(tmp_path)
    manifest = json.loads((suite / "suite.json").read_text())
    del manifest["license"]
    (suite / "suite.json").write_text(json.dumps(manifest))
    result = suite_cmd.cmd_validate(_ctx(workspace),
                                    _Args(directory=str(suite)))
    assert not result.ok
    assert result.exit_code == ExitCode.VALIDATION
    assert result.data["report"]["problems"]


def test_cli_example_writes_suite(tmp_path):
    from ios_research.commands import suite_cmd
    out = suite_cmd.cmd_example(None, _Args(out=str(tmp_path / "ex")))
    assert out.ok
    assert (tmp_path / "ex" / "suite.json").is_file()
