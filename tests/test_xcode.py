"""Xcode test-plan adapter delta tests (#36): diagnostics table, hermetic
bundle ingestion, fuzz-input repro mapping, canonical CLI aliases.

Everything runs against the committed fixtures under
``tests/fixtures/xcode/``; no Xcode tooling is required or invoked.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from ios_research.errors import NotFoundError, ValidationError
from ios_research.hashing import sha256_bytes
from ios_research.xcode import (
    KNOWN_DIAGNOSTICS,
    SANITIZER_FLAGS,
    map_repro_from_input,
    parse_test_plan,
    parse_xcresult_bundle,
    parse_xcresult_path,
    tool_provenance,
)

FIXTURES = Path(__file__).parent / "fixtures" / "xcode"
PLAN_PATH = str(FIXTURES / "SampleApp.xctestplan")
BAD_PLAN_PATH = str(FIXTURES / "UnsupportedDiagnostics.xctestplan")
BUNDLE_PATH = str(FIXTURES / "SampleApp.xcresult")


def _run_main(argv):
    from ios_research.cli import main
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(list(argv))
    return code, buf.getvalue()


def _import_fixture_plan() -> str:
    """Import the fixture plan into a fresh tmp workspace; return its id."""
    from ios_research.cli import main
    assert main(["init", "--json"]) == 0
    assert _run_main(["xcode", "import-plan", PLAN_PATH, "--json"])[0] == 0
    _, out = _run_main(["xcode", "plan", "list", "--json"])
    return json.loads(out)["data"]["plans"][0]["id"]


# --- KNOWN-DIAGNOSTICS table ---------------------------------------------------

class TestDiagnosticsTable:
    def test_known_table_covers_issue_scope(self):
        assert set(KNOWN_DIAGNOSTICS) >= {
            "address", "thread", "undefined-behavior",
            "main-thread-checker", "guard-malloc", "zombies",
            "code-coverage"}

    def test_guard_malloc_and_coverage_flags_map(self):
        assert SANITIZER_FLAGS["guard-malloc"] == ("-enableGuardMalloc", "YES")
        assert SANITIZER_FLAGS["code-coverage"] == \
            ("-enableCodeCoverage", "YES")

    def test_fixture_plan_imports_with_declared_diagnostics(self):
        plan = parse_test_plan(PLAN_PATH)
        assert plan["name"] == "SampleApp"
        assert [t["name"] for t in plan["targets"]] == \
            ["SampleAppTests", "SampleAppUITests"]
        assert plan["targets"][1]["skipped"] is True
        assert plan["diagnostics"] == ["address"]

    def test_unsupported_plan_diagnostic_is_actionable(self):
        with pytest.raises(ValidationError) as exc:
            parse_test_plan(BAD_PLAN_PATH)
        message = exc.value.message
        assert "quantumSanitizer" in message
        assert "supported diagnostics:" in message
        for name in ("address", "thread", "undefined-behavior",
                     "guard-malloc", "zombies"):
            assert name in message


# --- hermetic bundle ingestion ---------------------------------------------------

class TestXcresultBundle:
    def test_bundle_normalizes_crashes_logs_coverage_provenance(self):
        parsed = parse_xcresult_bundle(BUNDLE_PATH)
        assert len(parsed["crashes"]) == 3
        asan = parsed["crashes"][0]
        assert asan["test"] == "SampleAppTests/ParserTests/testFuzzInput"
        assert asan["sanitizer"] == "address"
        assert asan["classification_hint"] == "OUT_OF_BOUNDS_WRITE"
        assert parsed["crashes"][1]["sanitizer"] == "thread"
        plain = parsed["crashes"][2]
        assert plain["sanitizer"] == ""
        log_names = [log["name"] for log in parsed["logs"]]
        assert "session.log" in log_names
        session = next(l for l in parsed["logs"] if l["name"] == "session.log")
        assert any("AddressSanitizer" in line
                   for line in session["excerpt"])
        assert parsed["coverage"]["entries"]["Line Coverage"] == pytest.approx(
            0.62)
        # Provenance merges Info.plist metadata and the graph's device info.
        assert parsed["provenance"]["formatVersion"] == "3.46"
        assert parsed["provenance"]["os_version"] == "17.5 (21F90)"
        assert parsed["provenance"]["model"] == "iPhone15,2"
        assert [u["issue_type"] for u in parsed["unrecognized"]] == \
            ["ExoticFutureDiagnostic"]

    def test_parse_path_uses_hermetic_walker_without_tooling(self,
                                                             monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        normalized, raw = parse_xcresult_path(BUNDLE_PATH)
        assert raw is None
        assert len(normalized["crashes"]) == 3

    def test_directory_without_info_plist_needs_tooling(self, tmp_path,
                                                        monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        empty = tmp_path / "Empty.xcresult"
        empty.mkdir()
        from ios_research.errors import StateError
        with pytest.raises(StateError) as exc:
            parse_xcresult_path(str(empty))
        assert "xcresulttool get" in exc.value.message

    def test_tool_provenance_records_without_executing(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        prov = tool_provenance()
        assert prov["xcodebuild_path"] is None
        assert prov["recorded_at"].endswith("Z")


# --- fuzz-input reproduction mapping ---------------------------------------------

class TestReproFromInput:
    def _plan(self):
        return {"name": "SampleApp",
                "targets": [{"name": "SampleAppTests", "skipped": False},
                            {"name": "SampleAppUITests", "skipped": True}]}

    def test_maps_minimized_input_to_focused_argv(self, tmp_path):
        seed = tmp_path / "minimized.bin"
        seed.write_bytes(b"\xde\xad\xbe\xef")
        mapped = map_repro_from_input(self._plan(), input_path=str(seed),
                                      project="SampleApp.xcodeproj",
                                      sanitizers=["address"])
        argv = mapped["command"]
        assert argv[:2] == ["xcodebuild", "test"]
        assert "-enableAddressSanitizer" in argv
        # Focused on the first *active* target only.
        assert argv.count("-only-testing") == 1
        assert argv[argv.index("-only-testing") + 1] == "SampleAppTests"
        assert mapped["environment"]["TEST_RUNNER_FUZZ_INPUT"] == str(seed)
        assert mapped["input_sha256"] == sha256_bytes(b"\xde\xad\xbe\xef")

    def test_actions_and_explicit_test_override(self, tmp_path):
        seed = tmp_path / "in.txt"
        seed.write_text("tap:home\nswipe:up\n", encoding="utf-8")
        mapped = map_repro_from_input(self._plan(), input_path=str(seed),
                                      project="p.xcodeproj",
                                      actions=["tap:home", "swipe:up"],
                                      test="SampleAppTests/MathTests/testAdd")
        assert mapped["only_testing"] == "SampleAppTests/MathTests/testAdd"
        assert mapped["environment"]["TEST_RUNNER_ACTIONS"] == \
            "tap:home,swipe:up"

    def test_missing_input_is_not_found(self):
        with pytest.raises(NotFoundError):
            map_repro_from_input(self._plan(),
                                 input_path="/nonexistent/input")

    def test_plan_without_active_targets_rejected(self, tmp_path):
        seed = tmp_path / "in"
        seed.write_text("x", encoding="utf-8")
        plan = {"name": "P",
                "targets": [{"name": "AllSkipped", "skipped": True}]}
        with pytest.raises(ValidationError):
            map_repro_from_input(plan, input_path=str(seed),
                                 project="p.xcodeproj")


# --- CLI contract -----------------------------------------------------------------

class TestCliAliasesAndSafety:
    def test_import_plan_and_run_tests_construct_only(self, tmp_path,
                                                      monkeypatch):
        monkeypatch.chdir(tmp_path)
        plan_id = _import_fixture_plan()
        code, out = _run_main([
            "xcode", "run-tests", plan_id, "--project",
            "SampleApp.xcodeproj", "--json"])
        assert code == 0
        envelope = json.loads(out)
        assert envelope["ok"] is True
        assert envelope["command"] == "xcode test"
        assert envelope["data"]["executed"] is False
        argv = envelope["data"]["command"]
        assert argv[:2] == ["xcodebuild", "test"]
        assert "-testPlan" in argv and "SampleApp" in argv
        assert "-enableAddressSanitizer" in argv

    def test_execute_requires_confirmation(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plan_id = _import_fixture_plan()
        code, out = _run_main([
            "xcode", "run-tests", plan_id, "--project", "p.xcodeproj",
            "--execute", "--json"])
        assert code == 6
        envelope = json.loads(out)
        assert envelope["ok"] is False
        assert "--yes" in envelope["error"]

    def test_execute_confirmed_without_xcodebuild_is_actionable(
            self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("shutil.which", lambda name: None)
        plan_id = _import_fixture_plan()
        code, out = _run_main([
            "xcode", "run-tests", plan_id, "--project", "p.xcodeproj",
            "--execute", "--yes", "--json"])
        assert code == 7
        envelope = json.loads(out)
        assert "xcodebuild unavailable" in envelope["error"]
        assert envelope["data"]["command"][0] == "xcodebuild"

    def test_parse_xcresult_alias_ingests_fixture_bundle(self, tmp_path,
                                                         monkeypatch):
        monkeypatch.chdir(tmp_path)
        from ios_research.cli import main
        assert main(["init", "--json"]) == 0
        assert _run_main(["xcode", "parse-xcresult", BUNDLE_PATH,
                          "--json"])[0] == 0
        _, out = _run_main(["xcode", "xcresult", "list", "--json"])
        record = json.loads(out)["data"]["records"][0]
        assert len(record["crashes"]) == 3
        assert record["provenance"]["formatVersion"] == "3.46"
        assert record["provenance"]["ingest"]["recorded_at"]

    def test_repro_cmd_from_minimized_input(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plan_id = _import_fixture_plan()
        seed = tmp_path / "minimized.bin"
        seed.write_bytes(b"\x00\x01")
        code, out = _run_main([
            "xcode", "repro-cmd", "--plan", plan_id, "--input",
            str(seed), "--project", "SampleApp.xcodeproj", "--json"])
        assert code == 0
        envelope = json.loads(out)
        assert envelope["command"] == "xcode repro-cmd"
        assert "-only-testing" in envelope["data"]["command"]
        assert envelope["data"]["input_sha256"] == sha256_bytes(b"\x00\x01")
