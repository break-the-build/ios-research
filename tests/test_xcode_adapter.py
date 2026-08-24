"""Xcode test-plan adapter and XCResult ingestion (#36).

All tests use fixtures; no Xcode tooling is invoked anywhere in CI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ios_research.errors import NotFoundError, StateError, ValidationError
from ios_research.xcode import (
    SANITIZER_FLAGS,
    PlanStore,
    XCResultStore,
    XcodebuildBackend,
    build_test_command,
    map_repro_command,
    parse_test_plan,
    parse_xcresult_export,
    parse_xcresult_path,
)


# --- fixtures -----------------------------------------------------------------

def _plan_file(tmp_path: Path, **overrides) -> str:
    plan = {
        "testTargets": [
            {"target": {"name": "VictimAppTests"}},
            {"target": {"name": "VictimAppUITests"}, "skipped": True},
        ],
        "defaultOptions": {"targetForVariableExpansion": {}},
    }
    plan.update(overrides)
    path = tmp_path / "VictimApp.xctestplan"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return str(path)


def _xcresult_export(**extra) -> dict:
    def string_node(value: str) -> dict:
        return {"_type": {"_name": "String"}, "_value": value}

    return {
        "_type": {"_name": "ActionsInvocationRecord"},
        "_values": [
            {
                "_type": {"_name": "ActionRunSummary"},
                "_values": [
                    {"_type": {"_name": "Test Failure"},
                     "_values": [
                         string_node(
                             "AddressSanitizer: heap-buffer-overflow WRITE "
                             "of size 4 in parse_record"),
                         {"_type": {"_name": "Test Case"},
                          "_values": [string_node(
                              "VictimAppTests/ParserTests/testFuzzInput")]},
                     ]},
                    {"_type": {"_name": "Test Failure"},
                     "_values": [
                         string_node("data race detected: two threads write"),
                         {"_type": {"_name": "Test Case"},
                          "_values": [string_node(
                              "VictimAppTests/SyncTests/testRace")]},
                     ]},
                ],
            },
            {"_type": {"_name": "Target Device"},
             "_values": [
                 {"_type": {"_name": "OS Version"},
                  "_values": [string_node("17.5 (21F90)")]},
                 {"_type": {"_name": "Model"},
                  "_values": [string_node("iPhone15,2")]},
             ]},
            {"_type": {"_name": "Coverage"},
             "_values": [
                 {"_type": {"_name": "Line Coverage"}, "_value": 0.62},
             ]},
            {"_type": {"_name": "ExoticFutureDiagnostic"},
             "_values": [string_node("something new")]},
        ],
    }


# --- test plans ---------------------------------------------------------------

class TestPlans:
    def test_import_normalizes_targets_and_skip_state(self, tmp_path):
        plan = parse_test_plan(_plan_file(tmp_path))
        assert plan["name"] == "VictimApp"
        assert plan["targets"] == [
            {"name": "VictimAppTests", "skipped": False},
            {"name": "VictimAppUITests", "skipped": True},
        ]

    def test_missing_file_is_not_found(self):
        with pytest.raises(NotFoundError):
            parse_test_plan("/nonexistent/plan.xctestplan")

    def test_invalid_json_is_actionable(self, tmp_path):
        path = tmp_path / "bad.xctestplan"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ValidationError) as exc:
            parse_test_plan(str(path))
        assert "line" in str(exc.value.message)

    def test_missing_target_names_rejected(self, tmp_path):
        path = tmp_path / "p.xctestplan"
        path.write_text(json.dumps({"testTargets": [{"target": {}}]}),
                        encoding="utf-8")
        with pytest.raises(ValidationError) as exc:
            parse_test_plan(str(path))
        assert "target.name" in str(exc.value.message)

    def test_plan_store_roundtrip(self, workspace, tmp_path):
        store = PlanStore(workspace)
        saved = store.save(parse_test_plan(_plan_file(tmp_path)))
        assert store.get(saved["id"])["name"] == "VictimApp"
        assert len(store.list()) == 1

    def test_plan_store_missing_raises(self, workspace):
        with pytest.raises(NotFoundError):
            PlanStore(workspace).get("xplan_nope")


# --- command construction -------------------------------------------------------

class TestCommandConstruction:
    def test_minimal_command(self):
        plan = {"name": "VictimApp"}
        cmd = build_test_command(plan, project="VictimApp.xcodeproj")
        assert cmd == ["xcodebuild", "test", "-project", "VictimApp.xcodeproj",
                       "-testPlan", "VictimApp"]

    def test_requires_project_or_workspace(self):
        with pytest.raises(ValidationError):
            build_test_command({"name": "P"})

    def test_sanitizer_flags(self):
        plan = {"name": "P"}
        cmd = build_test_command(
            plan, project="P.xcodeproj",
            sanitizers=list(SANITIZER_FLAGS))
        for name in SANITIZER_FLAGS:
            flag, value = SANITIZER_FLAGS[name]
            assert flag in cmd
            assert cmd[cmd.index(flag) + 1] == value

    def test_unknown_sanitizer_rejected(self):
        with pytest.raises(ValidationError) as exc:
            build_test_command({"name": "P"}, project="p.xcodeproj",
                               sanitizers=["magic-dust"])
        assert "magic-dust" in str(exc.value.message)

    def test_only_testing_and_destination(self):
        cmd = build_test_command({"name": "P"}, project="p.xcodeproj",
                                 only_testing=["A/B"],
                                 destination="platform=iOS Simulator,name=X")
        assert "-only-testing" in cmd and "A/B" in cmd
        assert "-destination" in cmd

    def test_focused_repro_uses_only_the_failing_test(self):
        cmd = map_repro_command({"name": "P"}, failing_test="T/testCase",
                                project="p.xcodeproj",
                                sanitizers=["address"])
        assert cmd.count("-only-testing") == 1
        assert "-enableAddressSanitizer" in cmd


# --- xcresult ingestion ----------------------------------------------------------

class TestXcresultParsing:
    def test_normalizes_failures_sanitizers_coverage_environment(self):
        normalized = parse_xcresult_export(_xcresult_export(),
                                           source="fixture.json")
        failures = normalized["failures"]
        assert len(failures) == 2
        first = failures[0]
        assert first["test"] == "VictimAppTests/ParserTests/testFuzzInput"
        assert first["sanitizer"] == "address"
        # WRITE is preserved in the classification hint.
        assert first["classification_hint"] == "OUT_OF_BOUNDS_WRITE"
        assert failures[1]["sanitizer"] == "thread"
        assert normalized["environment"]["os_version"] == "17.5 (21F90)"
        assert normalized["environment"]["model"] == "iPhone15,2"
        assert normalized["coverage"]["entries"]["Line Coverage"] == 0.62

    def test_unrecognized_issue_types_are_reported_not_dropped(self):
        normalized = parse_xcresult_export(_xcresult_export())
        kinds = [u["issue_type"] for u in normalized["unrecognized"]]
        assert "ExoticFutureDiagnostic" in kinds

    def test_non_object_export_rejected(self):
        with pytest.raises(ValidationError):
            parse_xcresult_export([1, 2, 3])

    def test_store_roundtrip_keeps_raw_export(self, workspace):
        store = XCResultStore(workspace)
        raw = json.dumps(_xcresult_export()).encode()
        normalized = parse_xcresult_export(_xcresult_export(), source="f.json")
        saved = store.save(normalized, raw)
        assert store.get(saved["id"])["failures"]
        raw_rel = f"xcode/xcresults/{saved['id']}.raw.json"
        assert workspace.path(raw_rel).exists()

    def test_parse_path_rejects_garbage_json(self, tmp_path):
        bad = tmp_path / "export.json"
        bad.write_text("definitely not json", encoding="utf-8")
        with pytest.raises(ValidationError):
            parse_xcresult_path(str(bad))

    def test_parse_path_missing_file(self, tmp_path):
        with pytest.raises(NotFoundError):
            parse_xcresult_path(str(tmp_path / "missing.json"))


# --- backend availability (no Xcode in CI) ----------------------------------------

class TestBackend:
    def test_blocker_when_xcodebuild_missing(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        backend = XcodebuildBackend()
        assert backend.available() is False
        assert "xcode-select" in backend.blocker()

    def test_run_without_tool_is_actionable(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        with pytest.raises(StateError) as exc:
            XcodebuildBackend().run(["xcodebuild", "test"])
        assert "--dry-run" in str(exc.value.message)

    def test_bundle_without_toolchain_suggests_json_export(self, tmp_path,
                                                           monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        bundle = tmp_path / "result.xcresult"
        bundle.mkdir()
        with pytest.raises(StateError) as exc:
            parse_xcresult_path(str(bundle))
        assert "xcresulttool get" in str(exc.value.message)


# --- CLI envelope contract ---------------------------------------------------------

def _run_main(argv):
    from ios_research.cli import main
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


def test_cli_plan_import_and_show_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    plan_path = _plan_file(tmp_path)
    from ios_research.cli import main
    assert main(["init", "--json"]) == 0
    assert main(["xcode", "plan", "import", plan_path, "--json"]) == 0
    code, out = _run_main(["xcode", "plan", "list", "--json"])
    assert code == 0
    envelope = json.loads(out)
    assert envelope["ok"] is True and envelope["command"] == "xcode plan list"
    assert envelope["data"]["count"] == 1


def test_cli_test_dry_run_emits_command(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    plan_path = _plan_file(tmp_path)
    from ios_research.cli import main
    main(["init", "--json"])
    main(["xcode", "plan", "import", plan_path, "--json"])
    _, listing = _run_main(["xcode", "plan", "list", "--json"])
    plan_id = json.loads(listing)["data"]["plans"][0]["id"]
    code, out = _run_main([
        "xcode", "test", plan_id, "--project", "App.xcodeproj",
        "--sanitizer", "address", "--only-testing", "T/case",
        "--dry-run", "--json"])
    assert code == 0
    envelope = json.loads(out)
    cmd = envelope["data"]["command"]
    assert cmd[:2] == ["xcodebuild", "test"]
    assert "-enableAddressSanitizer" in cmd and "YES" in cmd
    assert envelope["data"]["executed"] is False


def test_cli_xcresult_parse_and_repro(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    plan_path = _plan_file(tmp_path)
    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps(_xcresult_export()), encoding="utf-8")
    from ios_research.cli import main
    main(["init", "--json"])
    main(["xcode", "plan", "import", plan_path, "--json"])
    _, listing = _run_main(["xcode", "plan", "list", "--json"])
    plan_id = json.loads(listing)["data"]["plans"][0]["id"]
    assert main(["xcode", "xcresult", "parse", str(export_path), "--json"]) == 0
    _, records = _run_main(["xcode", "xcresult", "list", "--json"])
    record_id = json.loads(records)["data"]["records"][0]["id"]
    code, out = _run_main([
        "xcode", "repro", record_id, "--plan", plan_id,
        "--project", "App.xcodeproj", "--json"])
    assert code == 0
    envelope = json.loads(out)
    assert "-only-testing" in envelope["data"]["command"]
    assert "VictimAppTests/ParserTests/testFuzzInput" in \
        envelope["data"]["command"]
