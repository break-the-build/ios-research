"""Security tests: workspace path containment and id validation (#123)."""

from __future__ import annotations

import pytest

from ios_research.errors import ValidationError
from ios_research.workspace import Workspace, validate_component


@pytest.fixture
def ws(tmp_path) -> Workspace:
    w = Workspace(tmp_path / ".ios-research")
    w.init(framework_version="0", created_at="2023-11-14T22:13:20Z")
    return w


class TestContainment:
    def test_write_json_rejects_traversal(self, ws):
        with pytest.raises(ValidationError):
            ws.write_json("../escape.json", {"a": 1})

    def test_write_bytes_rejects_traversal(self, ws):
        with pytest.raises(ValidationError):
            ws.write_bytes("../../escape.bin", b"x")

    def test_read_json_rejects_traversal(self, ws):
        with pytest.raises(ValidationError):
            ws.read_json("../../../etc/passwd")

    def test_path_rejects_absolute_escape(self, ws, tmp_path):
        outside = tmp_path / "outside.txt"
        with pytest.raises(ValidationError):
            ws.path(outside)

    def test_nested_traversal_rejected(self, ws):
        with pytest.raises(ValidationError):
            ws.path("crashes/../../evil.json")

    def test_symlink_escape_rejected(self, ws, tmp_path):
        link = ws.root / "crashes" / "link"
        target = tmp_path / "target-dir"
        target.mkdir()
        link.symlink_to(target)
        with pytest.raises(ValidationError):
            ws.write_json("crashes/link/steal.json", {})

    def test_legitimate_paths_still_work(self, ws):
        dest = ws.write_json("crashes/abc/crash.json", {"id": "abc"})
        assert dest.exists()
        assert ws.read_json("crashes/abc/crash.json") == {"id": "abc"}
        assert ws.path("fuzz/session.json").exists() is False

    def test_deep_but_contained_writes_ok(self, ws):
        ws.write_bytes("artifacts/ab/" + ("c" * 64) + ".bin", b"payload")
        assert ws.read_bytes(
            "artifacts/ab/" + ("c" * 64) + ".bin") == b"payload"


class TestComponentValidation:
    def test_rejects_separators_and_dots(self):
        for bad in ("../x", "a/b", "a\\b", "..", ".", "", ".hidden"):
            with pytest.raises(ValidationError):
                validate_component(bad)

    def test_accepts_normal_ids(self):
        assert validate_component("crash_1a2b3c") == "crash_1a2b3c"
        assert validate_component("CVE-2024-1234") == "CVE-2024-1234"


class TestStoreEntryPoints:
    def test_crash_get_rejects_traversal_id(self, ws):
        from ios_research.crashes import CrashStore
        with pytest.raises(ValidationError):
            CrashStore(ws).get("../../evil")

    def test_fuzz_get_rejects_traversal_id(self, ws):
        from ios_research.fuzz import FuzzEngine
        with pytest.raises(ValidationError):
            FuzzEngine(ws).get("../../evil")

    def test_experiment_get_rejects_traversal_id(self, ws):
        from ios_research.experiment import ExperimentStore
        with pytest.raises(ValidationError):
            ExperimentStore(ws).get("../../evil")

    def test_report_get_rejects_traversal_id(self, ws):
        from ios_research.report import ReportGenerator
        with pytest.raises(ValidationError):
            ReportGenerator(ws).get("../../evil")
