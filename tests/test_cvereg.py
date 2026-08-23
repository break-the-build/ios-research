"""Tests for known-CVE patch-regression validation."""

from __future__ import annotations

import pytest

from ios_research.commands.cve_cmd import (
    cmd_add, cmd_catalog, cmd_install_catalog, cmd_list, cmd_remove,
    cmd_validate,
)
from ios_research.cvereg import (
    CveRegistry, decode_input_hex, install_builtin_catalog, validate_entry,
)
from ios_research.errors import (
    NotFoundError, StateError, UsageError, ValidationError,
)


@pytest.fixture
def registry(workspace) -> CveRegistry:
    return CveRegistry(workspace)


def _args(**kw):
    from argparse import Namespace
    base = {"cve_id": None, "title": "", "input_hex": None,
            "input_file": None, "vulnerable": "", "fixed": "",
            "reference": "", "note": ""}
    base.update(kw)
    return Namespace(**base)


class TestRegistry:
    def test_add_and_get_roundtrip(self, workspace):
        reg = CveRegistry(workspace)
        reg.add(cve_id="CVE-2024-9999", title="example",
                input_data=b"\x01\x02", vulnerable_targets=["mock:parser"],
                fixed_targets=[])
        entry = reg.get("CVE-2024-9999")
        assert entry.title == "example"
        assert entry.input_bytes() == b"\x01\x02"

    def test_get_missing_raises_not_found(self, workspace):
        with pytest.raises(NotFoundError):
            CveRegistry(workspace).get("CVE-0000-0000")

    def test_duplicate_id_rejected(self, workspace):
        reg = CveRegistry(workspace)
        kw = dict(cve_id="CVE-1-2", title="t", input_data=b"x",
                  vulnerable_targets=["mock:parser"], fixed_targets=[])
        reg.add(**kw)
        with pytest.raises(StateError):
            reg.add(**kw)

    def test_invalid_ids_rejected(self, workspace):
        reg = CveRegistry(workspace)
        for bad in ("", "../evil", "has space"):
            with pytest.raises(Exception):
                reg.add(cve_id=bad, title="t", input_data=b"x",
                        vulnerable_targets=["mock:parser"], fixed_targets=[])

    def test_needs_at_least_one_target(self, workspace):
        with pytest.raises(ValidationError):
            CveRegistry(workspace).add(
                cve_id="CVE-1-3", title="t", input_data=b"x",
                vulnerable_targets=[], fixed_targets=[])

    def test_remove_missing_raises(self, workspace):
        with pytest.raises(NotFoundError):
            CveRegistry(workspace).remove("NOPE-1")

    def test_input_bound_enforced(self, workspace):
        with pytest.raises(Exception):
            CveRegistry(workspace).add(
                cve_id="CVE-BIG-1", title="too big",
                input_data=b"A" * 5000,
                vulnerable_targets=["mock:parser"], fixed_targets=[])


class TestDecodeInputHex:
    def test_accepts_spaced_hex(self):
        assert decode_input_hex("DE AD 01") == b"\xde\xad\x01"

    def test_rejects_garbage(self):
        with pytest.raises(Exception):
            decode_input_hex("zzz")

    def test_rejects_empty(self):
        with pytest.raises(Exception):
            decode_input_hex("   ")

    def test_rejects_oversize(self):
        with pytest.raises(Exception):
            decode_input_hex("41" * 5000)


class TestValidation:
    def test_builtin_analogs_pass(self, tmp_path):
        from ios_research.workspace import Workspace
        from ios_research import __version__
        ws = Workspace(tmp_path / ".ios-research")
        ws.init(framework_version=__version__, created_at="2023-11-14T22:13:20Z")
        reg = CveRegistry(ws)
        added = install_builtin_catalog(reg)
        assert len(added) == 3
        for entry_id in added:
            report = validate_entry(reg.get(entry_id))
            assert report["passed"] is True, report
            assert report["targets"], "per-target rows expected"
            for row in report["targets"]:
                assert row["status"] == "pass"
                if row["expectation"] == "crash":
                    assert row["observed"] == "crash"
                    assert row["classification"] != ""
                else:
                    assert row["observed"] in ("accepted", "rejected")

    def test_fixed_target_still_crashing_fails(self, workspace):
        reg = CveRegistry(workspace)
        # Record type 0xFF crashes BOTH mock versions, so declaring it as
        # fixed on mock:parser must fail validation.
        reg.add(cve_id="MOCK-NEGCTRL-001", title="negative control",
                input_data=b"MOCK\x01\xff\x00\x02ok",
                vulnerable_targets=["mock:parser"],
                fixed_targets=["mock:parser"])
        report = validate_entry(reg.get("MOCK-NEGCTRL-001"))
        assert report["passed"] is False

    def test_unregistered_target_is_skipped_and_fails(self, workspace):
        reg = CveRegistry(workspace)
        reg.add(cve_id="CVE-GHOST-1", title="ghost target",
                input_data=b"anything", vulnerable_targets=["no:such-target"],
                fixed_targets=[])
        report = validate_entry(reg.get("CVE-GHOST-1"))
        assert report["passed"] is False
        assert report["targets"][0]["status"] == "skipped"

    def test_validation_is_deterministic(self, workspace):
        reg = CveRegistry(workspace)
        reg.add(cve_id="CVE-DET-1", title="determinism",
                input_data=b"MOCK\x01\xff\x00\x02ok",
                vulnerable_targets=["mock:parser"], fixed_targets=[])
        a = validate_entry(reg.get("CVE-DET-1"))
        b = validate_entry(reg.get("CVE-DET-1"))
        assert a == b

    def test_install_catalog_is_idempotent(self, workspace):
        reg = CveRegistry(workspace)
        first = install_builtin_catalog(reg)
        second = install_builtin_catalog(reg)
        assert first and second == []


class TestCliHandlers:
    def test_catalog_lists_analogs(self, ctx):
        result = cmd_catalog(ctx, _args())
        ids = {a["id"] for a in result.data["analogs"]}
        assert "MOCK-NULLDISPATCH-001" in ids
        assert result.data["count"] >= 3

    def test_install_list_validate_flow(self, ctx):
        cmd_install_catalog(ctx, _args())
        listing = cmd_list(ctx, _args())
        assert listing.data["count"] == 3
        result = cmd_validate(ctx, _args())
        assert result.ok is True
        assert all(r["passed"] for r in result.data["reports"])

    def test_validate_single_entry(self, ctx):
        cmd_install_catalog(ctx, _args())
        result = cmd_validate(ctx, _args(cve_id="MOCK-ASSERT-001"))
        assert result.data["reports"][0]["id"] == "MOCK-ASSERT-001"

    def test_validate_failure_sets_not_ok(self, ctx, workspace):
        reg = CveRegistry(workspace)
        reg.add(cve_id="MOCK-NEGCTRL-002", title="bad",
                input_data=b"MOCK\x01\xff\x00\x02ok",
                vulnerable_targets=["mock:parser"],
                fixed_targets=["mock:parser"])
        result = cmd_validate(ctx, _args(cve_id="MOCK-NEGCTRL-002"))
        assert result.ok is False

    def test_add_via_cli_with_hex(self, ctx):
        result = cmd_add(ctx, _args(
            cve_id="CVE-2024-0001", title="cli add",
            input_hex="4d4f434b 01 ff 00 02 6f 6b",
            vulnerable="mock:parser", fixed="mock:parser-v2"))
        assert result.data["entry"]["id"] == "CVE-2024-0001"

    def test_add_requires_exactly_one_input_source(self, ctx):
        with pytest.raises(UsageError):
            cmd_add(ctx, _args(cve_id="CVE-X", title="t",
                               input_hex="41", input_file="a.bin"))

    def test_add_via_cli_with_file(self, ctx, tmp_path):
        sample = tmp_path / "poc.bin"
        sample.write_bytes(b"MOCK\x01\xff\x00\x02ok")
        result = cmd_add(ctx, _args(cve_id="CVE-FILE-1", title="from file",
                                    input_file=str(sample),
                                    vulnerable="mock:parser"))
        assert result.data["entry"]["sha256"] != ""
        assert len(bytes.fromhex(result.data["entry"]["input_hex"])) == 10

    def test_remove_via_cli(self, ctx):
        cmd_install_catalog(ctx, _args())
        cmd_remove(ctx, _args(cve_id="MOCK-ASSERT-001"))
        listing = cmd_list(ctx, _args())
        ids = {e["id"] for e in listing.data["entries"]}
        assert "MOCK-ASSERT-001" not in ids
