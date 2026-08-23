"""Tests for the defensive detection-signature engine and CLI."""

from __future__ import annotations

import json

import pytest

from ios_research import detection
from ios_research.commands.detect_cmd import cmd_lint, cmd_scan, cmd_list_rules
from ios_research.errors import ValidationError


def _doc(rules: list[dict]) -> dict:
    return {"schema": 1, "rules": rules}


def _rule(**over) -> dict:
    rule = {
        "name": "test_rule",
        "family": "test-family",
        "severity": "high",
        "strings": [{"id": "$a", "type": "ascii", "value": "needle"}],
        "condition": {"all": ["$a"]},
    }
    rule.update(over)
    return rule


class TestParsing:
    def test_valid_rule_parses(self):
        rules = detection.parse_rules(_doc([_rule()]))
        assert len(rules) == 1
        assert rules[0].name == "test_rule"
        assert rules[0].severity == "high"

    def test_bad_schema_rejected(self):
        with pytest.raises(ValidationError):
            detection.parse_rules({"schema": 99, "rules": [_rule()]})

    def test_empty_rules_rejected(self):
        with pytest.raises(ValidationError):
            detection.parse_rules(_doc([]))

    def test_bad_name_rejected(self):
        with pytest.raises(ValidationError):
            detection.parse_rules(_doc([_rule(name="Bad-Name")]))

    def test_duplicate_names_rejected(self):
        with pytest.raises(ValidationError):
            detection.parse_rules(_doc([_rule(), _rule()]))

    def test_duplicate_string_ids_rejected(self):
        strings = [{"id": "$a", "type": "ascii", "value": "x"},
                   {"id": "$a", "type": "ascii", "value": "y"}]
        with pytest.raises(ValidationError):
            detection.parse_rules(_doc([_rule(strings=strings)]))

    def test_unknown_condition_id_rejected(self):
        with pytest.raises(ValidationError):
            detection.parse_rules(
                _doc([_rule(condition={"all": ["$missing"]})]))

    def test_missing_condition_rejected(self):
        rule = _rule()
        del rule["condition"]
        with pytest.raises(ValidationError):
            detection.parse_rules(_doc([rule]))

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            detection.parse_rules(_doc([_rule(severity="extreme")]))

    def test_bad_hex_token_rejected(self):
        strings = [{"id": "$h", "type": "hex", "value": "ZZ QQ"}]
        with pytest.raises(ValidationError):
            detection.parse_rules(_doc([_rule(strings=strings)]))

    def test_unsupported_type_rejected(self):
        strings = [{"id": "$a", "type": "regex", "value": ".*"}]
        with pytest.raises(ValidationError):
            detection.parse_rules(_doc([_rule(strings=strings)]))

    def test_lint_ok_document_has_no_issues(self):
        assert detection.lint(_doc([_rule()])) == []


class TestMatching:
    def _one(self, **over) -> list[detection.Rule]:
        return detection.parse_rules(_doc([_rule(**over)]))

    def test_ascii_literal_matches(self):
        res = detection.scan_bytes(b"xx needle yy", self._one())
        assert len(res["matches"]) == 1
        match = res["matches"][0]
        assert match["strings"] == [{"id": "$a", "offset": 3}]

    def test_no_match(self):
        res = detection.scan_bytes(b"nothing here", self._one())
        assert res["matches"] == []

    def test_nocase_flag(self):
        res = detection.scan_bytes(
            b"NEEDLE", self._one(
                strings=[{"id": "$a", "type": "ascii", "value": "needle",
                          "nocase": True}]))
        assert len(res["matches"]) == 1
        strict = detection.scan_bytes(b"NEEDLE", self._one())
        assert strict["matches"] == []

    def test_utf16le_matches(self):
        sample = "wide".encode("utf-16-le")
        rules = self._one(
            strings=[{"id": "$w", "type": "utf16le", "value": "wide"}],
            condition={"all": ["$w"]})
        res = detection.scan_bytes(b"\x00\x00" + sample + b"\x00\x00", rules)
        assert len(res["matches"]) == 1

    def test_hex_wildcard_matches(self):
        sample = bytes([0xDE, 0xAD, 0x00, 0xBE, 0xEF])
        rule = {"id": "$h", "type": "hex", "value": "DE AD ?? BE EF"}
        hit = self._one(strings=[rule], condition={"all": ["$h"]})
        miss = self._one(strings=[dict(rule, value="DE AD ?? 99 EF")],
                         condition={"all": ["$h"]})
        assert len(detection.scan_bytes(b"junk" + sample, hit)["matches"]) == 1
        assert detection.scan_bytes(b"junk" + sample, miss)["matches"] == []

    def test_any_condition(self):
        rules = self._one(
            strings=[{"id": "$a", "type": "ascii", "value": "aaa"},
                     {"id": "$b", "type": "ascii", "value": "bbb"}],
            condition={"any": ["$a", "$b"]})
        assert detection.scan_bytes(b"has aaa", rules)["matches"]
        assert detection.scan_bytes(b"bbb too", rules)["matches"]
        assert not detection.scan_bytes(b"empty", rules)["matches"]

    def test_at_least_condition_threshold(self):
        rules = self._one(
            strings=[{"id": f"${c}", "type": "ascii", "value": c}
                     for c in ("p1", "p2", "p3")],
            condition={"at_least": 2, "of": ["$p1", "$p2", "$p3"]})
        assert not detection.scan_bytes(b"only p1", rules)["matches"]
        assert detection.scan_bytes(b"p1 and p2", rules)["matches"]

    def test_nested_condition(self):
        rules = self._one(
            strings=[{"id": "$a", "type": "ascii", "value": "a"},
                     {"id": "$b", "type": "ascii", "value": "b"},
                     {"id": "$c", "type": "ascii", "value": "c"}],
            condition={"all": ["$a", {"any": ["$b", "$c"]}]})
        assert detection.scan_bytes(b"a b", rules)["matches"]
        assert not detection.scan_bytes(b"a only", rules)["matches"]

    def test_filesize_bounds(self):
        rules = self._one(filesize={"min": 20, "max": 30})
        # 11 bytes: contains the needle but below the minimum size.
        assert detection.scan_bytes(b"x" * 5 + b"needle", rules)["matches"] == []
        # 26 bytes: within bounds and contains the needle.
        assert len(detection.scan_bytes(
            b"needle" + b"x" * 20, rules)["matches"]) == 1
        # 35 bytes: above the maximum size.
        assert detection.scan_bytes(b"needle" + b"x" * 29,
                                    rules)["matches"] == []

    def test_match_cap_is_bounded_and_ordered(self):
        rules = self._one()
        res = detection.scan_bytes(b"needle" * 50, rules)
        strings = res["matches"][0]["strings"]
        assert len(strings) == detection.MAX_MATCHES_PER_STRING
        offsets = [s["offset"] for s in strings]
        assert offsets == sorted(offsets)

    def test_scan_output_deterministic_and_hashed(self):
        data = b"deterministic sample"
        a = detection.scan_bytes(data, self._one())
        b = detection.scan_bytes(data, self._one())
        assert a == b
        assert a["sha256"] == detection.sha256_bytes(data)


class TestBuiltinSignatures:
    def test_builtin_rules_load_and_lint_clean(self):
        path = detection.builtin_rules_path()
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        assert detection.lint(doc, source=path) == []
        rules = detection.load_rules(path)
        names = [r.name for r in rules]
        assert "spyware_surveillance_exfil_combo" in names
        assert "persistence_launchd_daemon_abuse" in names

    def test_spyware_combo_requires_multiple_indicators(self):
        rules = detection.load_rules(detection.builtin_rules_path())
        single = b"AVAudioRecorder recording module"
        assert detection.scan_bytes(single, rules)["matches"] == []
        combo = (b"AVAudioRecorder AVCaptureDevice CLLocationManager "
                 b"SecItemCopyMatching POST /")
        matches = detection.scan_bytes(combo, rules)["matches"]
        assert any(m["rule"] == "spyware_surveillance_exfil_combo"
                   for m in matches)

    def test_persistence_rule_fires_on_launchd_abuse(self):
        rules = detection.load_rules(detection.builtin_rules_path())
        sample = (b"<?xml version=\"1.0\"?> <plist> "
                  b"/Library/LaunchDaemons/com.evil.agent RunAtLoad")
        matches = detection.scan_bytes(sample, rules)["matches"]
        assert any(m["rule"] == "persistence_launchd_daemon_abuse"
                   for m in matches)


# ---------------------------------------------------------------------------
# CLI handlers
# ---------------------------------------------------------------------------

def _args(**kw):
    from argparse import Namespace
    defaults = {"rules": None, "path": None}
    defaults.update(kw)
    return Namespace(**defaults)


def _write_sample(tmp_path, payload: bytes) -> str:
    p = tmp_path / "sample.bin"
    p.write_bytes(payload)
    return str(p)


def test_cli_lint_builtin_ok(ctx):
    result = cmd_lint(ctx, _args())
    assert result.ok is True
    assert result.data["issues"] == []
    assert result.data["rules"] >= 5


def test_cli_lint_custom_file_with_issue(tmp_path, ctx):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(_doc([
        _rule(condition={"all": ["$nope"]})])))
    result = cmd_lint(ctx, _args(rules=str(bad)))
    assert result.ok is False
    assert result.exit_code == 4  # VALIDATION
    assert any("$nope" in i for i in result.data["issues"])


def test_cli_scan_reports_matches_and_clean_samples(tmp_path, ctx):
    evil = _write_sample(tmp_path, b"/Library/LaunchDaemons/ RunAtLoad <?xml")
    result = cmd_scan(ctx, _args(path=evil))
    assert result.data["matches"], "expected persistence rule to fire"

    clean = _write_sample(tmp_path, b"harmless log content")
    result = cmd_scan(ctx, _args(path=clean))
    assert result.data["matches"] == []


def test_cli_scan_missing_sample_is_not_found(tmp_path, ctx):
    from ios_research.errors import NotFoundError
    with pytest.raises(NotFoundError):
        cmd_scan(ctx, _args(path=str(tmp_path / "missing.bin")))


def test_cli_list_rules(ctx):
    result = cmd_list_rules(ctx, _args())
    assert result.data["count"] >= 5
    names = {r["name"] for r in result.data["rules"]}
    assert "keychain_credential_harvest_combo" in names


class TestScanFileCap:
    def test_oversized_sample_rejected_cleanly(self, tmp_path):
        import os
        from ios_research.errors import ValidationError
        big = tmp_path / "big.bin"
        with open(big, "wb") as fh:
            fh.seek(1024 * 1024)
            fh.write(b"\0")
        rules = detection.parse_rules(_doc([_rule()]))
        with pytest.raises(ValidationError):
            detection.scan_file(str(big), rules, max_sample_bytes=4096)

    def test_cap_is_not_hit_by_equal_size_sample(self, tmp_path):
        sample = tmp_path / "ok.bin"
        sample.write_bytes(b"needle" + b"x" * 10)
        rules = detection.parse_rules(_doc([_rule()]))
        result = detection.scan_file(str(sample), rules, max_sample_bytes=16)
        assert len(result["matches"]) == 1
        assert result["size"] == 16

    def test_negative_cap_rejected(self, tmp_path):
        from ios_research.errors import ValidationError
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"a")
        rules = detection.parse_rules(_doc([_rule()]))
        with pytest.raises(ValidationError):
            detection.scan_file(str(sample), rules, max_sample_bytes=-1)

    def test_default_cap_constant_is_sane(self):
        assert detection.DEFAULT_MAX_SAMPLE_BYTES == 64 * 1024 * 1024
