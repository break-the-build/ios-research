"""Authorized IPA static/configuration analysis (#44)."""

from __future__ import annotations

import plistlib
import zipfile

import pytest

from ios_research.errors import ValidationError
from ios_research.ipa_analysis import analyze_bundle, load_rule_pack


def _info_plist(**overrides) -> bytes:
    info = {
        "CFBundleIdentifier": "com.example.fixture",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }
    info.update(overrides)
    return plistlib.dumps(info)


def _profile(get_task_allow=True) -> bytes:
    profile = plistlib.dumps({
        "Name": "fixture",
        "Entitlements": {"get-task-allow": get_task_allow},
    })
    return b"-----BEGIN CMS-----\x00\x01" + profile


def _app_dir(tmp_path):
    app = tmp_path / "Fixture.app"
    (app / "_CodeSignature").mkdir(parents=True)
    (app / "Info.plist").write_bytes(_info_plist())
    (app / "embedded.mobileprovision").write_bytes(_profile())
    (app / "_CodeSignature" / "CodeResources").write_bytes(b"sig")
    return app


def test_flags_ats_exception_and_debug_entitlement(tmp_path):
    out = analyze_bundle(_app_dir(tmp_path))
    ids = {f["rule_id"] for f in out["findings"]}
    assert "IPA-ATS-003" in ids
    assert "IPA-ENT-004" in ids
    ats = next(f for f in out["findings"]
               if f["rule_id"] == "IPA-ATS-003")
    assert ats["severity"] == "high"
    assert ats["remediation"]


def test_unsigned_bundle_is_flagged_and_clean_bundle_is_quiet(tmp_path):
    unsigned = tmp_path / "Unsigned.app"
    unsigned.mkdir()
    (unsigned / "Info.plist").write_bytes(
        _info_plist(NSAppTransportSecurity={"NSAllowsArbitraryLoads": False}))
    out = analyze_bundle(unsigned)
    ids = {f["rule_id"] for f in out["findings"]}
    assert "IPA-SIGN-001" in ids
    assert "IPA-ATS-003" not in ids

    signed = tmp_path / "Signed.app"
    (signed / "_CodeSignature").mkdir(parents=True)
    (signed / "Info.plist").write_bytes(
        _info_plist(NSAppTransportSecurity={"NSAllowsArbitraryLoads": False}))
    (signed / "_CodeSignature" / "CodeResources").write_bytes(b"x")
    clean = analyze_bundle(signed)
    assert clean["findings"] == []


def test_ipa_zip_inputs_equivalent_to_dir(tmp_path):
    app = tmp_path / "Zipped.app"
    (app / "Frameworks").mkdir(parents=True)
    (app / "Info.plist").write_bytes(_info_plist())
    (app / "libweird.dylib").write_bytes(b"\xcf\xfa")
    ipa = tmp_path / "Fixture.ipa"
    with zipfile.ZipFile(ipa, "w") as bundle:
        for file in sorted(app.rglob("*")):
            if file.is_file():
                bundle.write(file, file.relative_to(app.parent))
    from_dir = analyze_bundle(app)
    from_zip = analyze_bundle(ipa)
    assert [f["rule_id"] for f in from_dir["findings"]] == \
        [f["rule_id"] for f in from_zip["findings"]]
    assert "IPA-FWK-006" in {f["rule_id"] for f in from_zip["findings"]}


def test_findings_are_deterministic_and_sorted(tmp_path):
    app = _app_dir(tmp_path)
    a = analyze_bundle(app)
    b = analyze_bundle(app)
    assert a == b
    rule_ids = [f["rule_id"] for f in a["findings"]]
    assert rule_ids == sorted(rule_ids)


def test_cleartext_endpoints_detected_in_binary(tmp_path):
    binary = tmp_path / "Blob.app"
    sig = binary / "_CodeSignature"
    sig.mkdir(parents=True)
    (binary / "Info.plist").write_bytes(
        _info_plist(NSAppTransportSecurity={"NSAllowsArbitraryLoads": False}))
    (sig / "CodeResources").write_bytes(b"x")
    (binary / "AppBinary").write_bytes(
        b"data http://insecure.example.test more")
    out = analyze_bundle(binary)
    net = [f for f in out["findings"] if f["rule_id"] == "IPA-NET-005"]
    assert net and "http://insecure.example.test" in net[0]["location"]


def test_extra_rule_packs_with_provenance_and_suppressions(tmp_path):
    app = _app_dir(tmp_path)
    pack = {
        "name": "team-rules",
        "version": "2.0.1",
        "rules": [{
            "rule_id": "TEAM-CFG-9001",
            "severity": "low",
            "match": {"plist_suffix": "Info.plist",
                      "key": "CFBundleIdentifier",
                      "equals": "com.example.fixture"},
            "remediation": "rotate the fixture id",
            "rationale": "policy example",
        }],
        "suppressions": [{"rule_id": "TEAM-CFG-9001"}],
    }
    pack_path = tmp_path / "pack.json"
    import json
    pack_path.write_text(json.dumps(pack))
    rules, suppressions, provenance = load_rule_pack(pack_path)
    assert provenance["version"] == "2.0.1"
    assert provenance["sha256"]

    out = analyze_bundle(app, extra_rules=rules,
                         suppressions=suppressions)
    team = [f for f in out["findings"]
            if f["rule_id"] == "TEAM-CFG-9001"]
    assert len(team) == 1
    assert team[0]["suppressed"] is True      # visible but marked
    assert out["extra_rules"] == 1


def test_malformed_bundles_fail_safely(tmp_path):
    bad_zip = tmp_path / "bad.ipa"
    bad_zip.write_bytes(b"not a zip")
    with pytest.raises(ValidationError, match="malformed archive"):
        analyze_bundle(bad_zip)
    bad_plist = tmp_path / "Bad.app"
    bad_plist.mkdir()
    (bad_plist / "Info.plist").write_bytes(b"\x00\x01junk")
    with pytest.raises(ValidationError):
        analyze_bundle(bad_plist)
    other = tmp_path / "bundle.txt"
    other.write_text("hi")
    with pytest.raises(ValidationError, match="unsupported bundle"):
        analyze_bundle(other)
    with pytest.raises(ValidationError, match="bundle not found"):
        analyze_bundle(tmp_path / "missing.app")


def test_secret_shaped_values_redacted(tmp_path):
    app = tmp_path / "Secret.app"
    (app / "_CodeSignature").mkdir(parents=True)
    (app / "Info.plist").write_bytes(plistlib.dumps({
        "api_password": "hunter2",
        "NSAppTransportSecurity": {},
    }))
    (app / "_CodeSignature" / "CodeResources").write_bytes(b"s")
    out = analyze_bundle(app)
    blob = str(out)
    assert "hunter2" not in blob
