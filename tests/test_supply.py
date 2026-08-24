"""Tests for offline supply-chain vetting (#72)."""

from __future__ import annotations

import hashlib
import json

import pytest

from ios_research.cli import main
from ios_research.errors import NotFoundError
from ios_research.supply import (
    SupplyStore, audit_requirements, parse_requirements, scan_behavior,
    verify_lock,
)

REQS = """
# pinned with hash
requests==2.31.0 --hash=sha256:abc
flask==3.0.0
# ranged, marker stripped
pyyaml>=5.4,<6 ; python_version < "3.10"
attrs[tests]~=23.1
--index-url https://example.invalid/simple
==1.2.3-no-name
"""


# --- requirements parsing ---------------------------------------------------------
def test_parse_requirements_pins_ranges_and_markers():
    parsed = parse_requirements(REQS)
    by_name = {e["name"]: e for e in parsed["entries"]}
    assert set(by_name) == {"requests", "flask", "pyyaml", "attrs"}
    assert by_name["requests"]["spec"] == "==2.31.0"
    assert by_name["requests"]["pinned"] is True
    assert by_name["requests"]["hashes"] is True
    assert by_name["flask"]["pinned"] is True
    assert by_name["flask"]["hashes"] is False
    assert by_name["pyyaml"]["spec"] == ">=5.4,<6"
    assert by_name["pyyaml"]["pinned"] is False
    assert by_name["attrs"]["spec"] == "~=23.1"


def test_parse_requirements_options_comments_malformed_empty():
    parsed = parse_requirements(REQS)
    assert parsed["options"] == 1
    assert parsed["skipped"] == 1
    assert parse_requirements("  \n# only a comment\n") == {
        "entries": [], "options": 0, "skipped": 0}


# --- requirements auditing ----------------------------------------------------------
def test_audit_requirements_empty_is_low_risk():
    result = audit_requirements("")
    assert result == {"total": 0, "pinned": 0, "unpinned": [], "hashed": 0,
                      "unpinned_pct": 0, "skipped": 0, "risk": "low"}


def test_audit_requirements_risk_thresholds():
    high = audit_requirements("a==1\nb>=2\n")
    assert high["risk"] == "high"
    assert high["unpinned"] == ["b"]
    assert high["unpinned_pct"] == 50
    medium = audit_requirements("a==1\nb==2\n")
    assert medium["risk"] == "medium"
    assert medium["hashed"] == 0
    low = audit_requirements("a==1 --hash=sha256:xyz\n")
    assert low["risk"] == "low"
    all_unpinned = audit_requirements("a\nb\n")
    assert all_unpinned["unpinned_pct"] == 100


# --- behavioral scan ------------------------------------------------------------------
def _tree(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "evil.py").write_text(
        "import os\n"
        "def boom(cmd):\n"
        "    os.system(cmd)\n"
        "    eval('1+1')\n")
    (pkg / "sneaky.py").write_text(
        f"PAYLOAD = '{'A' * 250}'\n"
        "import builtins\n"
        "getattr(builtins, 'dict').fromkeys(['a'])\n")
    (pkg / "clean.py").write_text("VALUE = 41 + 1\n")


def test_scan_detects_risky_calls(tmp_path):
    _tree(tmp_path)
    result = scan_behavior(tmp_path)
    calls = {(f["file"], f["call"]) for f in result["findings"]
             if f["kind"] == "risky-call"}
    assert ("pkg/evil.py", "os.system") in calls
    assert ("pkg/evil.py", "eval") in calls
    assert result["risk"] == "high"
    assert result["files_scanned"] == 3


def test_scan_detects_obfuscation_and_getattr_chain(tmp_path):
    _tree(tmp_path)
    result = scan_behavior(tmp_path)
    kinds = {f["kind"] for f in result["findings"]}
    assert {"obfuscation", "dynamic-attr"} <= kinds
    dyn = [f for f in result["findings"] if f["kind"] == "dynamic-attr"][0]
    assert dyn["file"] == "pkg/sneaky.py"
    obf = [f for f in result["findings"] if f["kind"] == "obfuscation"][0]
    assert obf["file"] == "pkg/sneaky.py"
    assert result["by_kind"].get("risky-call", 0) >= 1


def test_scan_clean_tree_is_low(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    result = scan_behavior(tmp_path)
    assert result == {"files_scanned": 1, "truncated": False,
                      "syntax_errors": 0, "findings": [], "by_kind": {},
                      "risk": "low"}


def test_scan_prunes_vendored_dirs(tmp_path):
    _tree(tmp_path)
    vendored = tmp_path / ".venv" / "lib"
    vendored.mkdir(parents=True)
    (vendored / "bad.py").write_text("os.system('x')\n")
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "c.py").write_text("eval('2')\n")
    result = scan_behavior(tmp_path)
    assert all(not f["file"].startswith((".venv/", "__pycache__/"))
               for f in result["findings"])
    assert result["files_scanned"] == 3


def test_scan_counts_syntax_errors_and_respects_max_files(tmp_path):
    _tree(tmp_path)
    (tmp_path / "broken.py").write_text("def oops(:\n")
    result = scan_behavior(tmp_path)
    assert result["syntax_errors"] == 1
    assert result["findings"] == sorted(
        result["findings"],
        key=lambda f: (f["file"], f["line"], f.get("call", "")))

    flat = tmp_path / "flat"
    flat.mkdir()
    for i in range(3):
        (flat / f"f{i}.py").write_text("X = 1\n")
    truncated = scan_behavior(flat, max_files=2)
    assert truncated["truncated"] is True
    assert truncated["files_scanned"] == 2


# --- lockfile verification -------------------------------------------------------------
def _lock_file(tmp_path, payload="print('ok')\n"):
    target = tmp_path / "mod.py"
    target.write_text(payload)
    digest = hashlib.sha256(payload.encode()).hexdigest()
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps(
        {"files": [{"path": "mod.py", "sha256": digest}]}))
    return lock


def test_verify_lock_ok(tmp_path):
    result = verify_lock(_lock_file(tmp_path), tmp_path)
    assert result == {"verified": True, "checked": 1, "drifted": [],
                      "missing": []}


def test_verify_lock_detects_drift(tmp_path):
    lock = _lock_file(tmp_path)
    (tmp_path / "mod.py").write_text("print('tampered')\n")
    result = verify_lock(lock, tmp_path)
    assert result["verified"] is False
    assert len(result["drifted"]) == 1
    drift = result["drifted"][0]
    assert drift["path"] == "mod.py"
    assert drift["actual"] != drift["expected"]


def test_verify_lock_reports_missing_entries(tmp_path):
    lock = _lock_file(tmp_path)
    doc = json.loads(lock.read_text())
    doc["files"].append({"path": "gone.py",
                         "sha256": "0" * 64})
    lock.write_text(json.dumps(doc))
    (tmp_path / "mod.py").unlink()
    result = verify_lock(lock, tmp_path)
    assert result["verified"] is False
    assert sorted(result["missing"]) == ["gone.py", "mod.py"]
    assert result["drifted"] == []


def test_verify_lock_missing_lockfile_raises(tmp_path):
    with pytest.raises(NotFoundError):
        verify_lock(tmp_path / "absent.json", tmp_path)


# --- store -------------------------------------------------------------------------------
def test_supply_store_roundtrip(workspace):
    store = SupplyStore(workspace)
    rec = store.create("audit", "reqs.txt", {"total": 1, "risk": "low"})
    assert rec.id.startswith("sup_")
    loaded = store.get(rec.id)
    assert loaded.to_dict() == rec.to_dict()
    assert [r.id for r in store.list()] == [rec.id]
    with pytest.raises(NotFoundError):
        store.get("sup_nope")


# --- CLI surface ---------------------------------------------------------------------------
def _run(capsys, argv, expected_rc=None):
    rc = main([*argv, "--json"])
    payload = json.loads(capsys.readouterr().out.strip())
    if expected_rc is not None:
        assert rc == expected_rc
    return rc, payload


def test_cli_supply_audit_and_scan_roundtrip(ctx, capsys, tmp_path):
    ws = str(ctx.workspace().root)
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("requests==2.31.0 --hash=sha256:abc\n")
    _, audit = _run(capsys, ["supply", "audit", "--requirements", str(reqs),
                             "--workspace", ws], expected_rc=0)
    assert audit["ok"] is True and audit["data"]["risk"] == "low"
    assert audit["data"]["id"].startswith("sup_")

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "m.py").write_text("import os\nos.system('ls')\n")
    _, scan = _run(capsys, ["supply", "scan", str(pkg),
                            "--workspace", ws], expected_rc=0)
    assert scan["data"]["risk"] == "high"
    assert scan["data"]["files_scanned"] == 1

    _, listing = _run(capsys, ["supply", "list", "--workspace", ws])
    assert listing["data"]["count"] == 2
    record_id = audit["data"]["id"]
    _, shown = _run(capsys, ["supply", "show", record_id,
                             "--workspace", ws])
    assert shown["data"]["kind"] == "audit"


def test_cli_supply_verify_exit_codes(ctx, capsys, tmp_path):
    ws = str(ctx.workspace().root)
    good = tmp_path / "good"
    good.mkdir()
    _, ok = _run(capsys, ["supply", "verify", "--lockfile",
                          str(_lock_file(good)), "--root", str(good),
                          "--workspace", ws], expected_rc=0)
    assert ok["data"]["verified"] is True and ok["ok"] is True

    bad = tmp_path / "bad"
    bad.mkdir()
    lock = _lock_file(bad)
    (bad / "mod.py").write_text("print('drifted')\n")
    rc, drifted = _run(capsys, ["supply", "verify", "--lockfile",
                                str(lock), "--root", str(bad),
                                "--workspace", ws])
    assert rc == 7
    assert drifted["ok"] is True and drifted["data"]["verified"] is False

    missing = tmp_path / "missing.json"
    rc, payload = _run(capsys, ["supply", "verify", "--lockfile",
                                str(missing), "--root", str(tmp_path),
                                "--workspace", ws])
    assert rc == 3
    assert payload["ok"] is False
