"""Phase 00 tests: foundation, interfaces, safety, CLI framework."""

from __future__ import annotations

import json

import pytest

from ios_research import __version__
from ios_research.cli import main, build_parser
from ios_research.config import Config, DEFAULT_CONFIG
from ios_research.errors import ExitCode, SafetyError
from ios_research.hashing import config_hash, sha256_bytes, canonical_json
from ios_research.ids import make_id
from ios_research.logging_util import redact
from ios_research import safety
from ios_research.targets import create, list_targets
from ios_research.targets.base import Outcome
from ios_research.workspace import Workspace, SUBDIRS


# --- hashing / ids ---------------------------------------------------------
def test_sha256_is_stable():
    assert sha256_bytes(b"abc") == sha256_bytes(b"abc")
    assert len(sha256_bytes(b"abc")) == 64


def test_config_hash_is_order_independent():
    assert config_hash({"a": 1, "b": 2}) == config_hash({"b": 2, "a": 1})


def test_canonical_json_sorts_keys():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_make_id_is_deterministic():
    a = make_id("experiment", "x", "y")
    b = make_id("experiment", "x", "y")
    assert a == b and a.startswith("exp_")
    assert make_id("experiment", "x", "z") != a


# --- config ---------------------------------------------------------------
def test_config_defaults_and_get():
    cfg = Config()
    assert cfg.get("fuzz.workers") == DEFAULT_CONFIG["fuzz"]["workers"]
    assert cfg.get("missing.key", "d") == "d"


def test_config_set_is_immutable():
    cfg = Config()
    cfg2 = cfg.set("fuzz.workers", 4)
    assert cfg.get("fuzz.workers") == 1
    assert cfg2.get("fuzz.workers") == 4


def test_config_deep_merge_preserves_sibling_defaults():
    # Overriding one nested key must not drop the other defaults under it
    # (guards against a shallow replace instead of a deep merge).
    cfg = Config({"fuzz": {"workers": 5}})
    assert cfg.get("fuzz.workers") == 5
    assert cfg.get("fuzz.max_cases") == DEFAULT_CONFIG["fuzz"]["max_cases"]
    assert cfg.get("fuzz.strategy_weights") is not None
    # A deeper override still preserves siblings.
    cfg2 = cfg.set("fuzz.strategy_weights.byte", 3)
    assert cfg2.get("fuzz.strategy_weights.byte") == 3
    assert cfg2.get("fuzz.strategy_weights.structure_aware") == \
        DEFAULT_CONFIG["fuzz"]["strategy_weights"]["structure_aware"]


def test_config_hash_is_distinct_and_fixed_width():
    # The hash suffix must be wide enough to avoid collisions across configs.
    cfg = Config()
    suffix = cfg.hash.split("_", 1)[1]
    assert len(suffix) == 16
    hashes = {Config().set("fuzz.workers", n).hash for n in range(64)}
    assert len(hashes) == 64          # all distinct — no truncation collisions


# --- safety ---------------------------------------------------------------
def test_safety_blocks_forbidden_capability():
    with pytest.raises(SafetyError):
        safety.assert_allowed("weaponized_exploit_chain")


def test_safety_allows_permitted_capability():
    safety.assert_allowed("fuzzing")  # must not raise


def test_redact_hides_secrets():
    cleaned = redact({"api_key": "xyz", "nested": {"token": "t", "ok": 1}})
    assert cleaned["api_key"] == "***REDACTED***"
    assert cleaned["nested"]["token"] == "***REDACTED***"
    assert cleaned["nested"]["ok"] == 1


# --- workspace ------------------------------------------------------------
def test_workspace_init_creates_layout(tmp_path):
    ws = Workspace(tmp_path / ".ios-research")
    ws.init(framework_version=__version__, created_at="t")
    assert ws.initialized
    for sub in SUBDIRS:
        assert ws.dir(sub).is_dir()


def test_workspace_atomic_json_roundtrip(workspace):
    workspace.write_json("experiments/x.json", {"a": 1})
    assert workspace.read_json("experiments/x.json") == {"a": 1}


def test_workspace_locate(tmp_path, monkeypatch):
    ws = Workspace(tmp_path / ".ios-research")
    ws.init(framework_version=__version__, created_at="t")
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    monkeypatch.chdir(sub)
    found = Workspace.locate()
    assert found is not None and found.root == ws.root


# --- targets --------------------------------------------------------------
def test_mock_parser_registered():
    ids = [t["id"] for t in list_targets()]
    assert "mock:parser" in ids


def test_mock_parser_accepts_valid_record():
    target = create("mock:parser")
    data = b"MOCK" + bytes([1, 1]) + (2).to_bytes(2, "big") + b"ok"
    res = target.execute(data)
    assert res.outcome == Outcome.ACCEPTED


def test_mock_parser_rejects_bad_magic():
    res = create("mock:parser").execute(b"XXXX....")
    assert res.outcome == Outcome.REJECTED


def test_mock_parser_timeout_on_oversized_declared_length():
    # declared_length >= 0xF000 with a matching payload takes the slow path.
    payload = b"\x00" * 0xF000
    data = b"MOCK" + bytes([1, 1]) + (0xF000).to_bytes(2, "big") + payload
    res = create("mock:parser").execute(data)
    assert res.outcome == Outcome.TIMEOUT


def test_null_dereference_has_null_faulting_address():
    res = create("mock:parser").execute(b"MOCK\x01\xff\x00\x00")
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "NULL_DEREFERENCE"
    assert res.diagnostics.faulting_address == "0x0000000000000000"


def test_non_null_crash_has_nonnull_faulting_address():
    res = create("mock:parser").execute(b"MOCK\x01\x01\xff\xff")   # OOB read
    assert res.diagnostics.faulting_address != "0x0000000000000000"


# --- CLI framework --------------------------------------------------------
def test_cli_version(capsys):
    code = main(["version"])
    out = capsys.readouterr().out
    assert code == ExitCode.OK
    assert __version__ in out


def test_cli_version_json(capsys):
    code = main(["version", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ok"] is True
    assert payload["data"]["version"] == __version__


def test_cli_no_command_prints_help():
    assert main([]) == ExitCode.USAGE


def test_cli_info_reports_boundary(capsys):
    main(["info", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["safety_boundary"]["authorized_research_only"] is True


def test_parser_builds():
    assert build_parser() is not None
