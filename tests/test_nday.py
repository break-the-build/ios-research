"""Tests for IPSW symbol patch-diffing (`nday` command group)."""

from __future__ import annotations

import json

import pytest

from ios_research.cli import main
from ios_research.errors import ExitCode, NotFoundError
from ios_research.ipswdiff import (
    NdayEngine, NdayStore, diff_symbols, parse_nm_symbols,
    parse_nm_symbols_with_skipped, prioritize,
)

_NM_A = """
# build A symbol dump
0000000000100000 1f4 T _os_parse_header
0000000000100200 a0 T _os_validate_blob
0000000000100300 64 D _os_table
0000000000100400 t _os_static_helper
0000000000100500 U _external_ref

not a symbol line
"""

_NM_B = """
# build B symbol dump
0000000000100000 0c8 T _os_parse_header
0000000000100200 f0 T _os_validate_blob
0000000000100300 64 D _os_table
0000000000100600 20 T _os_new_check
"""

_REACHABLE = """
_os_parse_header
_os_validate_blob
# comment line

"""


# --- parsing -----------------------------------------------------------------
def test_parse_nm_symbols_parses_sizes_types_and_names():
    syms = parse_nm_symbols(_NM_A)
    assert set(syms) == {"_os_parse_header", "_os_validate_blob", "_os_table",
                         "_os_static_helper", "_external_ref"}
    entry = syms["_os_parse_header"]
    assert entry == {"addr": 0x100000, "size": 0x1F4, "type": "T",
                     "name": "_os_parse_header"}
    assert syms["_os_static_helper"]["size"] == 0


def test_parse_nm_symbols_optional_size_comments_and_malformed_skips():
    syms, skipped = parse_nm_symbols_with_skipped(
        "# comment\n"
        "\n"
        "1000 10 T _with_size\n"
        "2000 D _no_size\n"
        "garbage line here\n"
        "zzzz T _bad_addr\n"
        "3000 T\n")
    assert set(syms) == {"_with_size", "_no_size"}
    assert syms["_no_size"]["size"] == 0 and syms["_no_size"]["addr"] == 0x2000
    assert skipped == 3


def test_diff_symbols_classification_and_confidence_math():
    a = {
        "kept": {"addr": 1, "size": 10, "type": "T", "name": "kept"},
        "gone": {"addr": 2, "size": 8, "type": "T", "name": "gone"},
        "shrunk": {"addr": 3, "size": 100, "type": "T", "name": "shrunk"},
    }
    b = {
        "kept": {"addr": 1, "size": 10, "type": "T", "name": "kept"},
        "new": {"addr": 9, "size": 4, "type": "T", "name": "new"},
        "shrunk": {"addr": 3, "size": 40, "type": "T", "name": "shrunk"},
    }
    result = diff_symbols(a, b)
    assert result["added"] == ["new"]
    assert result["removed"] == ["gone"]
    assert len(result["modified"]) == 1
    mod = result["modified"][0]
    assert mod["name"] == "shrunk"
    assert mod["old_size"] == 100 and mod["new_size"] == 40
    assert mod["size_delta"] == -60
    assert mod["confidence"] == 0.6  # round(min(1, 60/100), 2)


def test_diff_symbols_addr_only_change_and_sorted_deterministic():
    a = {n: {"addr": 1, "size": 5, "type": "T", "name": n}
         for n in ["m_two", "m_one"]}
    b = {n: {"addr": 7, "size": 5, "type": "T", "name": n}
         for n in ["m_one", "m_two"]}
    result = diff_symbols(a, b)
    assert result["modified"] == [
        {"name": "m_one", "old_size": 5, "new_size": 5,
         "size_delta": 0, "confidence": 0.0},
        {"name": "m_two", "old_size": 5, "new_size": 5,
         "size_delta": 0, "confidence": 0.0},
    ]
    assert diff_symbols(b, a) == result


def test_prioritize_scores_weights_and_ordering():
    diff = {
        "added": ["add_hit", "add_miss"],
        "removed": ["rem_hit", "rem_miss"],
        "modified": [
            {"name": "mod_hit", "old_size": 100, "new_size": 50,
             "size_delta": -50, "confidence": 0.5},
            {"name": "mod_miss", "old_size": 10, "new_size": 0,
             "size_delta": -10, "confidence": 1.0},
        ],
    }
    ranked = prioritize(diff, {"add_hit", "mod_hit", "rem_hit"})
    by_name = {e["name"]: e for e in ranked}
    assert by_name["mod_hit"]["score"] == 80 + int(30 * 0.5)
    assert by_name["mod_hit"]["classes"] == ["modified", "reachable"]
    assert by_name["add_hit"]["score"] == 70
    assert by_name["add_miss"]["score"] == 30
    assert by_name["mod_miss"]["score"] == 40 + int(30 * 1.0)
    assert by_name["rem_hit"]["score"] == 20
    assert by_name["rem_miss"]["score"] == 10
    scores = [e["score"] for e in ranked]
    assert scores == sorted(scores, reverse=True)
    assert [e["name"] for e in ranked] == [
        "mod_hit", "add_hit", "mod_miss", "add_miss", "rem_hit", "rem_miss"]


def test_prioritize_is_deterministic():
    diff = {"added": ["z_add", "a_add"], "removed": ["m_rem"],
            "modified": [{"name": "b_mod", "old_size": 4, "new_size": 2,
                          "size_delta": -2, "confidence": 0.5}]}
    one = prioritize(diff, {"a_add"})
    two = prioritize(diff, {"a_add"})
    three = prioritize(diff, set())
    assert one == two
    assert [e["name"] for e in one][:1] == ["a_add"]
    assert [e["name"] for e in three][0] in ("b_mod", "a_add", "z_add")


# --- store / engine ----------------------------------------------------------
def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def test_store_roundtrip_and_missing_raises(workspace):
    from ios_research.ipswdiff import NdayDiff
    store = NdayStore(workspace)
    rec = NdayDiff(id="ndy_test0001", name="17.4-vs-17.5",
                   created_at="2026-01-01T00:00:00Z",
                   stats={"added": 1, "removed": 0, "modified": 2, "total": 3},
                   diff={"added": [], "removed": [], "modified": []})
    store.save(rec)
    loaded = store.get("ndy_test0001")
    assert loaded.name == "17.4-vs-17.5" and loaded.stats["total"] == 3
    with pytest.raises(NotFoundError):
        store.get("ndy_missing")


def test_engine_create_diff_reads_files_and_persists(tmp_path, workspace):
    engine = NdayEngine(workspace)
    rec = engine.create_diff("17.4-vs-17.5",
                             _write(tmp_path, "a.txt", _NM_A),
                             _write(tmp_path, "b.txt", _NM_B))
    assert rec.stats["added"] == 1      # _os_new_check
    assert rec.stats["removed"] == 2    # _os_static_helper, _external_ref
    assert rec.stats["modified"] == 2   # header (smaller), validate_blob
    assert rec.stats["total"] == 5
    assert rec.id.startswith("ndy_")
    stored = NdayStore(workspace).get(rec.id)
    assert stored.to_dict() == rec.to_dict()
    # Deterministic id for identical inputs.
    again = engine.create_diff("17.4-vs-17.5",
                               _write(tmp_path, "a.txt", _NM_A),
                               _write(tmp_path, "b.txt", _NM_B))
    assert again.id == rec.id


def test_engine_create_diff_missing_file_raises_not_found(tmp_path, workspace):
    engine = NdayEngine(workspace)
    with pytest.raises(NotFoundError):
        engine.create_diff("x", str(tmp_path / "missing-a.txt"),
                           _write(tmp_path, "b.txt", _NM_B))
    with pytest.raises(NotFoundError):
        engine.create_diff("x", _write(tmp_path, "a.txt", _NM_A),
                           str(tmp_path / "missing-b.txt"))


def test_engine_prioritize_stores_plan(tmp_path, workspace):
    engine = NdayEngine(workspace)
    rec = engine.create_diff("d", _write(tmp_path, "a.txt", _NM_A),
                             _write(tmp_path, "b.txt", _NM_B))
    out = engine.prioritize(rec.id, _write(tmp_path, "r.txt", _REACHABLE))
    assert out.plan["reachable_count"] == 2
    ranked = out.plan["ranked"]
    assert ranked and all({"name", "classes", "score"} <= set(e)
                          for e in ranked)
    top = ranked[0]
    assert top["classes"] == ["modified", "reachable"]
    assert top["name"] in ("_os_parse_header", "_os_validate_blob")


def test_engine_campaign_recommends_top3(tmp_path, workspace):
    engine = NdayEngine(workspace)
    rec = engine.create_diff("camp", _write(tmp_path, "a.txt", _NM_A),
                             _write(tmp_path, "b.txt", _NM_B))
    out = engine.campaign(rec.id, _write(tmp_path, "r.txt", _REACHABLE))
    recommended = out.plan["recommended"]
    assert len(recommended) == min(3, len(out.plan["ranked"]))
    assert recommended == [e["name"] for e in out.plan["ranked"][:3]]
    persisted = NdayStore(workspace).get(rec.id)
    assert persisted.plan["recommended"] == recommended


# --- CLI surface -------------------------------------------------------------
def test_cli_nday_roundtrip_json_envelopes(ctx, tmp_path, capsys):
    ws = str(ctx.workspace().root)
    sym_a = _write(tmp_path, "a.txt", _NM_A)
    sym_b = _write(tmp_path, "b.txt", _NM_B)
    reachable = _write(tmp_path, "r.txt", _REACHABLE)

    rc = main(["nday", "diff", "--name", "17.4-vs-17.5",
               "--symbols-a", sym_a, "--symbols-b", sym_b,
               "--json", "--workspace", ws])
    envelope = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and envelope["ok"] is True
    assert envelope["command"] == "nday diff"
    nday_id = envelope["data"]["nday"]["id"]
    assert nday_id.startswith("ndy_")

    rc = main(["nday", "list", "--json", "--workspace", ws])
    envelope = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and envelope["command"] == "nday list"
    assert envelope["data"]["count"] == 1

    rc = main(["nday", "show", nday_id, "--json", "--workspace", ws])
    envelope = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and envelope["data"]["id"] == nday_id
    assert envelope["data"]["stats"]["modified"] == 2

    rc = main(["nday", "prioritize", nday_id, "--reachable", reachable,
               "--json", "--workspace", ws])
    envelope = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and envelope["command"] == "nday prioritize"
    assert envelope["data"]["plan"]["reachable_count"] == 2
    assert envelope["data"]["plan"]["ranked"]

    rc = main(["nday", "campaign", nday_id, "--reachable", reachable,
               "--json", "--workspace", ws])
    envelope = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and envelope["command"] == "nday campaign"
    recommended = envelope["data"]["plan"]["recommended"]
    assert 1 <= len(recommended) <= 3


def test_cli_nday_error_exit_codes(ctx, tmp_path, capsys):
    ws = str(ctx.workspace().root)
    rc = main(["nday", "show", "ndy_nope", "--json", "--workspace", ws])
    envelope = json.loads(capsys.readouterr().out.strip())
    assert rc == ExitCode.NOT_FOUND
    assert envelope["ok"] is False and envelope["error"]

    rc = main(["nday", "prioritize", "ndy_nope",
               "--reachable", _write(tmp_path, "r.txt", _REACHABLE),
               "--json", "--workspace", ws])
    assert rc == ExitCode.NOT_FOUND
    capsys.readouterr()

    rc = main(["nday", "diff", "--name", "x",
               "--symbols-a", str(tmp_path / "gone"),
               "--symbols-b", str(tmp_path / "also-gone"),
               "--json", "--workspace", ws])
    assert rc == ExitCode.NOT_FOUND
    capsys.readouterr()

    with pytest.raises(SystemExit) as excinfo:
        main(["nday", "diff", "--symbols-a", "a", "--workspace", ws])
    assert excinfo.value.code == ExitCode.USAGE
