"""Tests for the static-analysis scout (#223).

Pure-function coverage with synthetic inputs: nm/otool/strings parsers,
format-constant fingerprinting, evidence-backed dictionary rendering,
Ghidra export normalization, directed-compatible call-graph export, and
parser focus-function identification. A native-marked test compiles a
fixture binary and runs the real census end-to-end.
"""

from __future__ import annotations

import json

import pytest

from ios_research import staticscan as ss
from ios_research.directed import load_callgraph, target_distances


# --- native-output parsers -----------------------------------------------------

def test_parse_nm_symbols():
    text = (
        "000000010003f4a0 T _MPEGAudioFile_OpenFromDataSource\n"
        "000000010003abcd D _kSomeConstant\n"
        "                 u _weak_symbol\n"
        "garbage line\n"
    )
    syms = ss.parse_nm_symbols(text)
    assert "_MPEGAudioFile_OpenFromDataSource" in syms
    assert syms["_kSomeConstant"]["type"] == "D"
    assert "_weak_symbol" not in syms      # no address -> skipped
    assert "garbage line" not in syms


def test_parse_otool_libraries():
    text = (
        "/bin/foo:\n"
        "\t/System/Library/Frameworks/CoreText.framework/CoreText "
        "(compatibility version 1.0.0, current version 1.0.0)\n"
        "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
    )
    libs = ss.parse_otool_libraries(text)
    assert libs[0].endswith("CoreText.framework/CoreText")
    assert any("libSystem" in l for l in libs)


def test_parse_strings_min_length():
    assert ss.parse_strings("abc\nabcd\nlonger string\n", min_len=4) == \
        ["abcd", "longer string"]


# --- fingerprinting ------------------------------------------------------------

def _font_parser_strings() -> list[str]:
    return [
        "CTFontManagerCreateFontDescriptorsFromData",
        "invalid sfnt table directory",
        "glyf", "loca", "maxp", "cmap", "OTTO", "ttcf",
        "unsupported CFF table",
        "ID3v2 tag",                       # audiotoolbox token in a font
    ]


def test_fingerprint_finds_coretext_with_evidence():
    matches = ss.fingerprint(_font_parser_strings())
    assert "coretext" in matches
    tokens = {m["token"] for m in matches["coretext"]}
    assert {"glyf", "loca", "maxp", "cmap", "OTTO", "ttcf"} <= tokens
    for m in matches["coretext"]:
        assert m["hits"] >= 1


def test_fingerprint_is_family_scoped_and_deterministic():
    strings = _font_parser_strings()
    a = ss.fingerprint(strings)
    b = ss.fingerprint(list(reversed(strings)))
    assert a == b                       # order-independent, deterministic
    assert "audiotoolbox" in a          # ID3 token present
    assert "imageio" not in a


def test_fingerprint_custom_signatures():
    matches = ss.fingerprint(["ZETA-MAGIC", "alpha"],
                             signatures={"custom": ("ZETA-MAGIC",)})
    assert matches == {"custom": [{"token": "ZETA-MAGIC", "hits": 1}]}


def test_build_dictionary_escapes_and_orders():
    matches = {"coretext": [{"token": "OTTO", "hits": 3},
                            {"token": "\x00\x01\x00\x00", "hits": 2}],
               "audiotoolbox": [{"token": 'ID3 "quoted"', "hits": 1}]}
    d = ss.build_dictionary(matches)
    lines = d.splitlines()
    assert '"\\x00\\x01\\x00\\x00"' in lines          # non-printable escaped
    assert '"ID3 \\"quoted\\""' in d                 # quotes escaped
    assert '"OTTO"' in d
    assert d.endswith("\n")
    # family filter
    only_ct = ss.build_dictionary(matches, families={"coretext"})
    assert "audiotoolbox" not in only_ct and '"OTTO"' in only_ct


def test_finding04_constants_fingerprint_audiotoolbox():
    # The constants from the FINDING-04 investigation identify the
    # MPEG/ID3 parser family in a binary's constant pool.
    matches = ss.fingerprint(["ID3v2 header", "RIFF", "WAVE", "fmt ",
                              "SSND", ".mp3"])
    assert "audiotoolbox" in matches


# --- ghidra export normalization ------------------------------------------------

def _ghidra_export() -> dict:
    return {
        "functions": [
            {"name": "OpenFromDataSource", "entry": "0x1000"},
            {"name": "ReadBytes", "entry": "0x2000"},
            {"name": "ParseTableDirectory", "entry": "0x3000"},
            {"name": "unrelated", "entry": "0x4000"},
        ],
        "edges": [
            {"from": "OpenFromDataSource", "to": "ReadBytes"},
            {"from": "OpenFromDataSource", "to": "ParseTableDirectory"},
            {"from": "ParseTableDirectory", "to": "unrelated"},
            {"from": "Ghost", "to": "ReadBytes"},   # unknown node dropped
        ],
        "strings": [
            {"data": "invalid glyf table", "references":
                ["ParseTableDirectory"]},
            {"data": "OTTO not supported", "references":
                ["OpenFromDataSource"]},
            {"data": "no refs here", "references": []},
        ],
    }


def test_parse_ghidra_export_normalizes():
    n = ss.parse_ghidra_export(_ghidra_export())
    assert set(n["functions"]) == {"OpenFromDataSource", "ReadBytes",
                                   "ParseTableDirectory", "unrelated"}
    assert ["OpenFromDataSource", "ReadBytes"] in n["edges"]


def test_parse_ghidra_export_rejects_malformed():
    with pytest.raises(Exception):
        ss.parse_ghidra_export({"functions": "nope"})
    with pytest.raises(Exception):
        ss.parse_ghidra_export({"functions": [{"name": "ok"}],
                                "edges": [{"from": "a"}]})   # missing 'to'


def test_callgraph_doc_loads_into_directed():
    n = ss.parse_ghidra_export(_ghidra_export())
    doc = ss.to_callgraph_doc(n)
    graph = load_callgraph(doc)                    # directed accepts it
    distances = target_distances(
        graph, {"ParseTableDirectory"})
    assert distances["OpenFromDataSource"] == 1
    # 'unrelated' is a callee of the target, not a caller: it cannot
    # *reach* the target, so directed selection correctly omits it.
    assert "unrelated" not in distances
    assert "Ghost" not in distances


def test_parser_focus_functions():
    n = ss.parse_ghidra_export(_ghidra_export())
    focus = ss.parser_focus_functions(n)
    by_fn = {f["function"]: f for f in focus}
    assert by_fn["ParseTableDirectory"]["families"] == ["coretext"]
    assert by_fn["OpenFromDataSource"]["families"] == ["coretext"]
    assert "unrelated" not in by_fn


# --- framework location ----------------------------------------------------------

def test_locate_rejects_path_traversal():
    with pytest.raises(Exception):
        ss.locate_framework("../etc/passwd")
    with pytest.raises(Exception):
        ss.locate_framework("")


def test_locate_reports_dyld_shared_cache(tmp_path, monkeypatch):
    fake_cache = tmp_path / "dyld_shared_cache_arm64e"
    fake_cache.write_bytes(b"x")
    monkeypatch.setattr(ss, "DSC_PATHS", (str(fake_cache),))
    loc = ss.locate_framework("AudioToolbox")
    assert loc["in_dyld_shared_cache"] is True
    assert loc["cache_path"] == str(fake_cache)
    assert loc["path"] is None


def test_locate_finds_loose_binary(tmp_path, monkeypatch):
    fw = tmp_path / "Foo.framework" / "Versions" / "Current" / "Foo"
    fw.parent.mkdir(parents=True)
    fw.write_bytes(b"\xcf\xfa\xed\xfe")
    monkeypatch.setattr(ss, "FRAMEWORK_BASES", (str(tmp_path),))
    monkeypatch.setattr(ss, "DSC_PATHS", ())
    loc = ss.locate_framework("Foo")
    assert loc["in_dyld_shared_cache"] is False
    assert loc["path"] == str(fw)


# --- scan record ------------------------------------------------------------------

def test_scan_record_shape():
    rec = ss.make_scan_record({"path": "/tmp/x"}, {"coretext": []},
                              dictionary='"OTTO"\n')
    d = rec.to_dict()
    assert d["kind"] == "staticscan"
    assert d["schema_version"] == ss.SCAN_SCHEMA_VERSION
    assert d["id"].startswith("sta_")   # framework ids truncate to 3 chars


# --- native census (real toolchain, opt-in) ----------------------------------------

@pytest.mark.native
def test_scan_binary_end_to_end(tmp_path):
    src = tmp_path / "fixture.c"
    src.write_text(
        'const char *kTokens[] = {"glyf", "loca", "OTTO", "ID3v2"};\n'
        "int main(void) { return kTokens[0][0] == 'g' ? 0 : 1; }\n")
    import subprocess
    bin_path = tmp_path / "fixture"
    subprocess.run(["cc", "-O0", str(src), "-o", str(bin_path)], check=True)
    binary = ss.scan_binary(str(bin_path))
    assert binary["is_dyld_shared_cache"] is False
    assert binary["strings"], "expected constant strings in fixture"
    matches = ss.fingerprint(binary["strings"])
    assert "coretext" in matches and "audiotoolbox" in matches
    dictionary = ss.build_dictionary(matches)
    assert '"OTTO"' in dictionary and '"glyf"' in dictionary
