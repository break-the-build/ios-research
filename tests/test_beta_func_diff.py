"""tools/beta/func_diff.py: which functions and strings changed between two builds."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "beta"))
import func_diff  # noqa: E402

RET, NOP = 0xD65F03C0, 0xD503201F
BRK = 0xD4200020                       # brk #1


def bl(imm: int) -> int:
    return 0x94000000 | imm


def cmp_x0(imm: int) -> int:           # subs xzr, x0, #imm
    return 0xF100001F | (imm << 10)


def b_hi(imm: int) -> int:             # b.hi .+imm*4
    return 0x54000008 | (imm << 5)


def adrp_x8(page: int) -> int:
    return 0x90000008 | (page << 5)


def add_x8(imm: int) -> int:           # add x8, x8, #imm
    return 0x91000108 | (imm << 10)


def ldr_x0_x9(imm: int) -> int:        # ldr x0, [x9, #imm*8]
    return 0xF9400120 | (imm << 10)


def words(*ws: int) -> bytes:
    return struct.pack(f"<{len(ws)}I", *ws)


def macho(text: bytes, text_addr: int, strings: list[str]) -> bytes:
    """A minimal 64-bit Mach-O: one __TEXT segment with __text and __cstring."""
    cstring = b"".join(s.encode() + b"\0" for s in strings)
    header_size = 32 + 72 + 2 * 80
    text_off = header_size
    cstr_off = text_off + len(text)

    def section(name: str, addr: int, size: int, off: int) -> bytes:
        return (name.encode().ljust(16, b"\0") + b"__TEXT".ljust(16, b"\0")
                + struct.pack("<QQIIIIIIII", addr, size, off, 2, 0, 0, 0, 0, 0, 0))

    seg = (struct.pack("<II", 0x19, 72 + 160) + b"__TEXT".ljust(16, b"\0")
           + struct.pack("<QQQQIIII", text_addr, len(text) + len(cstring), 0,
                         cstr_off + len(cstring), 5, 5, 2, 0)
           + section("__text", text_addr, len(text), text_off)
           + section("__cstring", text_addr + len(text), len(cstring), cstr_off))
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 6, 1, len(seg), 0, 0)
    return header + seg + text + cstring


def baseline(root: Path, build: str, funcs: list[tuple[str, bytes]], strings: list[str],
             base: int = 0x1000) -> Path:
    """A lane_baseline.sh-shaped directory with one image, "Img"."""
    d = root / build / "Img"
    d.mkdir(parents=True)
    (root / build / "manifest.json").write_text("{}")
    starts, addr = [], base
    for _name, code in funcs:
        starts.append(addr)
        addr += len(code)
    (d / "Img").write_bytes(macho(b"".join(c for _n, c in funcs), base, strings))
    (d / "starts.txt").write_text("".join(f"0x{a:016X}\n" for a in starts))
    (d / "exports.txt").write_text(
        "0x000000000: (external|undefined)  ___stack_chk_fail\n"
        + "".join(f"0x{a:09x}: (__TEXT.__text)  {n}\n"
                  for a, (n, _c) in zip(starts, funcs) if n))
    return root / build


# ---- normalization and profiles ----

def test_normalize_masks_pc_relative_fields_only():
    n = func_diff.normalize
    assert n(words(bl(1))) == n(words(bl(0x123)))                         # call target
    assert n(words(b_hi(2))) == n(words(b_hi(9)))                         # branch target
    assert n(words(adrp_x8(1), add_x8(0x10))) == n(words(adrp_x8(7), add_x8(0x20)))
    assert n(words(cmp_x0(4))) != n(words(cmp_x0(8)))                     # a bound
    assert n(words(ldr_x0_x9(1))) != n(words(ldr_x0_x9(2)))               # a field offset
    assert n(words(b_hi(2))) != n(words(0x54000040 | 2 << 5))             # b.eq vs b.hi


def test_page_offset_is_kept_once_the_adrp_is_out_of_reach():
    gap = [NOP] * (func_diff._ADRP_REACH + 1)
    a = words(adrp_x8(1), *gap, add_x8(0x10))
    b = words(adrp_x8(1), *gap, add_x8(0x20))
    assert func_diff.normalize(a) != func_diff.normalize(b)


def test_profile_counts_checks_traps_and_calls():
    p = func_diff.profile(words(cmp_x0(4), b_hi(2), BRK, bl(5), bl(6), RET))
    assert p == {"checks": 2, "traps": 1, "calls": 2}


def test_operands_only_means_same_instructions():
    assert func_diff.operands_only(words(cmp_x0(4), RET), words(cmp_x0(8), RET))
    assert not func_diff.operands_only(words(cmp_x0(4), RET), words(NOP, RET))
    assert not func_diff.operands_only(words(RET), words(NOP, RET))


def test_parse_sections_rejects_non_macho():
    with pytest.raises(ValueError):
        func_diff.parse_sections(b"\x7fELF" + b"\0" * 60)


# ---- end to end ----

OLD_FUNCS = [("_moved", words(bl(1), RET)),
             ("_parse", words(cmp_x0(4), RET)),
             ("_layout", words(ldr_x0_x9(1), RET)),
             ("", words(NOP, NOP, RET))]
NEW_FUNCS = [("_moved", words(bl(99), RET)),                          # only its call moved
             ("_parse", words(cmp_x0(4), b_hi(2), cmp_x0(64), b_hi(2), RET)),  # new checks
             ("_layout", words(ldr_x0_x9(2), RET)),                   # struct offset moved
             ("", words(NOP, NOP, RET)),
             ("_new_reader.42", words(cmp_x0(1), b_hi(1), RET))]
BUILD_PATH = "/AppleInternal/Library/BuildRoots/abc/Sources/Img/x.c"


def _diff(tmp_path):
    old = baseline(tmp_path / "old", "25G83__Mac14,14", OLD_FUNCS, ["hello", BUILD_PATH])
    new = baseline(tmp_path / "new", "25G332__Mac14,14", NEW_FUNCS,
                   ["hello", "ERROR: offset (%zu) out of range",
                    BUILD_PATH.replace("abc", "def")], base=0x2000)
    return old, new, func_diff.diff_image(old / "Img", new / "Img")


def test_changes_are_found_classified_and_ranked(tmp_path):
    _old, _new, d = _diff(tmp_path)
    assert d["functions"] == [4, 5]
    names = [c["name"] for c in d["changed"]]
    assert names == ["_parse", "_layout"]                  # code change ranked first
    parse, layout = d["changed"]
    assert not parse["operands_only"] and parse["checks_delta"] == 3   # 1 -> 4
    assert parse["old_size"] == 8 and parse["new_size"] == 20
    assert layout["operands_only"] and layout["checks_delta"] == 0
    assert [a["name"] for a in d["added"]] == ["_new_reader"]   # numbered suffix dropped
    assert d["removed"] == []
    # Build-directory paths change in every build: never reported.
    assert d["strings_added"] == ["ERROR: offset (%zu) out of range"]
    assert d["strings_removed"] == []


def test_stripped_functions_are_named_by_address(tmp_path):
    old = baseline(tmp_path / "old", "a", [("", words(cmp_x0(4), RET))], [])
    new = baseline(tmp_path / "new", "b", [("", words(cmp_x0(4), b_hi(1), RET))], [])
    d = func_diff.diff_image(old / "Img", new / "Img")
    assert [c["name"] for c in d["changed"]] == ["sub_1000"]


def test_cli_writes_markdown_and_json(tmp_path, capsys):
    old, new, _d = _diff(tmp_path)
    out_json = tmp_path / "diff.json"
    assert func_diff.main([str(old), str(new), "--json", str(out_json)]) == 0
    md = capsys.readouterr().out
    assert "| Img | 1 | 3 | 1 | 1 | 0 | 1 |" in md
    assert "| changed | `_parse` | 0x2008 | 8 → 20 | +3 | +0 | +0 |" in md
    assert "`ERROR: offset (%zu) out of range`" in md
    assert json.loads(out_json.read_text())["images"]["Img"]["added"][0]["name"] == "_new_reader"


def test_build_dir_needs_exactly_one_recorded_build(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    with pytest.raises(SystemExit):
        func_diff._build_dir(tmp_path)
