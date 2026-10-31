"""Lane generators (tools/gen): fonts (lane 5), DNG (lane 1), and the gate.

Unit tests build their own tiny fonts and DNGs, so they run anywhere. Native
tests (opt-in, -m native) gate generated fonts on the real CoreText harness
and prove that hinting edits reach the TrueType interpreter.
"""

from __future__ import annotations

import os
import random
import struct
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "gen"))
import dng  # noqa: E402
import fonts  # noqa: E402
import gate  # noqa: E402


# ---------------------------------------------------------------- a tiny TrueType font

def _simple_glyph(program: bytes) -> bytes:
    # 1 contour, endPts=[2], bbox, instructions, 3 on-curve points (x/y bytes).
    return (struct.pack(">hhhhh", 1, 0, 0, 100, 100) + struct.pack(">H", 2)
            + struct.pack(">H", len(program)) + program
            + bytes([0x37, 0x37, 0x37]) + bytes([0, 50, 50]) + bytes([0, 100, 0]))


def _composite_glyph(program: bytes) -> bytes:
    # one component (ARG_1_AND_2_ARE_WORDS | WE_HAVE_INSTRUCTIONS), glyph 1.
    return (struct.pack(">hhhhh", -1, 0, 0, 100, 100)
            + struct.pack(">HHhh", 0x0001 | 0x0100, 1, 0, 0)
            + struct.pack(">H", len(program)) + program)


def tiny_font() -> bytes:
    glyphs = [_simple_glyph(b"\xb0\x05\x2b"),          # PUSHB[0] 5, CALL
              _simple_glyph(b"\x40\x02\x01\x02\x30"),  # NPUSHB 2 (1, 2), IUP[y]
              _composite_glyph(b"\xb8\x00\x07\x2b")]   # PUSHW[0] 7, CALL
    head = bytearray(54)
    struct.pack_into(">IIIIHH", head, 0, 0x00010000, 0, 0, 0x5F0F3CF5, 0, 1000)
    maxp = bytearray(32)
    struct.pack_into(">IHH", maxp, 0, 0x00010000, len(glyphs), 3)
    struct.pack_into(">HHHHHH", maxp, 14, 2, 4, 8, 16, 0, 64)
    tables = fonts.join_glyphs({"head": bytes(head)}, glyphs)
    tables.update({"maxp": bytes(maxp), "fpgm": b"\xb0\x00\x2c\x2d",   # FDEF 0 / ENDF
                   "prep": b"\xb1\x01\x02\x1d", "name": b"\0" * 6})
    return fonts.build_sfnt(b"\x00\x01\x00\x00", ["head", "maxp", "loca", "glyf",
                                                  "fpgm", "prep", "name"], tables)


# ---------------------------------------------------------------- fonts

def test_sfnt_roundtrip_and_whole_font_checksum():
    font = tiny_font()
    version, order, tables = fonts.parse_sfnt(font)
    assert version == b"\x00\x01\x00\x00" and order[0] == "head"
    assert fonts.build_sfnt(version, order, tables) == font
    assert fonts.checksum(font) == 0xB1B0AFBA            # head.checkSumAdjustment is right


def test_disassemble_keeps_push_operands_whole():
    code = b"\x40\x02\x01\x02\xb1\x03\x04\xb8\x00\x07\x41\x01\x12\x34\x2b"
    ins = fonts.disassemble(code)
    assert [i.hex() for i in ins] == ["40020102", "b10304", "b80007", "41011234", "2b"]
    assert b"".join(ins) == code


def test_program_mutations_reassemble_into_whole_instructions():
    rng = random.Random(3)
    code = b"\x40\x02\x01\x02\xb1\x03\x04\x2b\x30\x3c"
    for _ in range(300):
        out = fonts.mutate_program(code, rng, [0, 1, 0xFFFF])
        assert b"".join(fonts.disassemble(out)) == out


def test_glyph_programs_are_found_and_rebuilt():
    _v, _o, tables = fonts.parse_sfnt(tiny_font())
    glyphs = fonts.split_glyphs(tables)
    progs = [fonts.glyph_program(g) for g in glyphs]
    assert [p[1] for p in progs] == [3, 5, 4] and progs[0][2] == 3   # lengths; 3 points
    assert fonts.split_glyphs(fonts.join_glyphs(tables, glyphs)) == \
        [g + b"\0" * (-len(g) % 4) for g in glyphs]


def test_hinting_variants_change_programs_and_stay_parseable():
    font = tiny_font()
    rng = random.Random(7)
    changed = set()
    for _ in range(60):
        where, new = fonts.mutate_hinting(fonts.parse_sfnt(font)[2], rng)
        changed.add(where.rstrip("0123456789"))
        rebuilt = fonts.build_sfnt(b"\x00\x01\x00\x00", list(new), new)
        assert fonts.parse_sfnt(rebuilt)[2]["glyf"] == new["glyf"]
    assert changed == {"fpgm", "prep", "glyph"}


def test_table_variants_touch_one_table_and_sanitize_names(tmp_path):
    src = tmp_path / "Tiny.ttf"
    font = fonts.build_sfnt(b"\x00\x01\x00\x00", ["OS/2", "head"],
                            {"OS/2": b"\x00\x01" * 10, "head": bytes(54)})
    src.write_bytes(font)
    assert fonts.main([str(src), "--out", str(tmp_path / "v"), "--table", "3", "--hint", "0"]) == 0
    names = sorted(p.name for p in (tmp_path / "v").iterdir())
    assert names[0] == "Tiny-tbl-OS_2-0.ttf" and len(names) == 6


def test_variants_are_deterministic_per_seed(tmp_path):
    src = tmp_path / "Tiny.ttf"
    src.write_bytes(tiny_font())
    for run in ("a", "b"):
        fonts.main([str(src), "--out", str(tmp_path / run), "--table", "2", "--hint", "20"])
    a = {p.name: p.read_bytes() for p in (tmp_path / "a").iterdir()}
    b = {p.name: p.read_bytes() for p in (tmp_path / "b").iterdir()}
    assert a == b and len(a) == 7 * 2 + 20


def test_drawn_glyph_ids_match_the_harness_grid():
    assert fonts.drawn_glyph_ids(10) == list(range(10))
    ids = fonts.drawn_glyph_ids(1000)
    assert ids[:32] == list(range(32)) and len(ids) == 64 and ids[32] == 32


# ---------------------------------------------------------------- DNG

def _ljpeg_decode(stream: bytes) -> tuple[int, int, int, list[list[int]]]:
    """A deliberately independent decoder for the encoder's subset."""
    sof = stream.index(b"\xFF\xC3")
    p, y, x, nf = struct.unpack_from(">BHHB", stream, sof + 4)
    dht = stream.index(b"\xFF\xC4")
    bits = stream[dht + 5:dht + 21]
    vals = stream[dht + 21:dht + 21 + sum(bits)]
    table, code = {}, 0
    k = 0
    for length in range(1, 17):
        for _ in range(bits[length - 1]):
            table[(length, code)] = vals[k]
            k += 1
            code += 1
        code <<= 1
    sos = stream.index(b"\xFF\xDA")
    data = stream[sos + 2 + struct.unpack_from(">H", stream, sos + 2)[0]:stream.rindex(b"\xFF\xD9")]
    data = data.replace(b"\xFF\x00", b"\xFF")
    bitpos = 0

    def bit() -> int:
        nonlocal bitpos
        b = (data[bitpos >> 3] >> (7 - (bitpos & 7))) & 1
        bitpos += 1
        return b

    rows = []
    for yy in range(y):
        row = []
        for xx in range(x):
            for c in range(nf):
                length = code = 0
                while (length, code) not in table:
                    code = (code << 1) | bit()
                    length += 1
                cat = table[(length, code)]
                if cat in (0, 16):
                    diff = 0 if cat == 0 else 32768
                else:
                    v = 0
                    for _ in range(cat):
                        v = (v << 1) | bit()
                    diff = v if v >= 1 << (cat - 1) else v - (1 << cat) + 1
                if xx > 0:
                    pred = row[(xx - 1) * nf + c]
                elif yy > 0:
                    pred = rows[yy - 1][c]
                else:
                    pred = 1 << (p - 1)
                row.append((pred + diff) & 0xFFFF)
        rows.append(row)
    return p, x, nf, rows


@pytest.mark.parametrize("ncomp, precision", [(1, 8), (2, 12), (2, 16), (3, 14)])
def test_lossless_jpeg_roundtrips(ncomp, precision):
    rows = dng._pattern(6, 5, ncomp, precision)
    p, x, nf, decoded = _ljpeg_decode(dng.ljpeg_encode(rows, ncomp, precision))
    assert (p, x, nf) == (precision, 6, ncomp) and decoded == rows


def test_dng_layout_has_a_preview_and_a_raw_subifd():
    ifds = dng.parse_ifds(dng.make_dng(tile=16, width=48, height=40))
    main, raw = ifds
    assert 330 in main and 50706 in main and 50708 in main      # SubIFDs, DNGVersion, model
    assert {256, 257, 259, 322, 323, 324, 325, 33421} <= set(raw)


def test_mismatch_variants_patch_in_place():
    base = dng.make_dng(jpeg_comps=2)
    variants = dict(dng.mismatch_variants(base))
    kinds = {name.split("-")[1].rstrip("0123456789") for name in variants}
    assert {"SamplesPerPixel", "BitsPerSample", "jpegNf", "jpegP", "pair"} <= \
        {k if not k.startswith("pair") else "pair" for k in kinds}
    for name, data in variants.items():
        assert len(data) == len(base) and data != base, name
    pair = next(d for n, d in variants.items() if "SamplesPerPixel3-Nf1" in n)
    assert sum(a != b for a, b in zip(pair, base)) <= 3          # two fields, a few bytes


def _be_tiff() -> bytes:
    """Big-endian TIFF like Apple ProRAW: IFD0 -> EXIF IFD with a MakerNote."""
    ifd0 = struct.pack(">H", 4) + b"".join([
        struct.pack(">HHIH2x", 256, dng.SHORT, 1, 64),
        struct.pack(">HHIH2x", 257, dng.SHORT, 1, 48),
        struct.pack(">HHIH2x", 277, dng.SHORT, 1, 1),
        struct.pack(">HHII", dng.EXIF_IFD, dng.LONG, 1, 62),
    ]) + struct.pack(">I", 0)
    exif = struct.pack(">H", 2) + b"".join([
        struct.pack(">HHIH2x", 34855, dng.SHORT, 1, 100),
        struct.pack(">HHII", dng.MAKERNOTE, 7, 16, 92),
    ]) + struct.pack(">I", 0)
    data = b"MM\0*" + struct.pack(">I", 8) + ifd0 + exif + bytes(range(16))
    assert len(data) == 108
    return data


def test_big_endian_ifds_and_exif_are_parsed_and_patched():
    data = _be_tiff()
    ifd0, exif = dng.parse_ifds(data)
    assert ifd0[256] == (dng.SHORT, 1, 18) and dng.MAKERNOTE in exif
    variants = dict(dng.mismatch_variants(data))
    patched = variants["ifd0-ImageWidth-1"]
    assert patched[18:20] == b"\x00\x01" and len(patched) == len(data)
    assert not any("tag34855" in n or "makernote" in n for n in variants)


def test_all_tags_and_makernote_variants():
    data = _be_tiff()
    variants = dict(dng.mismatch_variants(data, all_tags=True, makernote=3, seed=7))
    assert "ifd1-tag34855x-0" in variants
    notes = [n for n in variants if "-makernote-" in n]
    assert len({n.split("-")[2] for n in notes}) == 3                # three positions
    for name in notes:
        diff = [i for i, (a, b) in enumerate(zip(variants[name], data)) if a != b]
        assert len(diff) == 1 and 92 <= diff[0] < 108, name
    again = dict(dng.mismatch_variants(data, all_tags=True, makernote=3, seed=7))
    assert again.keys() == variants.keys()


def test_rawsweep_streams_and_keeps_only_leads(tmp_path):
    import rawsweep

    raw = tmp_path / "be.dng"
    raw.write_bytes(_be_tiff())
    stub = tmp_path / "harness.sh"
    stub.write_text('#!/bin/sh\ni=0\nfor f in "$@"; do\n'
                    '  case "$f" in *ImageWidth-0.dng) kill -SEGV $$ ;; esac\n'
                    '  echo "DONE $i decoded pixels=5"; i=$((i+1))\ndone\n')
    stub.chmod(0o755)
    work, crashes = tmp_path / "work", tmp_path / "crashes"
    result = rawsweep.sweep(str(stub), [raw], work, crashes, workers=2, all_tags=True)
    expected = len(list(dng.mismatch_variants(raw.read_bytes(), all_tags=True)))
    assert result["variants"] == expected and result["decoded"] == expected - 1
    assert result["leads"] == [{"file": "be-ifd0-ImageWidth-0.dng", "verdict": "crash"}]
    assert (crashes / "crashed" / "be-ifd0-ImageWidth-0.dng").exists()
    assert not any(work.iterdir())


def test_gate_kind_groups_variant_names():
    assert gate.kind(Path("Arial-hint-glyph12-7.ttf")) == "hint-glyph"
    assert gate.kind(Path("Arial-tbl-OS_2-3.ttf")) == "tbl-OS_2"
    assert gate.kind(Path("x-ifd1-jpegNf-4.dng")) == "ifd1-jpegNf"


# ---------------------------------------------------------------- native

def _can_build_native() -> bool:
    return sys.platform == "darwin" and os.path.exists("/usr/lib/libgmalloc.dylib")


ARIAL = "/System/Library/Fonts/Supplemental/Arial.ttf"


@pytest.fixture(scope="module")
def coretext_harness() -> str:
    r = subprocess.run(["bash", str(REPO / "tools" / "harness" / "build.sh"), "coretext"],
                       capture_output=True, timeout=300, check=False)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    return str(REPO / "tools" / "harness" / "build" / "coretext_fuzzer")


def _pixels(harness: str, paths: list[str]) -> list[str]:
    out = subprocess.run([harness, *paths], capture_output=True, text=True, timeout=600,
                         check=False).stdout
    return [ln.split()[3] for ln in out.splitlines() if ln.startswith("DONE")]


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native() or not os.path.exists(ARIAL),
                    reason="requires macOS with libgmalloc and Arial")
def test_native_hinting_edits_reach_the_truetype_interpreter(coretext_harness, tmp_path):
    """Only the aliased pass runs fpgm/prep/glyph programs; some edits must show."""
    fonts.main([ARIAL, "--out", str(tmp_path), "--table", "0", "--hint", "60", "--seed", "5"])
    variants = sorted(str(p) for p in tmp_path.iterdir())
    original = _pixels(coretext_harness, [ARIAL])[0]
    results = _pixels(coretext_harness, variants)
    assert len(results) == len(variants)
    assert sum(r != original for r in results) >= 5, (original, results[:10])


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native() or not os.path.exists(ARIAL),
                    reason="requires macOS with libgmalloc and Arial")
def test_native_font_variants_pass_the_gate(coretext_harness, tmp_path):
    fonts.main([ARIAL, "--out", str(tmp_path), "--table", "2", "--hint", "40", "--seed", "9"])
    files = sorted(tmp_path.iterdir())
    decoded, _crashed = gate.run(coretext_harness, files)
    assert sum(decoded.values()) >= 0.9 * len(files), (sum(decoded.values()), len(files))
