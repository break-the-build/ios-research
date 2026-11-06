"""HEIF image-sequence generator (tools/gen/heics.py).

Unit tests build a synthetic image sequence (ftyp + moov/trak/.../stbl + mdat
of length-prefixed NALs) without an encoder, so they run anywhere. The native
test that drives the real ImageIO harness lives in test_mac_harness_reach.py.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "gen"))
import gate
import heics

# ---------------------------------------------------------------- a synthetic sequence

def _box(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I4s", 8 + len(payload), kind) + payload


def _full(kind: bytes, payload: bytes, version: int = 0) -> bytes:
    return _box(kind, bytes([version, 0, 0, 0]) + payload)


def _hvcc(length_size_minus_one: int = 3) -> bytes:
    fixed = bytes(21) + bytes([0b00001100 | length_size_minus_one, 0])   # 0 arrays
    return _box(b"hvcC", fixed)


def _sample_entry(kind: bytes = b"hvc1") -> bytes:
    visual = bytes(6) + struct.pack(">H", 1) + bytes(16) + struct.pack(">HH", 64, 64) \
        + bytes(50)                                    # 78 bytes of VisualSampleEntry
    assert len(visual) == 78
    return _box(kind, visual + _hvcc())


def _nal_sample(i: int, body: int = 6) -> bytes:
    nal = bytes([0x02, 0x01]) + bytes([i & 0xFF]) * (body - 2)    # TRAIL_R-ish header
    return struct.pack(">I", len(nal)) + nal


def sequence(n: int = 5, *, runs: list[tuple[int, int, int]] | None = None,
             sync: list[int] | None = None) -> bytes:
    """A 'pict' track of ``n`` one-NAL samples; ``runs`` is the stsc table."""
    samples = [_nal_sample(i, body=6 + i) for i in range(n)]
    runs = runs or [(1, n, 1)]
    # Chunk boundaries follow the stsc runs.
    per_chunk: list[int] = []
    for idx, (first, spc, _) in enumerate(runs):
        last = runs[idx + 1][0] - 1 if idx + 1 < len(runs) else None
        chunk = first
        while sum(per_chunk) < n and (last is None or chunk <= last):
            per_chunk.append(spc)
            chunk += 1
    sync = sync if sync is not None else [1]
    ftyp = _box(b"ftyp", b"msf1" + bytes(4) + b"msf1mif1hevc")

    def moov(chunk_offsets: list[int]) -> bytes:
        stbl = _box(b"stbl", b"".join([
            _full(b"stsd", struct.pack(">I", 1) + _sample_entry()),
            _full(b"stts", struct.pack(">III", 1, n, 9000)),
            _full(b"stsc", struct.pack(">I", len(runs))
                  + b"".join(struct.pack(">III", *r) for r in runs)),
            _full(b"stsz", struct.pack(">II", 0, n)
                  + b"".join(struct.pack(">I", len(s)) for s in samples)),
            _full(b"stco", struct.pack(">I", len(chunk_offsets))
                  + b"".join(struct.pack(">I", o) for o in chunk_offsets)),
            _full(b"stss", struct.pack(">I", len(sync))
                  + b"".join(struct.pack(">I", s) for s in sync)),
        ]))
        minf = _box(b"minf", stbl)
        hdlr = _full(b"hdlr", bytes(4) + b"pict" + bytes(12) + b"\0")
        mdia = _box(b"mdia", hdlr + minf)
        tkhd = _full(b"tkhd", bytes(72) + struct.pack(">II", 64 << 16, 64 << 16))
        return _box(b"moov", _box(b"trak", tkhd + mdia))

    placeholder = moov([0] * len(per_chunk))
    data_start = len(ftyp) + len(placeholder) + 8
    offsets, at, i = [], data_start, 0
    for spc in per_chunk:
        offsets.append(at)
        for _ in range(spc):
            at += len(samples[i])
            i += 1
    return ftyp + moov(offsets) + _box(b"mdat", b"".join(samples))


def _layout(data: bytes):
    t = heics.tables(data, heics.sequence_track(data))
    return heics.sample_layout(data, t)


# ---------------------------------------------------------------- structure

def test_sample_layout_single_chunk():
    data = sequence(5)
    layout = _layout(data)
    assert [size for _, size in layout] == [4 + 6 + i for i in range(5)]
    for i, (at, size) in enumerate(layout):
        assert struct.unpack_from(">I", data, at)[0] == size - 4
        assert data[at + 6] == i                       # the sample's own marker byte


def test_sample_layout_follows_stsc_runs():
    # chunk 1 holds 2 samples, chunks 2.. hold 1 each.
    data = sequence(5, runs=[(1, 2, 1), (2, 1, 1)])
    layout = _layout(data)
    assert len(layout) == 5
    assert [data[at + 6] for at, _ in layout] == [0, 1, 2, 3, 4]


def test_still_image_is_rejected():
    still = _box(b"ftyp", b"heic" + bytes(4) + b"mif1heic") + _full(b"meta", b"")
    with pytest.raises(ValueError, match="moov"):
        list(heics.variants(still))


def test_boundaries_skip_current_and_stay_in_range():
    assert heics._boundaries(0) == [1, heics.U32_MAX]
    assert heics._boundaries(heics.U32_MAX) == [0, heics.U32_MAX - 1]
    assert 5 not in heics._boundaries(5, 5, 7)


# ---------------------------------------------------------------- variants

def test_variants_are_in_place_unique_and_classified():
    data = sequence(5, sync=[1, 4])
    items = list(heics.variants(data))
    names = [n for n, _ in items]
    assert len(names) == len(set(names))
    assert all(len(blob) == len(data) and blob != data for _, blob in items)
    kinds = {gate.kind(Path(f"x-{n}.heic")) for n in names}
    assert "other" not in kinds
    for expected in ("seq-stss-first", "seq-stsz-last", "seq-stco-first", "seq-stsc-perchunk",
                     "seq-stts-delta", "seq-entry-type", "seq-handler-type", "seq-hvcc-nalsize",
                     "seq-tkhd-width", "seq-ftyp-major", "seq-nal-middle"):
        assert expected in kinds, expected


def test_entry_type_swap_changes_only_the_fourcc():
    data = sequence(3)
    entry = heics.sample_entry(data, heics.tables(data, heics.sequence_track(data)))
    fourcc = entry.start + 4
    swapped = dict(heics.variants(data))["seq-entry-type-0"]
    assert data[fourcc:fourcc + 4] == b"hvc1" and swapped[fourcc:fourcc + 4] == b"hev1"
    assert swapped[:fourcc] == data[:fourcc] and swapped[fourcc + 4:] == data[fourcc + 4:]


def test_nal_size_variant_changes_only_low_bits():
    data = sequence(3)
    entry = heics.sample_entry(data, heics.tables(data, heics.sequence_track(data)))
    at = heics.hvcc(data, entry).payload + 21
    for size_minus_one in range(3):
        blob = dict(heics.variants(data))[f"seq-hvcc-nalsize-{size_minus_one}"]
        assert blob[at] & 3 == size_minus_one
        assert blob[at] & ~3 == data[at] & ~3
        assert blob[:at] == data[:at] and blob[at + 1:] == data[at + 1:]


def test_nal_variants_hit_the_first_length_prefix_of_each_pick():
    data = sequence(5)
    layout = _layout(data)
    by_name = dict(heics.variants(data))
    for pick, index in (("first", 0), ("middle", 2), ("last", 4)):
        blob = by_name[f"seq-nal-{pick}-0"]
        at = layout[index][0]
        assert struct.unpack_from(">I", blob, at)[0] == 0
        assert blob[:at] == data[:at] and blob[at + 4:] == data[at + 4:]


def test_main_writes_variants(tmp_path):
    src = tmp_path / "s.heic"
    src.write_bytes(sequence(4))
    out = tmp_path / "out"
    assert heics.main(["variants", str(src), "--out", str(out)]) == 0
    files = sorted(out.iterdir())
    assert files and all(f.name.startswith("s-seq-") and f.suffix == ".heic" for f in files)


def test_profiles_are_bounded_and_cross_the_frame_budget():
    for name, p in heics.PROFILES.items():
        w, h = (int(x) for x in p.size.split("x"))
        assert w * h <= 128 * 96, name                       # small: fast executions
        assert p.gop in ("low-delay", "intra-only", "unrestricted"), name
    # At least one inter-coded profile is longer than the harness's 16-frame
    # leading budget, so its last frame is reached via the last-frame path.
    assert any(p.frames > 16 and p.gop != "intra-only" for p in heics.PROFILES.values())
