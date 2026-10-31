#!/usr/bin/env python3
"""DNG seed writer and field-mismatch generator for lane 1 (ImageIO / RawCamera).

Anchor: CVE-2025-43300 (exploited in the wild), an out-of-bounds write in
ImageIO's DNG path when the TIFF SamplesPerPixel disagreed with the component
count of the embedded lossless-JPEG header. Bugs cluster: this generator makes
every such pair of descriptions disagree, one field at a time.

* ``base``: write small valid DNGs from scratch (no third-party code): CFA and
  LinearRaw, uncompressed and lossless JPEG (SOF3, predictor 1, one or two
  JPEG components per row as Adobe's encoder does for CFA), strips and tiles.
* ``mismatch``: for each DNG, patch one value in place per variant, so
  everything else stays valid: TIFF fields (sizes, bit depth, compression,
  samples, tiling, CFA geometry, crop/active area), the JPEG frame and scan
  headers (P, Y, X, Nf, sampling, Ns, predictor, point transform), and pairs
  that keep the two layers inconsistent (SamplesPerPixel/Nf,
  BitsPerSample/P, TileWidth/X, TileLength/Y, ImageWidth/TileWidth).

* ``mismatch --all-tags``: also every other SHORT/LONG value in every IFD
  (IFD0 and its chain, SubIFDs, the EXIF IFD), for TIFF-based camera RAW
  (DNG, CR2, NEF, ARW, PEF, SRW, ORF, RW2: either byte order).
* ``mismatch --makernote N``: also N single-byte edits inside the EXIF
  MakerNote, where camera-specific decoders read their parameters.

**Limitation (macOS 26.x):** ImageIO classifies the ``base`` seeds as plain
TIFF and decodes only their 8x8 preview; RawCamera never loads (tried: raw in
IFD0 and in a SubIFD, generic/Leica/Pentax/iPhone camera identities). Feed
``mismatch`` real RAW files instead: they do reach RawCamera (a public iPhone
12 Pro ProRAW from raw.pixls.us, CC0: RawCamera loads, and corrupting its raw
tiles changes the decoded output). Check with ``sips -g format`` and the gate.

Authorized / own-machine research only (SECURITY.md).

Usage:
    python tools/gen/dng.py base --out DIR
    python tools/gen/dng.py mismatch RAW ... --out DIR [--all-tags] [--makernote N]
"""

from __future__ import annotations

import argparse
import itertools
import pathlib
import random
import struct
import sys

# ---------------------------------------------------------------- lossless JPEG

# One DC table for every component: categories 0-16, all 5-bit codes.
_BITS = [0, 0, 0, 0, 17] + [0] * 11
_HUFFVAL = list(range(17))
_CODES = {cat: (cat, 5) for cat in _HUFFVAL}            # canonical: code == category


class _BitWriter:
    def __init__(self) -> None:
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, value: int, bits: int) -> None:
        for i in range(bits - 1, -1, -1):
            self.acc = (self.acc << 1) | ((value >> i) & 1)
            self.n += 1
            if self.n == 8:
                self.out.append(self.acc)
                if self.acc == 0xFF:
                    self.out.append(0x00)                # byte stuffing
                self.acc = self.n = 0

    def flush(self) -> bytes:
        while self.n:
            self.put(1, 1)                               # pad with ones
        return bytes(self.out)


def ljpeg_encode(rows: list[list[int]], ncomp: int, precision: int) -> bytes:
    """Lossless JPEG (SOF3, predictor 1) of interleaved samples.

    ``rows`` holds ``height`` rows of ``width * ncomp`` samples."""
    height, width = len(rows), len(rows[0]) // ncomp
    w = _BitWriter()
    for y, row in enumerate(rows):
        for x in range(width):
            for c in range(ncomp):
                if x > 0:
                    pred = row[(x - 1) * ncomp + c]
                elif y > 0:
                    pred = rows[y - 1][c]
                else:
                    pred = 1 << (precision - 1)
                diff = (row[x * ncomp + c] - pred) & 0xFFFF
                if diff >= 0x8000:
                    diff -= 0x10000
                cat = 16 if diff == -32768 else abs(diff).bit_length()
                code, length = _CODES[cat]
                w.put(code, length)
                if 0 < cat < 16:
                    w.put(diff if diff > 0 else diff + (1 << cat) - 1, cat)
    dht = bytes([0x00] + _BITS + _HUFFVAL)
    sof = struct.pack(">BHHB", precision, height, width, ncomp) + b"".join(
        bytes([c + 1, 0x11, 0]) for c in range(ncomp))
    sos = bytes([ncomp]) + b"".join(bytes([c + 1, 0x00]) for c in range(ncomp)) + bytes([1, 0, 0])

    def seg(marker: int, body: bytes) -> bytes:
        return struct.pack(">HH", 0xFF00 | marker, len(body) + 2) + body

    return (b"\xFF\xD8" + seg(0xC4, dht) + seg(0xC3, sof) + seg(0xDA, sos)
            + w.flush() + b"\xFF\xD9")


# ---------------------------------------------------------------- TIFF / DNG writer

SHORT, LONG, ASCII, BYTE, RATIONAL, SRATIONAL = 3, 4, 2, 1, 5, 10
_SIZE = {BYTE: 1, ASCII: 1, SHORT: 2, LONG: 4, RATIONAL: 8, SRATIONAL: 8}
_FMT = {BYTE: "B", ASCII: "B", SHORT: "H", LONG: "I", RATIONAL: "I", SRATIONAL: "i"}


def _pattern(width: int, height: int, spp: int, bps: int) -> list[list[int]]:
    top = (1 << bps) - 1
    return [[((x * 37 + y * 101 + s * 53) * 97) % (top + 1) >> 2
             for x in range(width) for s in range(spp)] for y in range(height)]


def _pack(rows: list[list[int]], bps: int) -> bytes:
    if bps == 8:
        return bytes(v for r in rows for v in r)
    return b"".join(struct.pack(f"<{len(r)}H", *r) for r in rows)   # 16-bit, file order


def make_dng(width: int = 32, height: int = 32, *, cfa: bool = True, bps: int = 16,
             ljpeg: bool = True, jpeg_comps: int = 2, tile: int | None = None,
             make: str = "iosr", model: str = "iosr-gen", unique: str = "iosr-gen") -> bytes:
    """A small DNG in the standard layout: an 8x8 RGB preview in IFD0 (which
    carries the camera-wide DNG tags) and the raw image in a SubIFD."""
    spp = 1 if cfa else 3
    if not ljpeg and bps not in (8, 16):
        raise ValueError("uncompressed seeds use 8 or 16 bits")
    tw, th = (tile, tile) if tile else (width, height)
    pieces = []
    for ty in range(0, height, th):
        for tx in range(0, width, tw):
            rows = [r[tx * spp:(tx + tw) * spp] for r in _pattern(width, height, spp, bps)[ty:ty + th]]
            rows = [r + [0] * (tw * spp - len(r)) for r in rows] + \
                   [[0] * (tw * spp)] * (th - len(rows))
            if ljpeg:
                n = jpeg_comps if (cfa and (tw * spp) % jpeg_comps == 0) else spp
                pieces.append(ljpeg_encode(rows, n, bps))
            else:
                pieces.append(_pack(rows, bps))
    raw_tags: list[tuple[int, int, list]] = [
        (254, LONG, [0]), (256, LONG, [width]), (257, LONG, [height]),
        (258, SHORT, [bps] * spp), (259, SHORT, [7 if ljpeg else 1]),
        (262, SHORT, [32803 if cfa else 34892]), (277, SHORT, [spp]), (284, SHORT, [1]),
        (50714, LONG, [0]), (50717, LONG, [(1 << bps) - 1]),
        (50719, LONG, [0, 0]), (50720, LONG, [width, height]),
    ]
    if cfa:
        raw_tags += [(33421, SHORT, [2, 2]), (33422, BYTE, [0, 1, 1, 2]),
                     (50710, BYTE, [0, 1, 2]), (50711, SHORT, [1])]
    if tile:
        raw_tags += [(322, LONG, [tw]), (323, LONG, [th]),
                     (324, LONG, [0] * len(pieces)), (325, LONG, [len(p) for p in pieces])]
    else:
        raw_tags += [(273, LONG, [0]), (278, LONG, [height]), (279, LONG, [len(pieces[0])])]
    preview = bytes((x * 32, y * 32, 128) [c] for y in range(8) for x in range(8) for c in range(3))
    main_tags: list[tuple[int, int, list]] = [
        (254, LONG, [1]), (256, LONG, [8]), (257, LONG, [8]), (258, SHORT, [8, 8, 8]),
        (259, SHORT, [1]), (262, SHORT, [2]), (273, LONG, [0]),
        (271, ASCII, list(make.encode() + b"\0")), (272, ASCII, list(model.encode() + b"\0")),
        (274, SHORT, [1]), (277, SHORT, [3]), (278, LONG, [8]), (279, LONG, [len(preview)]),
        (284, SHORT, [1]), (330, LONG, [0]),
        (50706, BYTE, [1, 4, 0, 0]), (50707, BYTE, [1, 1, 0, 0]),
        (50708, ASCII, list(unique.encode() + b"\0")),
        (50721, SRATIONAL, [10000, 10000, 0, 1, 0, 1, 0, 1, 10000, 10000, 0, 1,
                            0, 1, 0, 1, 10000, 10000]),
        (50728, RATIONAL, [1, 1, 1, 1, 1, 1]), (50778, SHORT, [21]),
    ]
    return _write_tiff([sorted(main_tags), sorted(raw_tags)], [[preview], pieces],
                       [273, 324 if tile else 273])


def _write_tiff(ifds, pieces, offsets_tags) -> bytes:
    """Write IFD0 and its SubIFDs (IFD0 tag 330 points at IFDs 1..n).

    ``ifds[i]`` is a sorted tag list, ``pieces[i]`` its strips or tiles, and
    ``offsets_tags[i]`` the tag (273/324) that receives their offsets."""
    def encode(typ, vals):
        return struct.pack(f"<{len(vals)}{_FMT[typ]}", *vals)

    # Pass 1: where each IFD, its out-of-line values and each data piece go.
    at, ifd_at, extra_at = 8, [], []
    for tags in ifds:
        ifd_at.append(at)
        at += 2 + 12 * len(tags) + 4
        extra_at.append(at)
        at += sum(len(encode(t, v)) + len(encode(t, v)) % 2
                  for _tag, t, v in tags if len(encode(t, v)) > 4)
    piece_at = []
    for plist in pieces:
        offs = []
        for p in plist:
            offs.append(at)
            at += len(p) + len(p) % 2
        piece_at.append(offs)
    # Pass 2: write, filling strip/tile offsets and the SubIFD pointers.
    out = bytearray(b"II*\0" + struct.pack("<I", 8))
    for i, tags in enumerate(ifds):
        extras = bytearray()
        body = bytearray(struct.pack("<H", len(tags)))
        for tag, typ, vals in tags:
            if tag == offsets_tags[i]:
                vals = piece_at[i]
            elif tag == 330 and i == 0:
                vals = ifd_at[1:]
            raw = encode(typ, vals)
            count = len(vals) // (2 if typ in (RATIONAL, SRATIONAL) else 1)
            if len(raw) > 4:
                value = struct.pack("<I", extra_at[i] + len(extras))
                extras += raw + b"\0" * (len(raw) % 2)
            else:
                value = raw.ljust(4, b"\0")
            body += struct.pack("<HHI", tag, typ, count) + value
        out += body + b"\0\0\0\0" + extras
    for plist in pieces:
        for p in plist:
            out += p + b"\0" * (len(p) % 2)
    return bytes(out)


def base_set() -> dict[str, bytes]:
    """Small seeds covering the DNG layouts the mismatch generator works on."""
    seeds = {}
    for bps in (8, 12, 14, 16):
        seeds[f"cfa-ljpeg2-{bps}"] = make_dng(bps=bps, jpeg_comps=2)
        seeds[f"cfa-ljpeg1-{bps}"] = make_dng(bps=bps, jpeg_comps=1)
    seeds["cfa-ljpeg2-16-tiled"] = make_dng(48, 40, tile=16)
    seeds["linear-ljpeg-16"] = make_dng(cfa=False)
    seeds["cfa-raw-16"] = make_dng(ljpeg=False)
    seeds["cfa-raw-8"] = make_dng(ljpeg=False, bps=8)
    seeds["linear-raw-16-tiled"] = make_dng(48, 40, cfa=False, ljpeg=False, tile=16)
    return seeds


# ---------------------------------------------------------------- mismatch generator

# TIFF fields that describe the image's geometry or encoding.
TIFF_FIELDS = {256: "ImageWidth", 257: "ImageLength", 258: "BitsPerSample",
               259: "Compression", 277: "SamplesPerPixel", 278: "RowsPerStrip",
               279: "StripByteCounts", 322: "TileWidth", 323: "TileLength",
               325: "TileByteCounts", 33421: "CFARepeatPatternDim",
               50713: "BlackLevelRepeatDim", 50719: "DefaultCropOrigin",
               50720: "DefaultCropSize", 50829: "ActiveArea"}


def _values(orig: int, width: int) -> list[int]:
    top = (1 << (8 * width)) - 1
    vals = {0, 1, 2, 3, 4, 7, 8, 16, orig - 1, orig + 1, orig * 2, 0x7FFF, 0xFFFF}
    if width == 4:
        vals.add(0xFFFFFFFF)
    return sorted(v & top for v in vals if v != orig and v >= 0)


SUBIFDS, EXIF_IFD, MAKERNOTE = 330, 34665, 37500
_MAX_IFDS = 32


def _order(data: bytes) -> str:
    """struct byte order of a TIFF-based file (the magic after it varies: ORF, RW2)."""
    if data[:2] == b"II":
        return "<"
    if data[:2] == b"MM":
        return ">"
    raise ValueError("not a TIFF-based file")


def parse_ifds(data: bytes) -> list[dict[int, tuple[int, int, int]]]:
    """IFD0, its SubIFDs, the IFD chain and the EXIF IFD, in that order:
    tag -> (type, count, offset of the value field)."""
    bo = _order(data)
    todo, seen, ifds = [struct.unpack_from(bo + "I", data, 4)[0]], set(), []
    while todo and len(ifds) < _MAX_IFDS:
        at = todo.pop(0)
        if not at or at in seen or at + 2 > len(data):
            continue
        seen.add(at)
        (n,) = struct.unpack_from(bo + "H", data, at)
        ifd = {}
        for i in range(n):
            tag, typ, count = struct.unpack_from(bo + "HHI", data, at + 2 + 12 * i)
            field = at + 2 + 12 * i + 8
            if _SIZE.get(typ, 1) * count > 4:
                field = struct.unpack_from(bo + "I", data, field)[0]
            ifd[tag] = (typ, count, field)
        ifds.append(ifd)
        if SUBIFDS in ifd:
            typ, count, field = ifd[SUBIFDS]
            todo += list(struct.unpack_from(f"{bo}{min(count, _MAX_IFDS)}I", data, field))
        nxt = at + 2 + 12 * n
        if nxt + 4 <= len(data):
            todo.append(struct.unpack_from(bo + "I", data, nxt)[0])
        if EXIF_IFD in ifd:
            todo.append(_read(data, ifd[EXIF_IFD][0], ifd[EXIF_IFD][2]))
    return ifds


def _read(data: bytes, typ: int, at: int) -> int:
    return struct.unpack_from(_order(data) + ("H" if typ == SHORT else "I"), data, at)[0]


def _write(buf: bytearray, typ: int, at: int, value: int) -> None:
    struct.pack_into(_order(buf) + ("H" if typ == SHORT else "I"), buf, at,
                     value & (0xFFFF if typ == SHORT else 0xFFFFFFFF))


def _jpeg_fields(data: bytes, ifd) -> dict[str, tuple[int, int]]:
    """JPEG header fields of the first strip/tile: name -> (offset, width)."""
    for off_tag in (273, 324):
        if off_tag in ifd:
            typ, _count, field = ifd[off_tag]
            start = _read(data, typ, field)
            break
    else:
        return {}
    out = {}
    sof = data.find(b"\xFF\xC3", start, start + 4096)
    if sof >= 0:
        nf = data[sof + 9] if sof + 9 < len(data) else 0
        out.update({"P": (sof + 4, 1), "Y": (sof + 5, 2), "X": (sof + 7, 2), "Nf": (sof + 9, 1)})
        if nf:
            out["HV"] = (sof + 11, 1)
    sos = data.find(b"\xFF\xDA", start, start + 4096)
    if sos >= 0:
        ns = data[sos + 4]
        out["Ns"] = (sos + 4, 1)
        base = sos + 5 + 2 * ns
        out.update({"Ss": (base, 1), "Al": (base + 2, 1)})
    return out


def _patch_jpeg(buf: bytearray, at: int, width: int, value: int) -> None:
    if width == 1:
        buf[at] = value & 0xFF
    else:
        struct.pack_into(">H", buf, at, value & 0xFFFF)


def _field_variants(data: bytes, k: int, ifd, tag: int, name: str):
    typ, count, field = ifd[tag]
    for idx in range(min(count, 2)):
        at = field + idx * _SIZE[typ]
        if at + _SIZE[typ] > len(data):
            return
        orig = _read(data, typ, at)
        for v in _values(orig, _SIZE[typ]):
            buf = bytearray(data)
            _write(buf, typ, at, v)
            yield f"ifd{k}-{name}{idx or ''}-{v}", bytes(buf)


def _makernote_variants(data: bytes, k: int, ifd, edits: int, rng: random.Random):
    _typ, count, field = ifd[MAKERNOTE]
    end = min(field + count, len(data))
    if count <= 4 or end <= field:
        return
    for at in sorted(rng.sample(range(field, end), min(edits, end - field))):
        orig = data[at]
        for v in sorted({0x00, 0x01, 0x7F, 0x80, 0xFF, orig ^ 0xFF} - {orig}):
            buf = bytearray(data)
            buf[at] = v
            yield f"ifd{k}-makernote-{at - field}-{v}", bytes(buf)


def mismatch_variants(data: bytes, *, all_tags: bool = False, makernote: int = 0,
                      seed: int = 1):
    """Yield (name, bytes): one in-place change per variant, then pairs."""
    ifds = parse_ifds(data)
    rng = random.Random(seed)
    for k, ifd in enumerate(ifds):
        for tag in sorted(ifd):
            if ifd[tag][0] not in (SHORT, LONG):
                continue
            if tag in TIFF_FIELDS:
                yield from _field_variants(data, k, ifd, tag, TIFF_FIELDS[tag])
            elif all_tags:
                yield from _field_variants(data, k, ifd, tag, f"tag{tag}x")
        if makernote and MAKERNOTE in ifd:
            yield from _makernote_variants(data, k, ifd, makernote, rng)
        jf = _jpeg_fields(data, ifd)
        for name, (at, width) in jf.items():
            orig = data[at] if width == 1 else struct.unpack_from(">H", data, at)[0]
            extra = list(range(8)) + [255] if name in ("Ss", "Al", "Nf", "Ns") else []
            for v in sorted(set(_values(orig, width) + extra) - {orig}):
                buf = bytearray(data)
                _patch_jpeg(buf, at, width, v)
                yield f"ifd{k}-jpeg{name}-{v}", bytes(buf)
        pairs = [((277, None), "Nf"), ((258, None), "P"), ((322, None), "X"),
                 ((323, None), "Y"), ((256, None), "X"), ((257, None), "Y")]
        for (tag, _), jname in pairs:
            if tag not in ifd or jname not in jf or ifd[tag][0] not in (SHORT, LONG):
                continue
            typ, _count, field = ifd[tag]
            at, width = jf[jname]
            t_orig = _read(data, typ, field)
            j_orig = data[at] if width == 1 else struct.unpack_from(">H", data, at)[0]
            for tv, jv in itertools.product((1, 2, 3, 4, t_orig), (1, 2, 3, 4, j_orig)):
                if (tv, jv) == (t_orig, j_orig) or tv == jv:
                    continue
                buf = bytearray(data)
                _write(buf, typ, field, tv)
                _patch_jpeg(buf, at, width, jv)
                yield f"ifd{k}-pair-{TIFF_FIELDS.get(tag, tag)}{tv}-{jname}{jv}", bytes(buf)
        if 256 in ifd and 322 in ifd:
            for a, b in itertools.product((1, 2, 3, 4), (1, 2, 3, 4)):
                if a == b:
                    continue
                buf = bytearray(data)
                _write(buf, ifd[256][0], ifd[256][2], a)
                _write(buf, ifd[322][0], ifd[322][2], b)
                yield f"ifd{k}-pair-ImageWidth{a}-TileWidth{b}", bytes(buf)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("base", help="write the base DNG seeds")
    b.add_argument("--out", type=pathlib.Path, required=True)
    m = sub.add_parser("mismatch", help="write field-mismatch variants of DNGs "
                       "(large RAW files: use tools/gen/rawsweep.py, which streams)")
    m.add_argument("dngs", nargs="+", type=pathlib.Path)
    m.add_argument("--out", type=pathlib.Path, required=True)
    add_variant_args(m)
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    if args.cmd == "base":
        for name, data in base_set().items():
            (args.out / f"{name}.dng").write_bytes(data)
        print(f"wrote {len(base_set())} base DNGs to {args.out}", file=sys.stderr)
        return 0
    total = 0
    for path in args.dngs:
        try:
            items = list(mismatch_variants(path.read_bytes(), **variant_kwargs(args)))
        except (ValueError, struct.error, IndexError) as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)
            continue
        for name, data in items:
            (args.out / f"{path.stem}-{name}{path.suffix.lower() or '.dng'}").write_bytes(data)
        total += len(items)
        print(f"{path.name}: {len(items)} variants", file=sys.stderr)
    print(f"wrote {total} variants to {args.out}", file=sys.stderr)
    return 0


def add_variant_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--all-tags", action="store_true",
                    help="also every other SHORT/LONG value in every IFD")
    ap.add_argument("--makernote", type=int, default=0, metavar="N",
                    help="also N single-byte edits inside the EXIF MakerNote")
    ap.add_argument("--seed", type=int, default=1, help="MakerNote position seed")


def variant_kwargs(args: argparse.Namespace) -> dict:
    return {"all_tags": args.all_tags, "makernote": args.makernote, "seed": args.seed}


if __name__ == "__main__":
    raise SystemExit(main())
