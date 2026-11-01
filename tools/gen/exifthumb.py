#!/usr/bin/env python3
"""JPEG files with an embedded EXIF thumbnail, and variants of them (lane 4, ImageIO).

The thumbnail pass of the ImageIO harness takes a file's own thumbnail when
it has one. In a JPEG that thumbnail sits inside the APP1 "Exif" segment: a
TIFF structure whose IFD1 gives its offset (JPEGInterchangeFormat, 513) and
length (JPEGInterchangeFormatLength, 514). Few real photos carry one, and
byte mutation rarely lands on those two fields, let alone on a pair whose sum
overflows. So:

* ``build`` writes a JPEG with an APP1 Exif segment: IFD0 (orientation), an
  EXIF IFD with a UserComment, and IFD1 pointing at an embedded thumbnail;
* ``variants`` edits one thing per output file, in place (sizes don't change):
  - the thumbnail (offset, length) pair: boundary values, values running past
    the TIFF, and pairs whose sum wraps 32 bits;
  - count and offset of every out-of-line ASCII/UNDEFINED entry (UserComment,
    MakerNote, descriptions);
  - every SHORT/LONG field in every IFD (``--all-tags``; tools/gen/dng.py);
  - the length field of every marker segment before the scan: 0-3, +-1, up
    to and just past the end of the file, 0xFFFF.

Authorized / own-machine research only (SECURITY.md).

Usage:
    python tools/gen/exifthumb.py build MAIN.jpg THUMB.jpg --out WITH_THUMB.jpg
    python tools/gen/exifthumb.py variants FILE.jpg ... --out DIR [--all-tags]
"""

from __future__ import annotations

import argparse
import itertools
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import dng  # noqa: E402

SOI, SOS, EOI = 0xFFD8, 0xFFDA, 0xFFD9
EXIF_HEADER = b"Exif\0\0"
THUMB_OFFSET, THUMB_LENGTH = 513, 514
EXIF_IFD, GPS_IFD, INTEROP_IFD = 34665, 34853, 40965
ASCII, SHORT, LONG, UNDEFINED = 2, 3, 4, 7
_MAX_IFDS = 16


# ---------------------------------------------------------------- JPEG structure

def segments(jpeg: bytes) -> list[tuple[int, int, int]]:
    """(marker, offset of the marker, segment length field) up to the first scan."""
    if struct.unpack_from(">H", jpeg)[0] != SOI:
        raise ValueError("not a JPEG file")
    out, at = [], 2
    while at + 4 <= len(jpeg):
        marker, length = struct.unpack_from(">HH", jpeg, at)
        if marker & 0xFF00 != 0xFF00:
            break
        out.append((marker, at, length))
        if marker in (SOS, EOI):
            break
        at += 2 + length
    return out


def exif_range(jpeg: bytes) -> tuple[int, int] | None:
    """(start, end) of the TIFF structure inside the first APP1 Exif segment."""
    for marker, at, length in segments(jpeg):
        body = at + 4
        if marker == 0xFFE1 and jpeg[body:body + 6] == EXIF_HEADER:
            return body + 6, min(at + 2 + length, len(jpeg))
    return None


def entries(tiff: bytes) -> list[tuple[int, int, int, int]]:
    """(tag, type, count, entry offset) of every entry of IFD0, its chain and
    the EXIF, GPS and interoperability IFDs."""
    bo = dng._order(tiff)
    todo, seen, out = [struct.unpack_from(bo + "I", tiff, 4)[0]], set(), []
    while todo and len(seen) < _MAX_IFDS:
        at = todo.pop(0)
        if not at or at in seen or at + 2 > len(tiff):
            continue
        seen.add(at)
        (n,) = struct.unpack_from(bo + "H", tiff, at)
        for i in range(n):
            e = at + 2 + 12 * i
            if e + 12 > len(tiff):
                break
            tag, typ, count = struct.unpack_from(bo + "HHI", tiff, e)
            out.append((tag, typ, count, e))
            if tag in (EXIF_IFD, GPS_IFD, INTEROP_IFD):
                todo.append(struct.unpack_from(bo + "I", tiff, e + 8)[0])
        nxt = at + 2 + 12 * n
        if nxt + 4 <= len(tiff):
            todo.append(struct.unpack_from(bo + "I", tiff, nxt)[0])
    return out


# ---------------------------------------------------------------- build

def _ifd(items: list[tuple[int, int, int, int]], next_ifd: int) -> bytes:
    """A little-endian IFD from (tag, type, count, value-or-offset) entries."""
    body = struct.pack("<H", len(items))
    for tag, typ, count, value in sorted(items):
        if typ == SHORT and count == 1:
            body += struct.pack("<HHIHH", tag, typ, count, value, 0)
        else:
            body += struct.pack("<HHII", tag, typ, count, value)
    return body + struct.pack("<I", next_ifd)


def build(main: bytes, thumb: bytes, comment: bytes = b"ASCII\0\0\0iosr thumbnail") -> bytes:
    """``main`` with its own APP1 Exif segments replaced by one carrying ``thumb``."""
    ifd0_at = 8
    ifd0_len = 2 + 12 * 2 + 4
    exif_at = ifd0_at + ifd0_len
    exif_len = 2 + 12 + 4
    ifd1_at = exif_at + exif_len
    ifd1_len = 2 + 12 * 3 + 4
    comment_at = ifd1_at + ifd1_len
    thumb_at = comment_at + len(comment)
    tiff = (b"II*\0" + struct.pack("<I", ifd0_at)
            + _ifd([(274, SHORT, 1, 1), (EXIF_IFD, LONG, 1, exif_at)], ifd1_at)
            + _ifd([(37510, UNDEFINED, len(comment), comment_at)], 0)
            + _ifd([(259, SHORT, 1, 6), (THUMB_OFFSET, LONG, 1, thumb_at),
                    (THUMB_LENGTH, LONG, 1, len(thumb))], 0)
            + comment + thumb)
    payload = EXIF_HEADER + tiff
    if len(payload) + 2 > 0xFFFF:
        raise ValueError(f"thumbnail too large for one APP1 segment ({len(thumb)} bytes)")
    app1 = struct.pack(">HH", 0xFFE1, len(payload) + 2) + payload
    kept = bytearray(main[:2])
    segs = segments(main)
    for marker, at, length in segs:
        if marker in (SOS, EOI):
            break
        if not (marker == 0xFFE1 and main[at + 4:at + 10] == EXIF_HEADER):
            kept += main[at:at + 2 + length]
    rest = segs[-1][1] if segs and segs[-1][0] in (SOS, EOI) else len(main)
    return bytes(kept[:2]) + app1 + bytes(kept[2:]) + main[rest:]


# ---------------------------------------------------------------- variants

def _splice(jpeg: bytes, start: int, tiff: bytes) -> bytes:
    return jpeg[:start] + tiff + jpeg[start + len(tiff):]


def _put(tiff: bytearray, at: int, value: int) -> None:
    struct.pack_into(dng._order(tiff) + "I", tiff, at, value & 0xFFFFFFFF)


def thumbnail_pairs(tiff: bytes):
    """(name, tiff) for boundary (offset, length) pairs of each embedded thumbnail."""
    found = {tag: e for tag, typ, _c, e in entries(tiff)
             if tag in (THUMB_OFFSET, THUMB_LENGTH) and typ == LONG}
    if len(found) < 2:
        return
    bo, size = dng._order(tiff), len(tiff)
    off0 = struct.unpack_from(bo + "I", tiff, found[THUMB_OFFSET] + 8)[0]
    len0 = struct.unpack_from(bo + "I", tiff, found[THUMB_LENGTH] + 8)[0]
    offsets = {0, 8, off0 - 1, off0 + 1, size - 1, size, size + 1, 0x7FFFFFFF,
               0xFFFFFFF0, 0xFFFFFFFF, off0}
    lengths = {0, 1, 2, len0 - 1, len0 + 1, size - off0, size - off0 + 1, size,
               0x7FFFFFFF, 0xFFFFFFFF, len0}
    for o, n in itertools.product(sorted(offsets), sorted(lengths)):
        if (o, n) == (off0, len0) or o < 0 or n < 0:
            continue
        buf = bytearray(tiff)
        _put(buf, found[THUMB_OFFSET] + 8, o)
        _put(buf, found[THUMB_LENGTH] + 8, n)
        yield f"thumb-off{o:x}-len{n:x}", bytes(buf)
    for k in (1, 0x10, 0x100):                       # offset + length wraps 32 bits
        buf = bytearray(tiff)
        _put(buf, found[THUMB_OFFSET] + 8, 0x100000000 - k)
        _put(buf, found[THUMB_LENGTH] + 8, k + len0)
        yield f"thumb-wrap{k:x}", bytes(buf)


def blob_variants(tiff: bytes):
    """(name, tiff) editing count and offset of out-of-line ASCII/UNDEFINED entries."""
    size = len(tiff)
    for tag, typ, count, e in entries(tiff):
        if typ not in (ASCII, UNDEFINED) or count <= 4:
            continue
        for c in sorted({0, 1, 7, 8, 9, count - 1, count + 1, size, 0xFFFF, 0xFFFFFFFF}
                        - {count}):
            buf = bytearray(tiff)
            _put(buf, e + 4, c)
            yield f"tag{tag}-count{c:x}", bytes(buf)
        for o in (0, size - 1, size, 0xFFFFFFFF):
            buf = bytearray(tiff)
            _put(buf, e + 8, o)
            yield f"tag{tag}-at{o:x}", bytes(buf)


def marker_variants(jpeg: bytes):
    """(name, jpeg) with one marker segment's length field changed."""
    for marker, at, length in segments(jpeg):
        if marker in (SOS, EOI):
            break
        remaining = len(jpeg) - at - 2
        for v in sorted({0, 1, 2, 3, length - 1, length + 1, remaining, remaining + 1,
                         0xFFFF} - {length}):
            if 0 <= v <= 0xFFFF:
                buf = bytearray(jpeg)
                struct.pack_into(">H", buf, at + 2, v)
                yield f"m{marker & 0xFF:02X}at{at}-len{v}", bytes(buf)


def variants(jpeg: bytes, *, all_tags: bool = False):
    """Yield (name, bytes): one in-place change per variant."""
    rng = exif_range(jpeg)
    if rng is not None:
        start, end = rng
        tiff = jpeg[start:end]
        for name, t in itertools.chain(thumbnail_pairs(tiff), blob_variants(tiff)):
            yield name, _splice(jpeg, start, t)
        if all_tags:
            for name, t in dng.mismatch_variants(tiff, all_tags=True):
                yield f"exif-{name}", _splice(jpeg, start, t)
    yield from marker_variants(jpeg)


# ---------------------------------------------------------------- driver

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="embed THUMB as MAIN's EXIF thumbnail")
    b.add_argument("main", type=pathlib.Path)
    b.add_argument("thumb", type=pathlib.Path)
    b.add_argument("--out", type=pathlib.Path, required=True)
    v = sub.add_parser("variants", help="one-change variants of JPEG files")
    v.add_argument("jpegs", nargs="+", type=pathlib.Path)
    v.add_argument("--out", type=pathlib.Path, required=True)
    v.add_argument("--all-tags", action="store_true",
                   help="also vary every SHORT/LONG field of every IFD (dng.py)")
    args = ap.parse_args(argv)
    if args.cmd == "build":
        args.out.write_bytes(build(args.main.read_bytes(), args.thumb.read_bytes()))
        print(f"wrote {args.out}", file=sys.stderr)
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    total = 0
    for path in args.jpegs:
        try:
            items = list(variants(path.read_bytes(), all_tags=args.all_tags))
        except (ValueError, struct.error) as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)
            continue
        for name, data in items:
            (args.out / f"{path.stem}-{name}.jpg").write_bytes(data)
        total += len(items)
        print(f"{path.name}: {len(items)} variants", file=sys.stderr)
    print(f"wrote {total} variants to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
