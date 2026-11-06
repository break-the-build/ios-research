#!/usr/bin/env python3
"""HEIF image sequences and variants of them (ImageIO, the msf1 sequence path).

A HEIF image sequence (brand msf1, handler 'pict') is an ISOBMFF track of HEVC
pictures: one intra picture, then P/B pictures predicted from earlier ones.
ImageIO exposes every picture as a frame. That path -- the sample tables, the
hvc1 sample entry, inter prediction and the decoded-picture buffer -- is a
different surface from the still-image 'meta'/'iloc' path that real-file seeds
(iPhone photos) exercise, and no seed reached it. The harness decodes the
leading frames plus the middle and last ones (IOSR_IMGIO_MAX_FRAMES), so a
sequence longer than the budget reaches the end of its reference chain.

* ``build`` encodes small sequences with ffmpeg (frame source) and libheif's
  heif-enc (x265), one profile per coding configuration: low-delay I+P and
  B-frame GOPs, lossless (cu_transquant_bypass), monochrome 4:0:0, 10-bit,
  several keyframes, x265 tool knobs, and a sequence whose final frame
  differs from its poster frame;
* ``variants`` edits one field per output file, in place (sizes don't change):
  sync-sample, sample-size, sample-to-chunk, chunk-offset and time-to-sample
  tables; the track handler and sample-entry type; the hvcC NAL length size
  and array count; the track dimensions; the major brand; and the first NAL
  length of the first, middle and last samples.

Authorized / own-machine research only (SECURITY.md).

Usage:
    python tools/gen/heics.py build --out DIR [--profile NAME ...]
    python tools/gen/heics.py variants FILE.heic ... --out DIR
    python tools/gen/heics.py profiles
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass

# ---------------------------------------------------------------- ISOBMFF structure

CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"edts", b"udta",
              b"meta", b"iprp", b"ipco", b"stsd", b"hvc1", b"hev1"}
# Children of these start after fixed fields: FullBox header (meta), entry
# count (stsd), VisualSampleEntry fields (hvc1/hev1).
CHILD_OFFSET = {b"meta": 4, b"stsd": 8, b"hvc1": 78, b"hev1": 78}
SAMPLE_ENTRIES = (b"hvc1", b"hev1")
SEQUENCE_HANDLERS = (b"pict", b"vide")
U32_MAX = 0xFFFFFFFF


@dataclass(frozen=True)
class Box:
    kind: bytes
    start: int
    size: int
    header: int

    @property
    def payload(self) -> int:
        return self.start + self.header

    @property
    def end(self) -> int:
        return self.start + self.size


def boxes(data: bytes, start: int = 0, end: int | None = None) -> list[Box]:
    """The boxes laid end to end in data[start:end]; stops at a malformed size."""
    end = len(data) if end is None else end
    out, at = [], start
    while at + 8 <= end:
        size, kind = struct.unpack_from(">I4s", data, at)
        header = 8
        if size == 1:
            if at + 16 > end:
                break
            size = struct.unpack_from(">Q", data, at + 8)[0]
            header = 16
        elif size == 0:
            size = end - at
        if size < header or at + size > end:
            break
        out.append(Box(kind, at, size, header))
        at += size
    return out


def children(data: bytes, box: Box) -> list[Box]:
    if box.kind not in CONTAINERS:
        return []
    return boxes(data, box.payload + CHILD_OFFSET.get(box.kind, 0), box.end)


def child(data: bytes, box: Box, kind: bytes) -> Box | None:
    return next((b for b in children(data, box) if b.kind == kind), None)


@dataclass(frozen=True)
class Track:
    trak: Box
    handler: int            # offset of the 4-byte handler_type
    tkhd: Box
    stbl: Box


def sequence_track(data: bytes) -> Track:
    """The first image-sequence ('pict') or video ('vide') track."""
    moov = next((b for b in boxes(data) if b.kind == b"moov"), None)
    if moov is None:
        raise ValueError("no moov box: not an image sequence")
    for trak in (b for b in children(data, moov) if b.kind == b"trak"):
        mdia, tkhd = child(data, trak, b"mdia"), child(data, trak, b"tkhd")
        hdlr = mdia and child(data, mdia, b"hdlr")
        minf = mdia and child(data, mdia, b"minf")
        stbl = minf and child(data, minf, b"stbl")
        if not (hdlr and tkhd and stbl):
            continue
        handler = hdlr.payload + 8          # version/flags, pre_defined
        if data[handler:handler + 4] in SEQUENCE_HANDLERS:
            return Track(trak, handler, tkhd, stbl)
    raise ValueError("no 'pict' or 'vide' track")


def _u32(data: bytes, at: int) -> int:
    return struct.unpack_from(">I", data, at)[0]


@dataclass(frozen=True)
class Tables:
    stsd: Box
    stts: Box
    stsc: Box
    stsz: Box
    stco: Box               # stco or co64
    stss: Box | None


def tables(data: bytes, track: Track) -> Tables:
    found = {b.kind: b for b in children(data, track.stbl)}
    stco = found.get(b"stco") or found.get(b"co64")
    missing = [k for k in (b"stsd", b"stts", b"stsc", b"stsz") if k not in found]
    if missing or stco is None:
        raise ValueError(f"sample table incomplete: missing {missing or ['stco']}")
    return Tables(found[b"stsd"], found[b"stts"], found[b"stsc"], found[b"stsz"], stco,
                  found.get(b"stss"))


def sample_layout(data: bytes, t: Tables) -> list[tuple[int, int]]:
    """(file offset, size) of every sample, in decode order."""
    wide = t.stco.kind == b"co64"
    n_chunks = _u32(data, t.stco.payload + 4)
    width = 8 if wide else 4
    offsets = [struct.unpack_from(">Q" if wide else ">I", data, t.stco.payload + 8 + width * i)[0]
               for i in range(n_chunks)]
    fixed = _u32(data, t.stsz.payload + 4)
    count = _u32(data, t.stsz.payload + 8)
    sizes = [fixed] * count if fixed else [_u32(data, t.stsz.payload + 12 + 4 * i)
                                           for i in range(count)]
    runs = [struct.unpack_from(">III", data, t.stsc.payload + 8 + 12 * i)
            for i in range(_u32(data, t.stsc.payload + 4))]
    layout, sample = [], 0
    for ci, base in enumerate(offsets, start=1):
        per_chunk = next((spc for first, spc, _ in reversed(runs) if first <= ci), 0)
        at = base
        for _ in range(per_chunk):
            if sample >= count:
                return layout
            layout.append((at, sizes[sample]))
            at += sizes[sample]
            sample += 1
    return layout


def sample_entry(data: bytes, t: Tables) -> Box:
    entries = boxes(data, t.stsd.payload + 8, t.stsd.end)
    if not entries or entries[0].kind not in SAMPLE_ENTRIES:
        raise ValueError("first sample entry is not hvc1/hev1")
    return entries[0]


def hvcc(data: bytes, entry: Box) -> Box:
    box = child(data, entry, b"hvcC")
    if box is None or box.size < box.header + 23:
        raise ValueError("sample entry has no usable hvcC")
    return box


# ---------------------------------------------------------------- variants

def _with(data: bytes, at: int, fmt: str, value: int | bytes) -> bytes:
    out = bytearray(data)
    struct.pack_into(fmt, out, at, value)
    return bytes(out)


def _boundaries(current: int, *extra: int) -> list[int]:
    """0, +-1, the given values and 2^32-1; never the current value."""
    picked = [0, current - 1, current + 1, *extra, U32_MAX]
    seen, out = {current}, []
    for v in picked:
        if 0 <= v <= U32_MAX and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _field_variants(data: bytes, name: str, at: int, *extra: int):
    for i, v in enumerate(_boundaries(_u32(data, at), *extra)):
        yield f"seq-{name}-{i}", _with(data, at, ">I", v)


def _picks(count: int) -> dict[str, int]:
    """Indices of the first, middle and last entries (deduplicated)."""
    if count <= 0:
        return {}
    named = {"first": 0, "middle": count // 2, "last": count - 1}
    seen, out = set(), {}
    for k, i in named.items():
        if i not in seen:
            seen.add(i)
            out[k] = i
    return out


def table_variants(data: bytes, t: Tables, n_samples: int):
    # stss: which samples are sync (IDR) samples -- decoding can start there.
    if t.stss is not None:
        n_sync = _u32(data, t.stss.payload + 4)
        yield from _field_variants(data, "stss-count", t.stss.payload + 4, 2 * n_sync + 1)
        for k, i in _picks(n_sync).items():
            yield from _field_variants(data, f"stss-{k}", t.stss.payload + 8 + 4 * i,
                                       2, n_samples, n_samples + 1)
    # stsz: per-sample sizes, the count, and the constant-size field.
    yield from _field_variants(data, "stsz-count", t.stsz.payload + 8, 2 * n_samples)
    if _u32(data, t.stsz.payload + 4) == 0:
        yield "seq-stsz-fixed-0", _with(data, t.stsz.payload + 4, ">I", 1)
        yield "seq-stsz-fixed-1", _with(data, t.stsz.payload + 4, ">I", U32_MAX)
        for k, i in _picks(n_samples).items():
            yield from _field_variants(data, f"stsz-{k}", t.stsz.payload + 12 + 4 * i,
                                       len(data))
    # stsc: the first run of the sample-to-chunk table.
    if _u32(data, t.stsc.payload + 4):
        run = t.stsc.payload + 8
        yield from _field_variants(data, "stsc-first", run, 2)
        yield from _field_variants(data, "stsc-perchunk", run + 4, 2 * n_samples)
        yield from _field_variants(data, "stsc-desc", run + 8, 2)
    yield from _field_variants(data, "stsc-count", t.stsc.payload + 4, 2)
    # stco: chunk offsets (32-bit tables only; co64 offsets are left alone).
    yield from _field_variants(data, "stco-count", t.stco.payload + 4, 2)
    if t.stco.kind == b"stco":
        for k, i in _picks(_u32(data, t.stco.payload + 4)).items():
            yield from _field_variants(data, f"stco-{k}", t.stco.payload + 8 + 4 * i,
                                       len(data))
    # stts: decode timing; the sample count in a run must cover every sample.
    if _u32(data, t.stts.payload + 4):
        yield from _field_variants(data, "stts-samples", t.stts.payload + 8, 2 * n_samples)
        yield from _field_variants(data, "stts-delta", t.stts.payload + 12)
    yield from _field_variants(data, "stts-count", t.stts.payload + 4, 2)


def entry_variants(data: bytes, track: Track, entry: Box):
    kind = data[entry.start + 4:entry.start + 8]
    other = b"hev1" if kind == b"hvc1" else b"hvc1"
    yield "seq-entry-type-0", _with(data, entry.start + 4, "4s", other)
    for i, handler in enumerate((b"vide", b"pict", b"soun", b"auxv")):
        if handler != data[track.handler:track.handler + 4]:
            yield f"seq-handler-type-{i}", _with(data, track.handler, "4s", handler)
    box = hvcc(data, entry)
    at = box.payload + 21                   # ... | lengthSizeMinusOne (2 bits)
    flags = data[at]
    for size_minus_one in range(4):
        if size_minus_one != flags & 3:
            yield (f"seq-hvcc-nalsize-{size_minus_one}",
                   _with(data, at, "B", (flags & ~3) | size_minus_one))
    for i, arrays in enumerate((0, 1, 255)):
        if arrays != data[box.payload + 22]:
            yield f"seq-hvcc-arrays-{i}", _with(data, box.payload + 22, "B", arrays)


def track_variants(data: bytes, track: Track):
    version = data[track.tkhd.payload]
    at = track.tkhd.payload + (88 if version == 1 else 76)
    if at + 8 > track.tkhd.end:
        return
    for i, v in enumerate((0, 1 << 16, 0xFFFF << 16, U32_MAX)):
        yield f"seq-tkhd-width-{i}", _with(data, at, ">I", v)
        yield f"seq-tkhd-height-{i}", _with(data, at + 4, ">I", v)


def brand_variants(data: bytes):
    ftyp = next((b for b in boxes(data) if b.kind == b"ftyp"), None)
    if ftyp is None:
        return
    current = data[ftyp.payload:ftyp.payload + 4]
    for i, brand in enumerate((b"msf1", b"mif1", b"heic", b"isom")):
        if brand != current:
            yield f"seq-ftyp-major-{i}", _with(data, ftyp.payload, "4s", brand)


def nal_variants(data: bytes, layout: list[tuple[int, int]], length_size: int):
    """The first NAL length prefix of the first, middle and last samples."""
    fmt = {1: ">B", 2: ">H", 4: ">I"}.get(length_size)
    if fmt is None:
        return
    top = (1 << (8 * length_size)) - 1
    for k, i in _picks(len(layout)).items():
        at, size = layout[i]
        if size < length_size or at + length_size > len(data):
            continue
        current = struct.unpack_from(fmt, data, at)[0]
        picks = [0, current - 1, current + 1, size, size + 1, top]
        seen = {current}
        for j, v in enumerate(v for v in picks if 0 <= v <= top):
            if v in seen:
                continue
            seen.add(v)
            yield f"seq-nal-{k}-{j}", _with(data, at, fmt, v)


def variants(data: bytes):
    """(name, bytes) one-field edits of an image sequence; sizes never change."""
    track = sequence_track(data)
    t = tables(data, track)
    layout = sample_layout(data, t)
    entry = sample_entry(data, t)
    length_size = (data[hvcc(data, entry).payload + 21] & 3) + 1
    out = [*table_variants(data, t, len(layout)), *entry_variants(data, track, entry),
           *track_variants(data, track), *brand_variants(data),
           *nal_variants(data, layout, length_size)]
    seen = set()
    for name, blob in out:
        if name in seen:
            raise AssertionError(f"duplicate variant name {name}")
        seen.add(name)
        yield name, blob


# ---------------------------------------------------------------- build

@dataclass(frozen=True)
class Profile:
    """One encoder configuration. ``source`` is an ffmpeg -filter_complex graph
    whose output is the frame sequence; {size} and {frames} are filled in."""
    source: str
    frames: int
    size: str = "128x96"
    gray: bool = True
    depth: int = 8
    gop: str = "low-delay"
    lossless: bool = False
    x265: tuple[str, ...] = ()
    heif: tuple[str, ...] = ()


MOTION = "testsrc2=size={size}:rate=10"
ZOOM = "mandelbrot=size={size}:rate=10"
LIFE = "life=size={size}:rate=10:mold=10:ratio=0.3:death_color=#202020"
# Black poster frame and black body, white final frame: a viewer that shows
# frame 0 and one that shows the last frame see different pictures.
POSTER_DIFFERS = ("color=c=black:size={size}:rate=10:duration={body}[a];"
                  "color=c=white:size={size}:rate=10:duration=0.1[b];[a][b]concat=n=2:v=1:a=0")

PROFILES: dict[str, Profile] = {
    # 17 frames: one past the harness's leading budget, so the last frame is
    # reached through the "last frame" path.
    "lowdelay-lossless-gray": Profile(MOTION, 17, lossless=True, x265=("sao=0", "deblock=false")),
    "lowdelay-gray": Profile(MOTION, 40),
    "lowdelay-rgb": Profile(MOTION, 17, gray=False),
    # B-frames: decode order differs from display order. ffmpeg decodes 24
    # distinct frames; ImageIO on macOS 27.2 returns 24 blank (all-zero) frames,
    # so the gate counts it and its variants as not decoded (pixels=0). Kept:
    # it is the only profile that reaches the reorder path at all.
    "bframes-rgb": Profile(MOTION, 24, gray=False, gop="unrestricted"),
    "intra-only-gray": Profile(MOTION, 8, gop="intra-only"),
    "lowdelay-10bit-gray": Profile(ZOOM, 17, depth=10),
    "keyframes-gray": Profile(LIFE, 40, size="64x64", heif=("--max-keyframe-distance", "8")),
    "tools-gray": Profile(MOTION, 17, x265=("ctu=16", "min-cu-size=8", "tskip=1", "amp=1",
                                            "rect=1", "merange=256", "me=star",
                                            "max-merge=5")),
    "poster-differs-gray": Profile(POSTER_DIFFERS, 20, size="64x64", lossless=True),
}
# Not a profile: heif-enc -V (a 'vide' track, no 'pict') is typed public.heics
# by ImageIO but reports 0 frames on macOS 27.2, so it only reaches rejection.
# The handler-type variants cover that edge from a decodable sequence.


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        raise RuntimeError(f"{tool} not found on PATH (brew install ffmpeg libheif)")
    return path


def _pix_fmt(p: Profile) -> str:
    if p.depth > 8:
        return "gray16be" if p.gray else "rgb48be"
    return "gray" if p.gray else "rgb24"


def _run(argv: list[str], what: str) -> None:
    r = subprocess.run(argv, capture_output=True, timeout=600, check=False)
    if r.returncode != 0:
        tail = r.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
        raise RuntimeError(f"{what} failed ({r.returncode}): {' | '.join(tail)}")


def encode(name: str, p: Profile, out: pathlib.Path) -> pathlib.Path:
    """Encode one profile to ``out/<name>.heic``."""
    ffmpeg, heif_enc = _require("ffmpeg"), _require("heif-enc")
    body = f"{(p.frames - 1) / 10:.1f}"
    graph = p.source.format(size=p.size, frames=p.frames, body=body)
    target = out / f"{name}.heic"
    with tempfile.TemporaryDirectory(prefix="heics-") as tmp:
        frames = pathlib.Path(tmp)
        _run([ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-filter_complex", graph,
              "-frames:v", str(p.frames), "-pix_fmt", _pix_fmt(p), str(frames / "f%03d.png")],
             f"ffmpeg ({name})")
        argv = [heif_enc, "-S", "--gop-structure", p.gop, "--fps", "10"]
        if p.lossless:
            argv.append("-L")
        if p.depth > 8:
            argv += ["-b", str(p.depth)]
        for kv in p.x265:
            argv += ["-p", f"x265:{kv}"]
        argv += [*p.heif, "-o", str(target), str(frames / "f001.png")]
        _run(argv, f"heif-enc ({name})")
    return target


# ---------------------------------------------------------------- driver

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="encode image-sequence seeds (ffmpeg + heif-enc)")
    b.add_argument("--out", type=pathlib.Path, required=True)
    b.add_argument("--profile", action="append", choices=sorted(PROFILES),
                   help="encode only these profiles (repeatable; default: all)")
    v = sub.add_parser("variants", help="one-field variants of image sequences")
    v.add_argument("files", nargs="+", type=pathlib.Path)
    v.add_argument("--out", type=pathlib.Path, required=True)
    sub.add_parser("profiles", help="list build profiles")
    args = ap.parse_args(argv)
    if args.cmd == "profiles":
        for name, p in PROFILES.items():
            print(f"{name}: {p.frames} frames {p.size} gop={p.gop} depth={p.depth}"
                  f"{' lossless' if p.lossless else ''}{' gray' if p.gray else ' rgb'}")
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    if args.cmd == "build":
        failed = 0
        for name in args.profile or list(PROFILES):
            try:
                print(f"wrote {encode(name, PROFILES[name], args.out)}", file=sys.stderr)
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                failed += 1
                print(f"skip {name}: {exc}", file=sys.stderr)
        return 1 if failed else 0
    total = 0
    for path in args.files:
        try:
            items = list(variants(path.read_bytes()))
        except (ValueError, struct.error) as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)
            continue
        for name, data in items:
            (args.out / f"{path.stem}-{name}.heic").write_bytes(data)
        total += len(items)
        print(f"{path.name}: {len(items)} variants", file=sys.stderr)
    print(f"wrote {total} variants to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
