#!/usr/bin/env python3
"""PDF generator for lane 3 (CoreGraphics): shadings and extreme geometry.

Byte mutation of real PDFs almost never produces a *consistent* shading whose
parts disagree, or a coordinate at an exact fixed-point boundary: both need
whole objects written on purpose. Two families, each one small one-page PDF
with a correct cross-reference table:

* **shading**: all seven shading types. Types 1-3 pair a color space (Gray,
  RGB, CMYK) with a function (sampled, exponential, stitching, PostScript
  calculator) whose output count matches it or doesn't (0-8). Types 4-7 (mesh)
  add a vertex stream whose Decode array, bit depths, row length and data
  length agree with the dictionary or don't, with and without a Function.
  Each is painted with ``sh`` and, in a second file, as a pattern fill.
* **geometry**: paths, clips, strokes, dashes and text whose coordinates,
  widths and sizes sit at fixed-point and integer boundaries (2^15, 2^16,
  2^23, 2^24, 2^31, 2^32 and neighbours, 1e15, 1e30), under scaled and
  sheared transforms. Rasterizer coverage arithmetic overflows only at such
  device coordinates (CVE-2026-86950 needed a 1024 pt text size).

Authorized / own-machine research only (SECURITY.md).

Usage:
    python tools/gen/pdf.py shading --out DIR
    python tools/gen/pdf.py geometry --out DIR
    python tools/gen/pdf.py random --out DIR --count 2000 [--seed 1]
"""

from __future__ import annotations

import argparse
import itertools
import pathlib
import random
import sys

COLOR_SPACES = {"DeviceGray": 1, "DeviceRGB": 3, "DeviceCMYK": 4}
OUTPUT_DIMS = (0, 1, 2, 3, 4, 5, 8)
EXTREMES = (0, 1e-6, 1, 255, 256, 32767, 32768, 65535, 65536, 8388607, 8388608,
            16777216, 2147483647, 2147483648, 4294967296, 1e15, 1e30)
SCALES = (1, 1000, 1e6, 1e-6)


# ---------------------------------------------------------------- PDF writer

def _num(v: float) -> str:
    """A PDF number: integers stay exact, reals keep enough digits."""
    if float(v).is_integer() and abs(v) < 1e18:
        return str(int(v))
    return f"{v:.10f}".rstrip("0").rstrip(".") if abs(v) >= 1e-4 else f"{v:.12f}"


def build_pdf(content: bytes, resources: str = "", objects: list[bytes] | None = None) -> bytes:
    """One 200x200 page. ``objects`` become objects 5, 6, ... (refer to them
    as ``5 0 R`` and up); ``resources`` is the page's /Resources body."""
    page_res = f" /Resources << {resources} >>" if resources else ""
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200]{page_res} "
            f"/Contents 4 0 R >>".encode(),
            _stream(b"", content)] + list(objects or [])
    out, offsets = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"), []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (i, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % off for off in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objs) + 1, xref)
    return bytes(out)


def _stream(dict_body: bytes, data: bytes) -> bytes:
    return b"<< %s /Length %d >>\nstream\n%s\nendstream" % (dict_body, len(data), data)


# ---------------------------------------------------------------- functions

def function_object(kind: str, n_out: int, n_in: int = 1) -> bytes:
    """A function with ``n_in`` inputs and ``n_out`` outputs, as an object body."""
    dom = " ".join(["0 1"] * n_in)
    rng = " ".join(["0 1"] * n_out)
    if kind == "exponential":
        c0, c1 = " ".join(["0"] * n_out), " ".join(["1"] * n_out)
        return f"<< /FunctionType 2 /Domain [{dom}] /C0 [{c0}] /C1 [{c1}] /N 1 >>".encode()
    if kind == "sampled":
        size = " ".join(["2"] * n_in)
        samples = bytes(range(256))[:max(1, (2 ** n_in) * n_out)]
        return _stream(f"/FunctionType 0 /Domain [{dom}] /Range [{rng}] /Size [{size}] "
                       f"/BitsPerSample 8".encode(), samples)
    if kind == "postscript":
        code = "{ " + " ".join(["dup"] * max(0, n_out - n_in)) + " }"
        return _stream(f"/FunctionType 4 /Domain [{dom}] /Range [{rng}]".encode(),
                       code.encode())
    if kind == "stitching":                                   # 1-input only
        c0, c1 = " ".join(["0"] * n_out), " ".join(["1"] * (n_out + 1))
        return (f"<< /FunctionType 3 /Domain [0 1] /Bounds [0.5] /Encode [0 1 0 1] "
                f"/Functions [<< /FunctionType 2 /Domain [0 1] /C0 [{c0}] /C1 [{c0}] /N 1 >> "
                f"<< /FunctionType 2 /Domain [0 1] /C0 [{c1}] /C1 [{c1}] /N 1 >>] >>").encode()
    raise ValueError(kind)


FUNCTION_KINDS = ("exponential", "sampled", "postscript", "stitching")


# ---------------------------------------------------------------- shadings

def _paint(shading: bytes, extra: list[bytes], as_pattern: bool) -> bytes:
    """A page painting ``shading`` (object 5; ``extra`` follow it) with sh or a pattern."""
    objects = [shading] + extra
    if as_pattern:
        objects.append(b"<< /PatternType 2 /Shading 5 0 R >>")
        pat = len(objects) + 4
        return build_pdf(b"/Pattern cs /P0 scn 0 0 200 200 re f",
                         f"/Pattern << /P0 {pat} 0 R >>", objects)
    return build_pdf(b"/Sh0 sh", "/Shading << /Sh0 5 0 R >>", objects)


def _axial_like(stype: int, cs: str, fn_ref: str) -> bytes:
    coords = {1: "", 2: "/Coords [0 0 200 200]", 3: "/Coords [100 100 0 100 100 100]"}[stype]
    dom = "/Domain [0 1 0 1]" if stype == 1 else "/Extend [true true]"
    return (f"<< /ShadingType {stype} /ColorSpace /{cs} {coords} {dom} "
            f"/Function {fn_ref} >>").encode()


def _mesh_data(stype: int, ncomp: int, bpc: int, bpcomp: int, vertices: int) -> bytes:
    """Packed mesh records: [flag] x y c..., big-endian, whole bytes per field."""
    flag = stype in (4, 6, 7)
    per = {4: 1, 5: 1, 6: 12, 7: 16}[stype]          # points per record
    out = bytearray()
    for v in range(vertices):
        if flag:
            out += b"\x00"
        for _p in range(per):
            for coord in ((v * 37) % 200, (v * 53) % 200):
                out += int(coord * ((1 << bpc) - 1) // 200).to_bytes(bpc // 8, "big")
        for c in range(ncomp if stype in (4, 5) else 4 * ncomp):
            out += ((v + c) * 97 % (1 << bpcomp)).to_bytes(bpcomp // 8, "big")
    return bytes(out)


def mesh_shading(stype: int, cs: str, *, function: int | None, decode_extra: int,
                 bpc: int, bpcomp: int, vertices: int, data_delta: int,
                 per_row: int = 2) -> tuple[bytes, list[bytes]]:
    """A type 4-7 shading stream (object 5) and its function object (6), if any.

    ``function`` is the function's output count (None: no function, colors
    are given per vertex). The Decode array gets ``decode_extra`` more (or
    fewer) entries than the color space implies; the data gets ``data_delta``
    more (or fewer) bytes than the vertex count needs."""
    n_cs = COLOR_SPACES[cs]
    ncomp = 1 if function is not None else n_cs
    decode = ["0", "200", "0", "200"] + ["0", "1"] * ncomp
    if decode_extra > 0:
        decode += ["0", "1"] * decode_extra
    elif decode_extra < 0:
        decode = decode[:max(0, len(decode) + 2 * decode_extra)]
    data = _mesh_data(stype, ncomp, bpc, bpcomp, vertices)
    data = data[:max(0, len(data) + data_delta)] if data_delta < 0 else data + b"\x5a" * data_delta
    head = (f"/ShadingType {stype} /ColorSpace /{cs} /BitsPerCoordinate {bpc} "
            f"/BitsPerComponent {bpcomp} /Decode [{' '.join(decode)}]")
    if stype != 5:
        head += " /BitsPerFlag 8"
    else:
        head += f" /VerticesPerRow {per_row}"
    extra = []
    if function is not None:
        head += " /Function 6 0 R"
        extra.append(function_object("exponential", function))
    return _stream(head.encode(), data), extra


def shading_variants():
    """Yield (name, pdf bytes)."""
    for stype, cs, kind, n_out in itertools.product((1, 2, 3), COLOR_SPACES,
                                                    FUNCTION_KINDS, OUTPUT_DIMS):
        if stype == 1 and kind == "stitching":
            continue                                 # stitching takes one input
        fn = function_object(kind, n_out, n_in=2 if stype == 1 else 1)
        sh = _axial_like(stype, cs, "6 0 R")
        for as_pattern in (False, True):
            yield (f"sh{stype}-{cs[6:]}-{kind}-out{n_out}{'-pat' if as_pattern else ''}",
                   _paint(sh, [fn], as_pattern))
    mesh_cases = ([("fn", n, 0, 0) for n in OUTPUT_DIMS]
                  + [("nofn", None, d, 0) for d in (-2, -1, 1, 3)]
                  + [("nofn", None, 0, d) for d in (-7, -1, 1, 64)])
    for stype, cs, (tag, fn_out, dex, ddelta) in itertools.product(
            (4, 5, 6, 7), COLOR_SPACES, mesh_cases):
        for bpc, bpcomp in ((8, 8), (16, 16), (32, 16)):
            sh, extra = mesh_shading(stype, cs, function=fn_out, decode_extra=dex,
                                     bpc=bpc, bpcomp=bpcomp, vertices=6, data_delta=ddelta)
            label = (f"out{fn_out}" if tag == "fn"
                     else (f"decode{dex:+d}" if dex else f"data{ddelta:+d}"))
            yield f"sh{stype}-{cs[6:]}-{tag}-{label}-b{bpc}x{bpcomp}", _paint(sh, extra, False)
    for cs, per_row in itertools.product(COLOR_SPACES, (0, 1, 3, 65535, 2147483647)):
        sh, extra = mesh_shading(5, cs, function=None, decode_extra=0, bpc=8, bpcomp=8,
                                 vertices=6, data_delta=0, per_row=per_row)
        yield f"sh5-{cs[6:]}-rows{per_row}", _paint(sh, extra, False)


# ---------------------------------------------------------------- geometry

GEOMETRY_TEMPLATES = {
    "line": "{v} {v} m {w} {w} l h f",
    "curve": "0 0 m {v} {w} {w} {v} {v} {v} c f",
    "rect": "{w} {w} {v} {v} re f",
    "clip": "{w} {w} {v} {v} re W n 0 0 200 200 re f",
    "stroke": "{v} w 0 0 m 150 150 l S",
    "dash": "[{v} {w}] 0 d 2 w 0 0 m 200 200 l S",
    "text": "BT /F1 {v} Tf 10 10 Td (Agj%) Tj ET",
    "textmatrix": "BT /F1 12 Tf {v} {w} {w} {v} 10 10 Tm (Agj%) Tj ET",
}
_FONT_RES = "/Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >>"


def geometry_pdf(template: str, v: float, scale: float, shear: float = 0.0) -> bytes:
    body = GEOMETRY_TEMPLATES[template].format(v=_num(v), w=_num(-v if v else 1))
    cm = f"{_num(scale)} 0 {_num(shear)} {_num(scale)} 0 0 cm "
    return build_pdf((cm + body).encode(), _FONT_RES if "Tf" in body else "")


def geometry_variants():
    for template, v, sign, scale in itertools.product(GEOMETRY_TEMPLATES, EXTREMES,
                                                      (1, -1), SCALES):
        if sign < 0 and v == 0:
            continue
        yield (f"geo-{template}-{'n' if sign < 0 else ''}{_num(v)}-s{_num(scale)}",
               geometry_pdf(template, sign * v, scale))
    for template, v in itertools.product(("text", "rect", "curve"), EXTREMES):
        yield f"geo-{template}-{_num(v)}-shear", geometry_pdf(template, v, 1, shear=0.75)


def random_variants(count: int, seed: int):
    """Random mixes: several geometry operations, or a random mesh shading."""
    rng = random.Random(seed)
    for i in range(count):
        if rng.random() < 0.5:
            ops = [GEOMETRY_TEMPLATES[rng.choice(list(GEOMETRY_TEMPLATES))].format(
                       v=_num(rng.choice(EXTREMES) * rng.choice((1, -1))),
                       w=_num(rng.choice(EXTREMES) * rng.choice((1, -1))))
                   for _ in range(rng.randint(2, 6))]
            cm = (f"{_num(rng.choice(SCALES))} {_num(rng.choice((0, 0.5)))} "
                  f"{_num(rng.choice((0, 0.75)))} {_num(rng.choice(SCALES))} 0 0 cm ")
            yield f"rand-geo-{seed}-{i}", build_pdf((cm + " ".join(ops)).encode(), _FONT_RES)
        else:
            sh, extra = mesh_shading(
                rng.choice((4, 5, 6, 7)), rng.choice(list(COLOR_SPACES)),
                function=rng.choice((None, *OUTPUT_DIMS)), decode_extra=rng.randint(-2, 3),
                bpc=rng.choice((8, 16, 32)), bpcomp=rng.choice((8, 16)),
                vertices=rng.randint(0, 40), data_delta=rng.choice((-9, -1, 0, 0, 1, 33)),
                per_row=rng.choice((0, 1, 2, 3, 7, 65535)))
            yield f"rand-mesh-{seed}-{i}", _paint(sh, extra, rng.random() < 0.3)


# ---------------------------------------------------------------- driver

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("family", choices=("shading", "geometry", "random"))
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--count", type=int, default=1000, help="random: files to write")
    ap.add_argument("--seed", type=int, default=1, help="random: RNG seed")
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    gen = {"shading": shading_variants, "geometry": geometry_variants,
           "random": lambda: random_variants(args.count, args.seed)}[args.family]
    total = 0
    for name, data in gen():
        (args.out / f"{name}.pdf").write_bytes(data)
        total += 1
    print(f"wrote {total} {args.family} PDFs to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
