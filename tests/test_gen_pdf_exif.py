"""Generators for patched code paths: tools/gen/pdf.py (lane 3) and tools/gen/exifthumb.py (lane 4).

Unit tests check structure only (valid cross-reference tables, the requested
mismatches, one in-place change per variant), so they run anywhere. Native
tests (opt-in, -m native) decode generated files with the real harnesses.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "gen"))
import exifthumb  # noqa: E402
import pdf  # noqa: E402

# ---------------------------------------------------------------- pdf.py

def test_build_pdf_xref_points_at_every_object():
    data = pdf.build_pdf(b"0 0 m 1 1 l S", "/Font << >>", [b"<< /A 1 >>"])
    xref_at = int(re.search(rb"startxref\n(\d+)", data).group(1))
    lines = data[xref_at:].split(b"\n")
    assert lines[0] == b"xref" and lines[1] == b"0 6"
    for i in range(1, 6):
        assert data[int(lines[2 + i][:10]):].startswith(b"%d 0 obj" % i)
    assert b"/Resources << /Font << >> >>" in data


def test_numbers_are_exact_integers_or_short_reals():
    assert pdf._num(2147483648) == "2147483648"
    assert pdf._num(-32768) == "-32768"
    assert pdf._num(0.75) == "0.75"
    assert float(pdf._num(1e-6)) == pytest.approx(1e-6)


def _array(body: bytes, key: bytes) -> list[bytes]:
    return re.search(rb"/" + key + rb" \[([^\]]*)\]", body).group(1).split()


def test_function_objects_have_the_requested_output_count():
    assert len(_array(pdf.function_object("exponential", 3), b"C0")) == 3
    sampled = pdf.function_object("sampled", 2, n_in=2)
    assert len(_array(sampled, b"Range")) == 4 and b"/Length 8 " in sampled
    assert len(_array(pdf.function_object("postscript", 5), b"Range")) == 10
    assert b"/FunctionType 3" in pdf.function_object("stitching", 2)
    with pytest.raises(ValueError):
        pdf.function_object("bogus", 1)


def test_mesh_shading_follows_its_knobs():
    sh, extra = pdf.mesh_shading(4, "DeviceRGB", function=None, decode_extra=0, bpc=8,
                                 bpcomp=8, vertices=6, data_delta=0)
    assert len(_array(sh, b"Decode")) == 4 + 2 * 3 and extra == []
    assert b"/Length 36 " in sh                       # 6 x (flag + x + y + 3 colors)
    sh, extra = pdf.mesh_shading(5, "DeviceGray", function=5, decode_extra=0, bpc=16,
                                 bpcomp=16, vertices=2, data_delta=-3, per_row=7)
    assert len(_array(sh, b"Decode")) == 4 + 2                    # one t per vertex
    assert b"/Function 6 0 R" in sh and b"/VerticesPerRow 7" in sh
    assert b"/BitsPerFlag" not in sh and b"/Length 9 " in sh      # 2 x 6 bytes - 3
    assert len(_array(extra[0], b"C0")) == 5
    sh, _ = pdf.mesh_shading(6, "DeviceCMYK", function=None, decode_extra=-2, bpc=8,
                             bpcomp=8, vertices=1, data_delta=0)
    assert len(_array(sh, b"Decode")) == 4 + 2 * 4 - 4


def test_shading_family_covers_every_type(tmp_path):
    names = [n for n, _d in pdf.shading_variants()]
    assert len(names) == len(set(names))
    assert all(any(n.startswith(f"sh{t}-") for n in names) for t in range(1, 8))
    assert any(n.endswith("-pat") for n in names)
    assert pdf.main(["shading", "--out", str(tmp_path)]) == 0
    assert len(list(tmp_path.iterdir())) == len(names)


def test_geometry_and_random_families():
    geo = dict(pdf.geometry_variants())
    rect = geo["geo-rect-2147483648-s1"]
    assert b"-2147483648 -2147483648 2147483648 2147483648 re f" in rect
    assert b"/BaseFont /Helvetica" in geo["geo-text-65536-s1"]
    assert b"/Font" not in geo["geo-rect-65536-s1"]
    assert any(n.endswith("-shear") for n in geo)
    once = list(pdf.random_variants(20, 3))
    assert once == list(pdf.random_variants(20, 3))
    assert once != list(pdf.random_variants(20, 4))


# ---------------------------------------------------------------- exifthumb.py

SOS_AND_SCAN = b"\xff\xda" + struct.pack(">H", 8) + bytes(6) + b"\x12\x34\xff\xd9"


def _jpeg(tag: bytes = b"") -> bytes:
    """Marker structure only (SOI, APP0, DQT, SOS + scan, EOI): enough for parsing."""
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\0" + bytes(9)
    dqt = b"\xff\xdb" + struct.pack(">H", 4 + len(tag)) + b"\0\0" + tag
    return b"\xff\xd8" + app0 + dqt + SOS_AND_SCAN


THUMB = _jpeg(b"thumb")


def _thumb_fields(jpeg: bytes) -> tuple[bytes, int, int]:
    start, end = exifthumb.exif_range(jpeg)
    tiff = jpeg[start:end]
    at = {tag: e for tag, _t, _c, e in exifthumb.entries(tiff)}
    off = struct.unpack_from("<I", tiff, at[513] + 8)[0]
    n = struct.unpack_from("<I", tiff, at[514] + 8)[0]
    return tiff, off, n


def test_build_embeds_the_thumbnail_in_ifd1():
    out = exifthumb.build(_jpeg(), THUMB)
    tiff, off, n = _thumb_fields(out)
    assert tiff[off:off + n] == THUMB
    assert 37510 in {tag for tag, *_rest in exifthumb.entries(tiff)}     # UserComment
    assert out.startswith(b"\xff\xd8\xff\xe1") and out.endswith(SOS_AND_SCAN)
    again = exifthumb.build(out, THUMB)                  # an existing Exif segment is replaced
    assert again.count(b"Exif\0\0") == 1 and len(again) == len(out)


def test_build_rejects_a_thumbnail_too_large_for_app1():
    with pytest.raises(ValueError):
        exifthumb.build(_jpeg(), bytes(70000))


def test_thumbnail_pairs_include_overflowing_sums():
    tiff, _off, n = _thumb_fields(exifthumb.build(_jpeg(), THUMB))
    pairs = dict(exifthumb.thumbnail_pairs(tiff))
    assert all(len(t) == len(tiff) for t in pairs.values())
    wrapped = pairs["thumb-wrap10"]
    _t, o2, n2 = _thumb_fields(b"\xff\xd8\xff\xe1" + struct.pack(">H", len(tiff) + 8)
                               + b"Exif\0\0" + wrapped + SOS_AND_SCAN)
    assert o2 == 0xFFFFFFF0 and (o2 + n2) > 0xFFFFFFFF
    assert f"thumb-off0-len{n:x}" in pairs


def test_blob_and_marker_variants_change_one_field():
    jpeg = exifthumb.build(_jpeg(), THUMB)
    names = dict(exifthumb.variants(jpeg))
    assert "tag37510-count0" in names and "tag37510-atffffffff" in names
    assert all(len(v) == len(jpeg) for v in names.values())
    app0 = next(at for marker, at, _len in exifthumb.segments(jpeg) if marker == 0xFFE0)
    changed = names[f"mE0at{app0}-len0"]
    assert struct.unpack_from(">H", changed, app0 + 2)[0] == 0
    assert sum(a != b for a, b in zip(changed, jpeg)) == 1
    assert any(n.startswith("exif-ifd") for n, _v in exifthumb.variants(jpeg, all_tags=True))


def test_a_jpeg_without_exif_gets_marker_variants_only():
    names = [n for n, _v in exifthumb.variants(_jpeg())]
    assert names and all(n.startswith("m") for n in names)


def test_cli_build_and_variants(tmp_path, capsys):
    main, thumb, out = tmp_path / "main.jpg", tmp_path / "t.jpg", tmp_path / "with.jpg"
    main.write_bytes(_jpeg())
    thumb.write_bytes(THUMB)
    (tmp_path / "junk.jpg").write_bytes(b"not a jpeg")
    assert exifthumb.main(["build", str(main), str(thumb), "--out", str(out)]) == 0
    assert exifthumb.main(["variants", str(out), str(tmp_path / "junk.jpg"),
                           "--out", str(tmp_path / "v")]) == 0
    assert len(list((tmp_path / "v").iterdir())) > 50
    assert "skip" in capsys.readouterr().err


# ---------------------------------------------------------------- native

def _can_build_native() -> bool:
    return sys.platform == "darwin" and os.path.exists("/usr/lib/libgmalloc.dylib")


def _harness(key: str) -> str:
    r = subprocess.run(["bash", str(REPO / "tools" / "harness" / "build.sh"), key],
                       capture_output=True, timeout=300, check=False)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    return str(REPO / "tools" / "harness" / "build" / f"{key}_fuzzer")


def _done(harness: str, paths: list[str], **env: str) -> list[list[str]]:
    out = subprocess.run([harness, *paths], capture_output=True, text=True, timeout=600,
                         check=False, env={**os.environ, **env}).stdout
    return [ln.split()[2:] for ln in out.splitlines() if ln.startswith("DONE")]


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
def test_native_geometry_pdfs_decode(tmp_path):
    for name, data in list(pdf.geometry_variants())[::20]:
        (tmp_path / f"{name}.pdf").write_bytes(data)
    files = sorted(str(p) for p in tmp_path.iterdir())
    results = _done(_harness("coregraphics"), files)
    assert len(results) == len(files) and all(r[0] == "decoded" for r in results)


ICON = "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericDocumentIcon.icns"


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native() or not shutil.which("sips") or not os.path.exists(ICON),
                    reason="requires macOS with libgmalloc and sips")
def test_native_embedded_thumbnail_is_drawn(tmp_path):
    main, thumb = tmp_path / "main.jpg", tmp_path / "thumb.jpg"
    for out, size in ((main, "512"), (thumb, "96")):
        subprocess.run(["sips", "-s", "format", "jpeg", "-Z", size, ICON, "--out", str(out)],
                       capture_output=True, timeout=60, check=True)
    seed = tmp_path / "with.jpg"
    exifthumb.main(["build", str(main), str(thumb), "--out", str(seed)])
    harness = _harness("imageio")
    with_pass = _done(harness, [str(seed)])[0]
    without = _done(harness, [str(seed)], IOSR_IMGIO_THUMBNAIL="0")[0]
    assert with_pass[0] == without[0] == "decoded"
    extra = int(with_pass[1].split("=")[1]) - int(without[1].split("=")[1])
    assert 0 < extra <= 96 * 96 * 4          # the 96 px embedded thumbnail, not a 256 px one
