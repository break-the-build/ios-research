"""Reach and hygiene of the macOS framework harnesses.

* ImageIO repairs PNG chunk CRCs before decoding: ImageIO rejects a stale IHDR
  CRC, so blind mutation of PNG headers never got past the door.
* CoreText rasterizes (glyph grid, a shaped line of the font's own characters,
  variation extremes) instead of stopping at outlines and layout.
* jackalope.sh stops only the targets Jackalope spawned, before they can run
  without it. Orphaned TinyInst targets died with SIGBUS at their own PC and
  wrote fake framework crash reports; the old `pkill -f <harness>` also killed
  unrelated campaigns using the same harness binary, and every run rebuilt and
  re-signed that binary under them. Each run now uses a private copy.

Static checks run everywhere; native ones (opt-in, -m native) build the real
harnesses on macOS.
"""

from __future__ import annotations

import os
import re
import signal
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HARNESS_DIR = REPO / "tools" / "harness"
JACKALOPE_SH = HARNESS_DIR / "jackalope.sh"


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))


def _png(width: int = 8, height: int = 8) -> bytes:
    """A valid RGBA PNG with a gradient, written without any imaging library."""
    rows = b"".join(
        b"\x00" + b"".join(bytes((x * 30 % 256, y * 30 % 256, 128, 255)) for x in range(width))
        for y in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", zlib.compress(rows)) + _png_chunk(b"IEND", b""))


def _stale_ihdr(png: bytes) -> bytes:
    """Change IHDR's width (8 -> 9) but keep the old CRC, as a mutator would."""
    b = bytearray(png)
    b[8 + 8 + 3] ^= 0x01
    return bytes(b)


def _fixed_ihdr(png: bytes) -> bytes:
    b = bytearray(_stale_ihdr(png))
    b[8 + 8 + 13:8 + 8 + 17] = struct.pack(">I", zlib.crc32(bytes(b[8 + 4:8 + 8 + 13])) & 0xFFFFFFFF)
    return bytes(b)


# ---------------- static ----------------

def test_png_fixture_helpers_are_consistent():
    png = _png()
    assert _stale_ihdr(png) != png
    assert _fixed_ihdr(png)[:29] == _stale_ihdr(png)[:29]          # same header bytes
    assert _fixed_ihdr(png) != _stale_ihdr(png)                    # different CRC


def test_jackalope_never_kills_by_harness_path():
    """`pkill -f <harness>` also killed run.py campaigns using the same binary."""
    code = [ln for ln in JACKALOPE_SH.read_text().splitlines() if not ln.lstrip().startswith("#")]
    assert not any(re.search(r"\bpkill\b", ln) for ln in code)
    assert any("stop_jackalope" in ln for ln in code)


# ---------------- native ----------------

def _can_build_native() -> bool:
    return sys.platform == "darwin" and os.path.exists("/usr/lib/libgmalloc.dylib")


def _build(key: str) -> Path:
    r = subprocess.run(["bash", str(HARNESS_DIR / "build.sh"), key], capture_output=True,
                       timeout=300, check=False)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    return HARNESS_DIR / "build" / f"{key}_fuzzer"


def _done(binary: Path, path: Path | str, **env: str) -> str:
    r = subprocess.run([str(binary), str(path)], capture_output=True, timeout=120, check=False,
                       env={**os.environ, **env})
    assert b"IOSR-CRASH" not in r.stderr, r.stderr.decode("utf-8", "replace")
    return next(ln for ln in r.stdout.decode().splitlines() if ln.startswith("DONE"))


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
def test_native_png_with_stale_ihdr_crc_is_repaired_and_saved(tmp_path):
    harness = _build("imageio")
    stale = tmp_path / "stale.png"
    stale.write_bytes(_stale_ihdr(_png()))
    assert _done(harness, stale, IOSR_PNG_CRC_FIXUP="0").split()[2] == "rejected"
    saved = tmp_path / "saved.png"
    line = _done(harness, stale, IOSR_SAVE_INPUT=str(saved))
    assert line.split()[2] == "decoded" and int(line.split("=")[1]) > 0, line
    # The saved file is the standalone reproducer: valid CRCs, decodes unaided.
    assert saved.read_bytes() == _fixed_ihdr(_png())
    assert _done(harness, saved, IOSR_PNG_CRC_FIXUP="0").split()[2] == "decoded"


RASTER_FONTS = [
    "/System/Library/Fonts/Supplemental/Arial.ttf",          # TrueType outlines
    "/System/Library/Fonts/Apple Color Emoji.ttc",           # sbix bitmap strikes
    "/System/Library/Fonts/Supplemental/Skia.ttf",           # variation axes
]


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
@pytest.mark.parametrize("font", RASTER_FONTS)
def test_native_coretext_inks_pixels(font):
    if not os.path.exists(font):
        pytest.skip(f"{font} not on this macOS")
    line = _done(_build("coretext"), font)
    assert line.split()[2] == "decoded" and line.split()[3].startswith("pixels="), line
    assert int(line.split("=")[1]) > 0, line


_FAKE_JACKALOPE = """#!/bin/bash
# Stand-in for Jackalope: start one target (the harness, blocked on a FIFO)
# as a child, record its PID, and wait like the real fuzzer would.
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
"$1" "$FAKE_FIFO" > /dev/null 2>&1 &
echo $! > "$FAKE_PIDFILE"
wait
"""


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
def test_native_jackalope_stops_only_its_own_targets(tmp_path):
    harness = _build("imageio")
    fake = tmp_path / "fake_jackalope"
    fake.write_text(_FAKE_JACKALOPE)
    fake.chmod(0o755)
    os.mkfifo(tmp_path / "target.fifo")
    os.mkfifo(tmp_path / "bystander.fifo")
    env = {**os.environ, "IOSR_GMALLOC_REEXEC": "0"}
    # A campaign worker using the shared harness binary, which a campaign keeps
    # exec'ing: Jackalope must neither kill it nor rewrite the binary.
    campaign_binary = harness.read_bytes()
    bystander = subprocess.Popen([str(harness), str(tmp_path / "bystander.fifo")], env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        r = subprocess.run(
            ["bash", str(JACKALOPE_SH), "imageio", "2", "1"], capture_output=True, timeout=300,
            check=False, env={**env, "JACKALOPE": str(fake), "JACKALOPE_OUT": str(tmp_path / "out"),
                              "FAKE_FIFO": str(tmp_path / "target.fifo"),
                              "FAKE_PIDFILE": str(tmp_path / "target.pid")})
        assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
        assert harness.read_bytes() == campaign_binary, "jackalope.sh rewrote the campaign's harness"
        assert (tmp_path / "out" / "bin" / "imageio_fuzzer").is_file()
        target = int((tmp_path / "target.pid").read_text())
        deadline = time.monotonic() + 5
        while _alive(target) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not _alive(target), "Jackalope's target outlived it"
        assert bystander.poll() is None, "an unrelated process using the harness was killed"
    finally:
        bystander.send_signal(signal.SIGKILL)
        bystander.wait(timeout=10)
