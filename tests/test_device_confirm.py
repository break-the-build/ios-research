"""Unit tests for the device confirmation bridge (#217).

Pure-python parts only: magic-family dispatch (must mirror the ObjC probe's
classify_family) and verdict parsing from captured console output. No device
required.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "tools" / "campaign" / "confirm_on_device.py"


def _load():
    spec = importlib.util.spec_from_file_location("confirm_on_device", RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_repo_root_resolution():
    mod = _load()
    assert mod.REPO == REPO


def test_classify_family_matches_probe_dispatch():
    mod = _load()
    f = mod.classify_family
    assert f(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16) == "imageio"
    assert f(b"GIF89a" + b"\x00" * 16) == "imageio"
    assert f(b"\xff\xd8\xff\xe0" + b"\x00" * 16) == "imageio"
    assert f(b"\x00\x00\x00\x20ftypheic" + b"\x00" * 16) == "imageio"
    assert f(b"%PDF-1.7\n%%EOF\n") == "coregraphics"
    assert f(b"\x00\x01\x00\x00" + b"\x00" * 20) == "coretext"
    assert f(b"OTTO" + b"\x00" * 20) == "coretext"
    assert f(b"ttcf" + b"\x00" * 20) == "coretext"
    assert f(b"true" + b"\x00" * 20) == "coretext"
    assert f(b"RIFF\x00\x00\x00\x00WAVE") == "audio"
    assert f(b"FORM" + b"\x00" * 20) == "audio"
    assert f(b"caff" + b"\x00" * 20) == "audio"
    assert f(b"ID3\x04\x00") == "audio"
    assert f(b"\xff\xfb\x90\x00") == "audio"
    assert f(b"not-really-anything") == "unknown"


def test_finding04_input_classifies_as_audio():
    mod = _load()
    hang = bytes.fromhex(
        "49443300007000000000ffff61500bac49120000494433ff")
    assert mod.classify_family(hang) == "audio"


def test_parse_verdict_matrix():
    mod = _load()
    ok = ("PROBE about-to-open input.bin\nPROBE family=audio bytes=24\n"
          "PROBE OPEN_OK audio\nPROBE DONE no-hang\n")
    assert mod.parse_verdict(ok, timed_out=False) == "OPEN_OK"
    hang = ("PROBE about-to-open input.bin\nPROBE family=audio bytes=24\n")
    assert mod.parse_verdict(hang, timed_out=True) == "HANG"
    assert mod.parse_verdict(hang, timed_out=False) == "ERROR"
    fail = "PROBE family=audio bytes=24\nPROBE OPEN_FAIL audio status=-43\n"
    assert mod.parse_verdict(fail, timed_out=False) == "OPEN_FAIL"
    # opened one stage but DONE never arrived -> a later stage hung
    partial = "PROBE family=audio bytes=24\nPROBE OPEN_OK audio\n"
    assert mod.parse_verdict(partial, timed_out=True) == "HANG"
    assert mod.parse_verdict("PROBE ERROR unreadable x\n", timed_out=True) \
        == "ERROR"


def test_mutually_exclusive_input_args():
    mod = _load()
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--input")
    ap.add_argument("--crash")
    a = ap.parse_args(["--input", "x", "--crash", "y"])
    assert bool(a.input) == bool(a.crash)   # main() rejects this combination
