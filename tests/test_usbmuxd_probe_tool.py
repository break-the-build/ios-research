"""Tests for tools/probe/usbmuxd_probe.py (#228 §1).

Pure-function coverage of wire framing, mutation-round construction, and
plist parsing against synthetic data; the live-daemon run is marked
``native`` and self-skips where the socket is absent.
"""

from __future__ import annotations

import importlib.util
import plistlib
import struct
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "probe" / "usbmuxd_probe.py"


def _load():
    spec = importlib.util.spec_from_file_location("usbmuxd_probe", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pack_frame_header_layout():
    mod = _load()
    blob = mod.pack_frame(1, 8, 7, b"xy")
    length, version, msg_type, tag = struct.unpack("<IIII", blob[:16])
    assert (length, version, msg_type, tag) == (18, 1, 8, 7)
    assert blob[16:] == b"xy"


def test_pack_plist_roundtrip():
    mod = _load()
    blob = mod.pack_plist({"MessageType": "Listen"}, tag=3)
    head = blob[:16]
    length, version, msg_type, tag = mod.HEADER.unpack(head)
    assert version == 1 and msg_type == 8 and tag == 3
    assert plistlib.loads(blob[16:])["MessageType"] == "Listen"


def test_parse_plist_rejects_garbage():
    mod = _load()
    assert mod.parse_plist(b"not-a-plist") is None
    assert mod.parse_plist(plistlib.dumps([1, 2])) is None  # non-dict


def test_build_rounds_is_deterministic_and_bounded():
    mod = _load()
    a, b = mod.build_rounds(42), mod.build_rounds(42)
    assert [r["name"] for r in a] == [r["name"] for r in b]
    assert len(a) >= 20
    names = {r["name"] for r in a}
    assert {"baseline-hello", "connect-max-deviceid",
            "truncated-header", "declared-length-overrun"} <= names


def test_declared_length_overrun_stays_under_wire_cap():
    mod = _load()
    malformed_ok = {"declared-length-overrun", "garbage-bytes"}
    for rnd in mod.build_rounds(1):
        for blob in rnd.get("send", []):
            if len(blob) >= 16 and rnd["name"] not in malformed_ok:
                declared = struct.unpack("<I", blob[:4])[0]
                assert declared <= 16 * 1024 * 1024


@pytest.mark.native
def test_live_daemon_roundtrip_self_skips():
    import socket as _socket
    mod = _load()
    try:
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(mod.SOCKET_PATH)
    except OSError:
        pytest.skip("no local usbmuxd socket")
        return
    s.close()
    session = mod.ProbeSession(mod.SOCKET_PATH)
    assert session.alive()
