"""Tests for kernel-boundary harnesses: mach_msg model + mach:sim target."""

from __future__ import annotations

import json
import random

import pytest

from ios_research import machmsg
from ios_research import targets as tgt
from ios_research.cli import main
from ios_research.machmsg import (
    MachMessage, MachMessageError, OOLDescriptor, PortDescriptor,
    pack, parse,
)
from ios_research.targets.base import Outcome


def _complex_msg() -> MachMessage:
    return MachMessage(
        bits=machmsg.COMPLEX_FLAG,
        ports=[PortDescriptor(name=0x103), PortDescriptor(name=0x207)],
        ool_regions=[OOLDescriptor(address=0x4000, size=8)],
        payload=b"\xde\xad" + b"B" * 6,
    )


# --- pack / parse roundtrip ---------------------------------------------------
def test_pack_parse_roundtrip_complex():
    msg = _complex_msg()
    blob = pack(msg)
    assert len(blob) >= 28
    status, detail, parsed = parse(blob)
    assert status == "ok", detail
    assert parsed is not None and parsed.complex
    assert [p.name for p in parsed.ports] == [0x103, 0x207]
    assert parsed.ool_regions[0].size == 8
    assert parsed.payload.startswith(b"\xde\xad")


def test_pack_simple_message_without_descriptors():
    blob = pack(MachMessage(bits=0))  # simple message
    status, detail, parsed = parse(blob)
    assert status == "ok" and not parsed.complex
    assert parsed.payload == b""


def test_pack_rejects_complex_without_descriptors():
    with pytest.raises(MachMessageError):
        pack(MachMessage(bits=machmsg.COMPLEX_FLAG))


# --- defect paths (kernel-boundary logic shapes) -------------------------------
def test_short_header_is_underflow():
    assert parse(b"\x01\x02")[0] == "err_short_header"


def test_size_underflow_detected():
    blob = bytearray(pack(_complex_msg()))
    blob[4:8] = (16).to_bytes(4, "little")  # size < header
    assert parse(bytes(blob))[0] == "err_size_underflow"


def test_truncated_body_detected():
    blob = pack(_complex_msg())
    assert parse(blob[:-3])[0] == "err_truncated_body"


def test_complex_empty_detected():
    # Craft raw bytes like a fuzzer would: keep the complex bit, zero the
    # descriptor-count fields.
    blob = bytearray(pack(_complex_msg()))
    bits = int.from_bytes(blob[0:4], "little")
    bits |= machmsg.COMPLEX_FLAG
    bits &= ~(machmsg.PORT_COUNT_MASK | machmsg.OOL_COUNT_MASK)
    blob[0:4] = bits.to_bytes(4, "little")
    status, detail, _ = parse(bytes(blob))
    assert status == "err_complex_empty"


def _raw_ports_message(count: int) -> bytes:
    import struct as _s
    desc = b"".join(_s.pack("<BBI", machmsg.DESC_PORT, 0, i)
                    for i in range(count))
    size = machmsg.HEADER_SIZE + len(desc)
    bits = machmsg.COMPLEX_FLAG | ((count & 0xFF) << 8)
    return _s.pack(machmsg.HEADER_FMT, bits, size, 1, 0, 0, 0x1000, 0) + desc


def test_ool_overflow_detected():
    msg = _complex_msg()
    msg.ool_regions = [OOLDescriptor(address=0x4000, size=0xFFFF)]
    blob = pack(msg) + b"A" * 64  # region claims far more than body holds
    assert parse(blob)[0] == "err_ool_overflow"


def test_right_overflow_detected():
    # 17 valid port descriptors with a matching count field: parse must
    # enforce the send-right budget itself (pack() refuses to build this).
    blob = _raw_ports_message(machmsg.PORT_RIGHT_LIMIT + 1)
    assert parse(blob)[0] == "err_right_overflow"
    assert parse(_raw_ports_message(machmsg.PORT_RIGHT_LIMIT))[0] == "ok"


# --- target integration ----------------------------------------------------------
def test_mach_sim_target_registered_and_seeds():
    target = tgt.create("mach:sim")
    seeds = target.seeds()
    assert seeds and parse(seeds[0])[0] == "ok"


def test_mach_sim_crash_paths_match_defects():
    target = tgt.create("mach:sim")

    short = target.execute(b"\x01\x02\x03")
    assert short.outcome == Outcome.CRASH
    assert short.diagnostics.classification_hint == "NULL_DEREFERENCE"

    over = _complex_msg()
    over.ool_regions = [OOLDescriptor(address=0x4000, size=0xFFFF)]
    res = target.execute(pack(over))
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "OUT_OF_BOUNDS_READ"

    rights = _raw_ports_message(machmsg.PORT_RIGHT_LIMIT + 1)
    res = target.execute(rights)
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "ASSERTION"

    revoked = _complex_msg()
    res = target.execute(pack(revoked))
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "USE_AFTER_FREE"


def test_mach_sim_accepts_clean_message():
    clean = MachMessage(bits=machmsg.COMPLEX_FLAG,
                        ports=[PortDescriptor(name=0x9)],
                        payload=b"hello")
    res = tgt.create("mach:sim").execute(pack(clean))
    assert res.outcome == Outcome.ACCEPTED


def test_structure_mutate_produces_parseable_outputs():
    target = tgt.create("mach:sim")
    seed = target.seeds()[0]
    rng = random.Random(1234)
    for i in range(50):
        mutated = target.structure_mutate(seed, rng)
        if mutated is None:
            continue
        status, detail, _msg = parse(mutated)
        # Every produced message must land in a modeled state, never explode.
        assert status in ("ok", "err_complex_empty", "err_ool_overflow",
                          "err_descriptor_bounds", "err_right_overflow",
                          "err_truncated_body", "err_size_underflow"), \
            f"iter {i}: {status} {detail}"


def test_coverage_features_namespaced():
    target = tgt.create("mach:sim")
    seed = target.seeds()[0]
    features = target.coverage_features(seed, None)
    assert all(f.startswith("mach-sim:v1") for f in features)


# --- CLI surface ------------------------------------------------------------------
def test_cli_kernel_surface(ctx):
    rc = main(["kernel", "surface", "--json",
               "--workspace", str(ctx.workspace().root)])
    assert rc == 0


def test_cli_kernel_build_then_unpack_roundtrip(ctx, tmp_path, capsys):
    ws = str(ctx.workspace().root)
    out = str(tmp_path / "msg.bin")
    rc = main(["kernel", "msg-build", "--port", "0x103", "--ool-size", "8",
               "--payload", "dead41414141414141", "--out", out,
               "--json", "--workspace", ws])
    assert rc == 0
    envelope = json.loads(capsys.readouterr().out.strip())
    assert envelope["data"]["self_check"]["status"] == "ok"

    rc = main(["kernel", "msg-unpack", out, "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 0
    fields = payload["data"]["fields"]
    assert fields["ports"] == [0x103]
    assert fields["ool_sizes"] == [8]


def test_cli_kernel_build_bad_payload_exit(ctx, capsys):
    rc = main(["kernel", "msg-build", "--payload", "zzz",
               "--out", "/tmp/unused.bin",
               "--json", "--workspace", str(ctx.workspace().root)])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 4 and payload["ok"] is False
