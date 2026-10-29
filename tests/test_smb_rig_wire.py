"""Tests for tools/smb-rig: SMB2 wire helpers (smb2.py) and structure-aware mutators (mutators.py)."""

from __future__ import annotations

import random
import struct

import pytest
from smb_rig_support import (
    create_req_body,
    create_rsp_body,
    create_with_lease,
    lease_ctx,
    mutators,
    qi_body,
    rsp,
    smb2,
    with_ctx,
)


def test_header_roundtrip_and_offsets():
    h = smb2.Header(status=0xC0000016, command=smb2.QUERY_INFO, flags=smb2.FLAG_RESPONSE,
                    message_id=0x1122334455, tree_id=7, session_id=9, credits=3, next_command=0)
    raw = smb2.pack_header(h)
    assert len(raw) == smb2.HDR
    assert struct.unpack_from("<H", raw, 12)[0] == smb2.QUERY_INFO
    assert struct.unpack_from("<I", raw, 16)[0] == smb2.FLAG_RESPONSE
    assert struct.unpack_from("<Q", raw, 24)[0] == 0x1122334455      # MessageId @24, not @28
    assert struct.unpack_from("<Q", raw, 40)[0] == 9
    assert smb2.unpack_header(raw) == h


def test_command_numbers_match_ms_smb2():
    assert (smb2.ECHO, smb2.QUERY_DIRECTORY, smb2.CHANGE_NOTIFY, smb2.QUERY_INFO) == (13, 14, 15, 16)
    assert smb2.cmd_name(16) == "QUERY_INFO"


def test_join_and_split_chain_pads_to_8():
    els = [rsp(smb2.CREATE, 5, b"x" * 13), rsp(smb2.CLOSE, 6, b"y" * 5)]
    pdu = smb2.join_chain(els)
    first = smb2.unpack_header(pdu)
    assert first.next_command == smb2.HDR + 16
    back = smb2.split_chain(pdu)
    assert [e.header.message_id for e in back] == [5, 6]
    assert back[1].body == b"y" * 5 and back[1].header.next_command == 0


def test_split_chain_survives_bad_next_command():
    pdu = smb2.join_chain([rsp(smb2.CREATE, 5, b"x" * 16), rsp(smb2.CLOSE, 6)], {0: 0xFFFFFFF8})
    assert len(smb2.split_chain(pdu)) == 1


def test_request_subkey():
    assert smb2.request_subkey(smb2.QUERY_INFO, qi_body(2, 5)) == 0x205
    assert smb2.request_subkey(smb2.QUERY_DIRECTORY, b"\x21\x00\x25") == 0x25
    assert smb2.request_subkey(smb2.IOCTL, struct.pack("<HHI", 57, 0, 0x140078)) == 0x140078
    assert smb2.request_subkey(smb2.CREATE, b"\x00" * 8) is None


def test_chain_fields_walks_create_contexts_with_loop_guard():
    ctx = struct.pack("<IHHHHI", 0, 16, 4, 0, 24, 0) + b"AAPL" + b"\x00" * 8
    looped = struct.pack("<I", 0) + ctx[4:]
    body = create_rsp_body(ctx)
    fields = mutators.chain_fields(smb2.CREATE, None, body)
    assert mutators.Field(88, 4) in fields                   # first context's Next
    body_loop = create_rsp_body(struct.pack("<I", 0x10000000) + looped[4:])
    assert len(mutators.chain_fields(smb2.CREATE, None, body_loop)) <= 5 * mutators.MAX_CHAIN_ENTRIES


def test_mutate_body_is_seeded_and_returns_new_bytes():
    body = create_rsp_body(struct.pack("<IHHHHI", 0, 16, 4, 0, 24, 0) + b"AAPL" + b"\x00" * 8)
    a = mutators.mutate_body(smb2.CREATE, None, body, random.Random(5))
    b = mutators.mutate_body(smb2.CREATE, None, body, random.Random(5))
    assert a == b and isinstance(a[0], bytes) and a[1]


def test_symlink_error_shape():
    status, body, desc = mutators.symlink_error(random.Random(2))
    assert status == smb2.STATUS_STOPPED_ON_SYMLINK
    assert struct.unpack_from("<H", body, 0)[0] == 9
    byte_count = struct.unpack_from("<I", body, 4)[0]
    assert byte_count == len(body) - 8
    assert struct.unpack_from("<I", body, 12)[0] == mutators.SYMLINK_ERROR_TAG
    assert desc.startswith("symlink:")


def test_oplock_break_is_unsolicited():
    el, _ = mutators.oplock_break(b"F" * 16, random.Random(1))
    assert el.header.message_id == smb2.NO_MESSAGE_ID and el.header.command == smb2.OPLOCK_BREAK
    assert len(el.body) == 24


@pytest.mark.parametrize("seed", range(40))
def test_inject_status_families_are_wellformed(seed):
    body = create_rsp_body()
    status, out, desc = mutators.inject_status(smb2.CREATE, None, body, random.Random(seed))
    assert status != smb2.STATUS_SUCCESS and isinstance(out, bytes) and desc
    if status not in (smb2.STATUS_BUFFER_OVERFLOW,):
        assert struct.unpack_from("<H", out, 0)[0] == 9               # ERROR response body


@pytest.mark.parametrize("seed", range(30))
def test_mutate_body_covers_resize_and_flip(seed):
    out, desc = mutators.mutate_body(smb2.LOCK, None, b"\x00" * 32, random.Random(seed))
    assert isinstance(out, bytes) and desc


def test_mutate_body_never_stomps_past_a_truncation():
    ctx = struct.pack("<IHHHHI", 0, 16, 4, 0, 24, 0) + b"AAPL" + b"\x00" * 8
    body = create_rsp_body(ctx)
    for seed in range(2000):                                 # regression: struct.error after trunc
        mutators.mutate_body(smb2.CREATE, None, body, random.Random(seed))


def test_resize_truncates_and_extends():
    descs = {mutators._resize(bytearray(b"x" * 10), random.Random(s))[1].split("+")[0].split("->")[0]
             for s in range(20)}
    assert descs == {"trunc", "extend"}


def test_next_command_override_targets_non_final_element():
    overrides, desc = mutators.next_command_override(3, random.Random(1))
    (idx,) = overrides
    assert 0 <= idx < 2 and desc.startswith(f"next[{idx}]")


@pytest.mark.parametrize("subkey,per_entry", [
    (0x100 | mutators.FILE_STREAM_INFORMATION, mutators.STREAM_INFO_FIELDS),
    (0x100 | mutators.FILE_FULL_EA_INFORMATION, mutators.FULL_EA_FIELDS),
])
def test_chain_spec_query_info_streams_and_eas(subkey, per_entry):
    entry = struct.pack("<II", 0, 14) + b"\x00" * 16
    body = struct.pack("<HHI", 9, smb2.HDR + 8, len(entry)) + entry
    fields = mutators.chain_fields(smb2.QUERY_INFO, subkey, body)
    assert [f.offset - 8 for f in fields] == [f.offset for f in per_entry]


def test_chain_spec_dir_and_notify():
    entry = b"\x00" * 72
    body = struct.pack("<HHI", 9, smb2.HDR + 8, len(entry)) + entry
    assert mutators.Field(68, 4) in mutators.chain_fields(smb2.QUERY_DIRECTORY, 0x25, body)
    assert mutators.Field(16, 4) in mutators.chain_fields(smb2.QUERY_DIRECTORY, 0x0C, body)
    assert mutators.Field(16, 4) in mutators.chain_fields(smb2.CHANGE_NOTIFY, None, body)
    assert mutators.chain_fields(smb2.READ, None, body) == []


@pytest.mark.parametrize("v2", [False, True])
def test_echo_lease_key_copies_client_keys(v2):
    parent_req = b"P" * 16 if v2 else b""
    tail = b"\x00" * 4 if v2 else b""
    req_body = with_ctx(create_req_body("")[:56], smb2.CTX_FIELDS_REQUEST,
                        lease_ctx(b"K" * 16, parent_req, tail))
    rsp_body = with_ctx(create_rsp_body()[:88], smb2.CTX_FIELDS_RESPONSE,
                        lease_ctx(b"r" * 16, b"q" * 16 if v2 else b"", tail))
    out = smb2.echo_lease_key(req_body, rsp_body)
    (name, off, ln), = smb2.create_contexts(out, True)
    assert name == b"RqLs" and out[off:off + 16] == b"K" * 16
    assert out[off + 16:off + 32] == rsp_body[off + 16:off + 32]            # lease state untouched
    if v2:
        assert ln == smb2.LEASE_V2_DATA_LEN and out[off + 32:off + 48] == b"P" * 16
    assert len(out) == len(rsp_body)


def test_echo_lease_key_noop_without_lease_and_on_garbage():
    rsp_body = create_rsp_body()
    assert smb2.echo_lease_key(create_req_body("a"), rsp_body) == rsp_body
    assert smb2.create_contexts(b"\x00" * 10, True) == []
    bogus = bytearray(create_rsp_body(b"\xff" * 24))
    struct.pack_into("<I", bogus, 88, 0)                         # Next=0 but garbage offsets
    assert smb2.echo_lease_key(create_req_body(""), bytes(bogus)) == bytes(bogus)


def test_ioctl_reply_echoes_request_file_id():
    req_body = struct.pack("<HHI", 57, 0, 0x140078) + b"Q" * 16 + b"\x00" * 32
    rsp_body = struct.pack("<HHI", 49, 0, 0x140078) + b"r" * 16 + b"\x00" * 24
    assert smb2.echo_ioctl_file_id(req_body, rsp_body)[8:24] == b"Q" * 16
    assert smb2.echo_ioctl_file_id(b"\x00" * 4, rsp_body) == rsp_body


def test_lease_key_of_and_break_ack():
    assert smb2.lease_key_of(create_with_lease(b"K" * 16)) == b"K" * 16
    assert smb2.lease_key_of(create_req_body("x")) is None
    oplock_ack = struct.pack("<HBBI", 24, 1, 0, 0) + b"F" * 16
    lease_ack = struct.pack("<HHI", 36, 0, 0) + b"K" * 16 + struct.pack("<IQ", 1, 0)
    assert smb2.break_ack_response(oplock_ack) == oplock_ack
    assert smb2.break_ack_response(lease_ack) == lease_ack
    assert smb2.break_ack_response(b"\x07\x00" + b"\x00" * 30) is None
    assert smb2.break_ack_response(b"") is None


def test_lease_break_notification_shape():
    el, desc = mutators.lease_break(b"K" * 16, random.Random(3))
    assert len(el.body) == mutators.LEASE_BREAK_SIZE == 44
    assert struct.unpack_from("<H", el.body, 0)[0] == 44 and el.body[8:24] == b"K" * 16
    assert el.header.message_id == smb2.NO_MESSAGE_ID and desc.startswith("lease_break:")
