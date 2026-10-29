"""Tests for tools/smb-rig (kernel smbfs client fuzzing rig).

Covers SMB2 header/compound framing, seed-corpus pairing, the per-connection
response engine (MessageId echo, compound replies, handshake legs, CANCEL),
durable case storage, and a socketpair round-trip of serve_connection.
"""

from __future__ import annotations

import os
import random
import socket
import struct
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOL_DIR = REPO / "tools" / "smb-rig"
sys.path.insert(0, str(TOOL_DIR))

import cases
import corpus
import mutators
import smb2
import smb_rig
from fuzz_session import FuzzSession, Knobs

CLEAN = Knobs(p_status=0, p_pending=0, p_next=0, p_oplock=0, p_clean=1.0)
SESS = 0x1CE77404
TREE = 0x5


def req(cmd, mid, body=b"\x00" * 8, flags=0, sess=SESS, tree=TREE):
    return smb2.Element(smb2.Header(status=0, command=cmd, flags=flags, message_id=mid,
                                    session_id=sess, tree_id=tree), body)


def rsp(cmd, mid, body=b"\x09\x00" + b"\x00" * 7, status=0, sess=SESS, tree=TREE, credits=1):
    return smb2.Element(smb2.Header(status=status, command=cmd, flags=smb2.FLAG_RESPONSE,
                                    message_id=mid, session_id=sess, tree_id=tree,
                                    credits=credits), body)


def create_rsp_body(ctx=b""):
    body = bytearray(struct.pack("<HBBI", 89, 0, 0, 1) + b"\x00" * 48)
    body += struct.pack("<II", 0x80, 0) + b"F" * 16             # attrs, reserved2, FileId
    off = smb2.HDR + 88 if ctx else 0
    body += struct.pack("<II", off, len(ctx))
    return bytes(body) + ctx


def qi_body(info_type, cls):
    return struct.pack("<HBBI", 41, info_type, cls, 0) + b"\x00" * 32


def write_run(root, name, frames):
    d = root / name
    d.mkdir(parents=True)
    for i, (direction, payload) in enumerate(frames):
        (d / f"{i:06d}.smbr").write_bytes(corpus.write_record(direction, 0, 0, payload))
    return d


SMB1_NEG = b"\xffSMB\x72" + b"\x00" * 30


@pytest.fixture()
def seeds(tmp_path):
    """One realistic run: SMB1 mp-negotiate, 2-leg auth, tree, compound CREATE."""
    j = smb2.join_chain
    frames = [
        (0, SMB1_NEG),
        (1, j([rsp(smb2.NEGOTIATE, 0, b"MP" * 40, sess=0, tree=0)])),
        (0, j([req(smb2.NEGOTIATE, 1, sess=0, tree=0)])),
        (1, j([rsp(smb2.NEGOTIATE, 1, b"NG" * 40, sess=0, tree=0)])),
        (0, j([req(smb2.SESSION_SETUP, 2, sess=0, tree=0)])),
        (1, j([rsp(smb2.SESSION_SETUP, 2, b"L0" * 8, status=smb2.STATUS_MORE_PROCESSING_REQUIRED, tree=0)])),
        (0, j([req(smb2.SESSION_SETUP, 3, tree=0)])),
        (1, j([rsp(smb2.SESSION_SETUP, 3, b"L1" * 4, tree=0)])),
        (0, j([req(smb2.TREE_CONNECT, 4, tree=0)])),
        (1, j([rsp(smb2.TREE_CONNECT, 4, b"TC" * 8, tree=TREE)])),
        (0, j([req(smb2.CREATE, 5), req(smb2.QUERY_INFO, 6, qi_body(1, 0x12), flags=smb2.FLAG_RELATED),
               req(smb2.CLOSE, 7, flags=smb2.FLAG_RELATED)])),
        (1, j([rsp(smb2.CREATE, 5, create_rsp_body()), rsp(smb2.QUERY_INFO, 6, b"QI" * 20),
               rsp(smb2.CLOSE, 7, b"CL" * 30)])),
    ]
    write_run(tmp_path / "seeds", "run-1", frames)
    return tmp_path / "seeds"


# ---------------- smb2 ----------------

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


# ---------------- corpus ----------------

def test_corpus_pairs_requests_and_legs(seeds):
    c = corpus.load_corpus(str(seeds))
    assert c.mp_negotiate is not None and b"MP" in c.mp_negotiate
    assert c.latest(smb2.NEGOTIATE, None).body.startswith(b"NG")
    assert c.latest(smb2.SESSION_SETUP, 0).header.status == smb2.STATUS_MORE_PROCESSING_REQUIRED
    assert c.latest(smb2.SESSION_SETUP, 1).header.status == smb2.STATUS_SUCCESS
    assert c.latest(smb2.QUERY_INFO, 0x112).body.startswith(b"QI")   # split from compound


def test_corpus_ignores_stale_record_labels(tmp_path):
    payload = smb2.join_chain([rsp(smb2.CREATE, 9, create_rsp_body())])
    d = tmp_path / "seeds" / "run-old"
    d.mkdir(parents=True)
    (d / "000000.smbr").write_bytes(corpus.write_record(1, 0, 0xFEFF0000, payload))
    c = corpus.load_corpus(str(tmp_path / "seeds"))
    assert (smb2.CREATE, None) in c.templates and (smb2.NEGOTIATE, None) not in c.templates
    assert c.runs[0].stale_labels == 1


def test_quarantine_moves_unusable_runs(tmp_path):
    root = tmp_path / "seeds"
    write_run(root, "run-reqonly", [(0, SMB1_NEG)])
    write_run(root, "run-garbage", [(1, b"\xfeSMB" + b"\xff" * 80)])
    c = corpus.load_corpus(str(root))
    moved = corpus.quarantine(str(root), c.runs)
    assert len(moved) == 2
    assert corpus.run_dirs(str(root)) == []


# ---------------- fuzz session ----------------

def replies(outs):
    return [smb2.split_chain(o.pdu) for o in outs]


def test_handshake_replays_legs_with_recorded_status(seeds):
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(1), Knobs())
    outs = s.respond(SMB1_NEG)
    assert outs[0].kind == "SMB1_NEGOTIATE"
    leg0 = replies(s.respond(smb2.join_chain([req(smb2.SESSION_SETUP, 2, sess=0, tree=0)])))[0][0]
    assert leg0.header.status == smb2.STATUS_MORE_PROCESSING_REQUIRED
    assert leg0.header.message_id == 2 and leg0.header.session_id == SESS
    leg1 = replies(s.respond(smb2.join_chain([req(smb2.SESSION_SETUP, 3, tree=0)])))[0][0]
    assert leg1.header.status == smb2.STATUS_SUCCESS and leg1.body == b"L1" * 4


def test_compound_request_gets_every_element_answered(seeds):
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(1), CLEAN)
    pdu = smb2.join_chain([req(smb2.CREATE, 40), req(smb2.QUERY_INFO, 41, qi_body(1, 0x12), flags=smb2.FLAG_RELATED,
                                                     sess=smb2.RELATED_ID64, tree=smb2.RELATED_ID32),
                           req(smb2.CLOSE, 42, flags=smb2.FLAG_RELATED)])
    (chain,) = replies(s.respond(pdu))
    assert [e.header.message_id for e in chain] == [40, 41, 42]
    assert [e.header.command for e in chain] == [smb2.CREATE, smb2.QUERY_INFO, smb2.CLOSE]
    assert all(e.header.flags & smb2.FLAG_RESPONSE for e in chain)
    assert chain[1].header.flags & smb2.FLAG_RELATED
    assert chain[1].header.session_id == SESS and chain[1].header.tree_id == TREE


def test_unknown_command_gets_wellformed_error(seeds):
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(1), CLEAN)
    (chain,) = replies(s.respond(smb2.join_chain([req(smb2.LOCK, 77)])))
    h = chain[0].header
    assert h.status == smb2.STATUS_NOT_SUPPORTED and h.message_id == 77
    assert h.flags & smb2.FLAG_RESPONSE and h.next_command == 0
    assert chain[0].body == smb2.ERROR_BODY


def test_cancel_is_never_answered_and_echo_ends_cycle(seeds):
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(1), CLEAN)
    assert s.respond(smb2.join_chain([req(smb2.CANCEL, 0)])) == []
    s.respond(smb2.join_chain([req(smb2.QUERY_INFO, 50, qi_body(1, 0x12))]))
    assert not s.saw_echo                                   # QUERY_INFO (16) is not ECHO
    s.respond(smb2.join_chain([req(smb2.ECHO, 51)]))
    assert s.saw_echo


def test_pending_emits_interim_then_async_final(seeds):
    knobs = Knobs(p_status=0, p_pending=1.0, p_double_final=1.0, p_next=0, p_oplock=0, p_clean=1.0)
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(3), knobs)
    outs = s.respond(smb2.join_chain([req(smb2.CREATE, 60)]))
    hs = [smb2.unpack_header(o.pdu) for o in outs]
    assert hs[0].status == smb2.STATUS_PENDING and hs[0].flags & smb2.FLAG_ASYNC
    assert all(h.message_id == 60 for h in hs) and len(hs) == 3
    assert hs[1].reserved == hs[0].reserved and hs[1].tree_id == hs[0].tree_id   # same AsyncId


def test_session_is_deterministic_per_seed(seeds):
    c = corpus.load_corpus(str(seeds))
    pdu = smb2.join_chain([req(smb2.CREATE, 5)])
    a = FuzzSession(c, random.Random("7:3"), Knobs()).respond(pdu)
    b = FuzzSession(c, random.Random("7:3"), Knobs()).respond(pdu)
    assert a == b


# ---------------- mutators ----------------

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


# ---------------- cases ----------------

def test_case_writer_unique_runs_and_index(tmp_path):
    w1 = cases.CaseWriter(str(tmp_path), 1, {})
    w2 = cases.CaseWriter(str(tmp_path), 1, {})
    assert w1.dir != w2.dir                                  # restart never overwrites
    p = w1.save(0, "CREATE", b"abc", "len@80:0x0->0x1\twith tab")
    assert Path(p).read_bytes() == b"abc"
    lines = (Path(w1.dir) / "INDEX.tsv").read_text().splitlines()
    assert lines[0].split("\t") == list(cases.CaseWriter.INDEX_COLUMNS)
    assert len(lines[1].split("\t")) == len(cases.CaseWriter.INDEX_COLUMNS)


def test_durable_write_fsyncs_before_return(tmp_path, monkeypatch):
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real(fd)))
    cases.durable_write(str(tmp_path / "c.rsp"), b"x")
    assert len(synced) >= 2                                  # file + directory


# ---------------- integration: serve_connection over a socketpair ----------------

def test_serve_connection_round_trip(seeds, tmp_path):
    corp = corpus.load_corpus(str(seeds))
    writer = cases.CaseWriter(str(tmp_path / "cases"), 1, {})
    server, client = socket.socketpair()
    session = FuzzSession(corp, random.Random(1), CLEAN)
    t = threading.Thread(target=smb_rig.serve_connection, args=(server, session, writer, 0))
    t.start()
    try:
        client.sendall(smb2.nbss_wrap(SMB1_NEG))
        mp, buf = smb_rig.read_pdu(client, b"")
        assert b"MP" in mp
        client.sendall(smb2.nbss_wrap(smb2.join_chain([req(smb2.NEGOTIATE, 1, sess=0, tree=0)])))
        neg, buf = smb_rig.read_pdu(client, buf)
        assert smb2.unpack_header(neg).message_id == 1
        client.sendall(smb2.nbss_wrap(smb2.join_chain([req(smb2.ECHO, 2)])))
        echo, _ = smb_rig.read_pdu(client, buf)
        assert smb2.unpack_header(echo).command == smb2.ECHO
        t.join(timeout=5)
        assert not t.is_alive()                              # ECHO ends the cycle
    finally:
        server.close()
        client.close()
    assert writer.n == 3


def test_serve_connection_logs_unanswered_non_smb2(seeds, tmp_path):
    writer = cases.CaseWriter(str(tmp_path / "cases"), 1, {})
    server, client = socket.socketpair()
    session = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(1), CLEAN)
    t = threading.Thread(target=lambda: pytest.raises(ConnectionResetError, smb_rig.serve_connection,
                                                      server, session, writer, 0))
    t.start()
    client.sendall(smb2.nbss_wrap(b"\xffSMB\x25" + b"\x00" * 20))   # SMB1 non-negotiate
    client.close()
    t.join(timeout=5)
    server.close()
    assert writer.n == 1 and next(Path(writer.dir).glob("*.unknown"))


# ---------------- mutator families ----------------

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


# ---------------- CLI / proxy ----------------

def test_corpus_mode_reports_and_quarantines(seeds, capsys):
    write_run(seeds, "run-0-reqonly", [(0, SMB1_NEG)])
    smb_rig.main(["corpus", "--seeds", str(seeds), "--quarantine"])
    out = capsys.readouterr().out
    assert "run-0-reqonly: UNUSABLE" in out and "quarantined" in out
    assert "SESSION_SETUP[0x0]" in out and "negotiate reply: yes" in out


def test_fuzz_mode_refuses_empty_corpus(tmp_path):
    with pytest.raises(SystemExit, match="no usable seed templates"):
        smb_rig.main(["fuzz", "--seeds", str(tmp_path), "--cases", str(tmp_path / "c")])


def test_proxy_relay_records_both_directions(tmp_path):
    rec = smb_rig.Recorder(str(tmp_path / "run"))
    cli_a, cli_b = socket.socketpair()
    up_a, up_b = socket.socketpair()
    t = threading.Thread(target=smb_rig._relay, args=(cli_a, up_a, rec))
    t.start()
    try:
        request = smb2.join_chain([req(smb2.CREATE, 5), req(smb2.CLOSE, 6, flags=smb2.FLAG_RELATED)])
        cli_b.sendall(smb2.nbss_wrap(request))
        fwd, _ = smb_rig.read_pdu(up_b, b"")
        assert fwd == request
        reply = smb2.join_chain([rsp(smb2.CREATE, 5)])
        up_b.sendall(smb2.nbss_wrap(reply))
        back, _ = smb_rig.read_pdu(cli_b, b"")
        assert back == reply
    finally:
        cli_b.close()
        t.join(timeout=5)
        for s in (cli_a, up_a, up_b):
            s.close()
    names = sorted(p.name for p in (tmp_path / "run").glob("*.smbr"))
    assert names[0].startswith("000000_req_CREATE+CLOSE_0x5") and "_rsp_CREATE_" in names[1]
    report, _ = corpus.scan_run(str(tmp_path / "run"))
    assert report.usable and report.stale_labels == 0
