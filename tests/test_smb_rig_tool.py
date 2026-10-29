"""Tests for tools/smb-rig (kernel smbfs client fuzzing rig).

Covers SMB2 header/compound framing, seed-corpus pairing, the per-connection
response engine (MessageId echo, compound replies, handshake legs, CANCEL),
durable case storage, and a socketpair round-trip of serve_connection.
"""

from __future__ import annotations

import contextlib
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
import triage
from fuzz_session import FuzzSession, Knobs

CLEAN = Knobs.clean()
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
    knobs = Knobs(budget=1, p_mutate=0, p_pending=1.0, p_double_final=1.0, p_next=0, p_oplock=0)
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


# ---------------- mutation budget ----------------

def _drive(session, n=60):
    """Feed n CREATE+QUERY_INFO+CLOSE compounds; return all Outgoing."""
    outs = []
    for i in range(n):
        mid = 100 + 3 * i
        outs += session.respond(smb2.join_chain([
            req(smb2.CREATE, mid), req(smb2.QUERY_INFO, mid + 1, qi_body(1, 0x12), flags=smb2.FLAG_RELATED),
            req(smb2.CLOSE, mid + 2, flags=smb2.FLAG_RELATED)]))
    return outs


@pytest.mark.parametrize("budget", [0, 1, 2, 5])
def test_budget_caps_mutation_events_per_connection(seeds, budget):
    c = corpus.load_corpus(str(seeds))
    knobs = Knobs(budget=budget, p_mutate=1.0, p_pending=0.5, p_next=0.5, p_oplock=0.5)
    s = FuzzSession(c, random.Random(9), knobs)
    outs = _drive(s)
    assert s.budget == 0
    mutated_reqs = {o.req for o in outs if o.mutated}
    assert 0 < len(mutated_reqs) <= budget if budget else not mutated_reqs
    assert sum(1 for o in outs if not o.mutated) > 0          # session continues clean afterwards


def test_budget_refills_per_mount_on_a_reused_session(seeds):
    c = corpus.load_corpus(str(seeds))
    s = FuzzSession(c, random.Random(4), Knobs(budget=1, p_mutate=1.0, p_pending=0, p_next=0,
                                               p_oplock=0, p_credit=0))
    mutated_per_mount = []
    for mount in range(3):
        s.respond(smb2.join_chain([req(smb2.TREE_CONNECT, 1000 + mount, tree=0)]))
        outs = _drive(s, 5)
        mutated_per_mount.append(sum(o.mutated for o in outs))
    assert mutated_per_mount == [1, 1, 1]


def test_clean_knobs_never_mutate_and_stamp_request_ordinals(seeds):
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(1), Knobs.clean())
    outs = _drive(s, 10)
    assert not any(o.mutated for o in outs)
    assert [o.req for o in outs] == list(range(1, 11))
    assert all("clean" in o.desc for o in outs)


# ---------------- triage: stats / replay ----------------

def _record_conn(seeds, tmp_path, knobs, n=12):
    writer = cases.CaseWriter(str(tmp_path / "cases"), 5, {})
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random("5:0"), knobs)
    for o in _drive(s, n):
        writer.save(0, o.kind, o.pdu, o.desc, req=o.req, mutated=o.mutated)
    writer.save(0, "UNKNOWN_REQ", b"junk", "x", ext="unknown", req=n + 1)
    return writer


def test_read_index_roundtrip_and_torn_line(seeds, tmp_path):
    w = _record_conn(seeds, tmp_path, Knobs(budget=1, p_mutate=1.0))
    with open(w.index, "a") as f:
        f.write("0000999\t2026-")                             # torn by a panic mid-write
    rows = cases.read_index(w.dir)
    assert len(rows) == w.n and rows[-1].kind == "UNKNOWN_REQ" and rows[-1].path.endswith(".unknown")
    assert sum(r.mutated for r in rows) >= 1 and rows[0].req == 1
    assert cases.latest_run(str(tmp_path / "cases")) == w.dir
    assert cases.latest_run(str(tmp_path / "nothing")) is None


def test_run_stats_depth_and_suspects(seeds, tmp_path):
    w = _record_conn(seeds, tmp_path, Knobs(budget=2, p_mutate=1.0))
    st = triage.run_stats(cases.read_index(w.dir))
    assert st.conns == 1 and st.reached["CREATE"] == 1 and st.reached["QUERY_INFO"] == 1
    assert st.reached["READ"] == 0 and st.mutated >= 1 and st.suspects
    text = "\n".join(triage.format_stats(st))
    assert "CREATE=1(100%)" in text and "panic suspects" in text
    assert triage.format_stats(triage.run_stats([]))[0].startswith("connections=0")


def test_patch_message_ids_preserves_corrupt_chain_and_notifications():
    good = smb2.join_chain([rsp(smb2.CREATE, 1, b"x" * 8), rsp(smb2.CLOSE, 2)])
    patched = smb2.split_chain(triage.patch_message_ids(good, [70, 71]))
    assert [e.header.message_id for e in patched] == [70, 71]
    corrupt = smb2.join_chain([rsp(smb2.CREATE, 1, b"x" * 8), rsp(smb2.CLOSE, 2)], {0: 0xFFFFFFF8})
    out = triage.patch_message_ids(corrupt, [70, 71])
    assert out[:24] == corrupt[:24] and out[32:] == corrupt[32:]          # only MessageId moved
    assert struct.unpack_from("<Q", out, 24)[0] == 70
    brk, _ = mutators.oplock_break(b"F" * 16, random.Random(1))
    note = smb2.join_chain([brk])
    assert triage.patch_message_ids(note, [5]) == note


def test_replay_reserves_recorded_bytes_then_falls_back_clean(seeds, tmp_path):
    w = _record_conn(seeds, tmp_path, Knobs(budget=2, p_mutate=1.0, p_next=1.0), n=6)
    rows = cases.read_index(w.dir)
    corp = corpus.load_corpus(str(seeds))
    rs = triage.ReplaySession(rows, FuzzSession(corp, random.Random(0), Knobs.clean()))
    # live client re-sends the same 6 compounds, but with different MessageIds
    live = []
    for i in range(7):
        mid = 900 + 3 * i
        live.append(rs.respond(smb2.join_chain([
            req(smb2.CREATE, mid), req(smb2.QUERY_INFO, mid + 1, qi_body(1, 0x12), flags=smb2.FLAG_RELATED),
            req(smb2.CLOSE, mid + 2, flags=smb2.FLAG_RELATED)])))
    recorded = [r for r in rows if r.req == 1]
    first = live[0]
    assert len(first) == len(recorded)
    orig = Path(recorded[0].path).read_bytes()
    zero = [0, 0, 0]
    assert triage.patch_message_ids(first[0].pdu, zero) == triage.patch_message_ids(orig, zero)
    assert struct.unpack_from("<Q", first[0].pdu, 24)[0] == 900
    assert any(o.mutated for group in live[:6] for o in group)
    assert not any(o.mutated for o in live[6]) and live[6][0].desc.startswith("CREATE:clean")
    assert not rs.saw_echo


def test_serve_forever_survives_rig_bug(seeds, tmp_path):
    writer = cases.CaseWriter(str(tmp_path / "cases"), 1, {})
    server, client = socket.socketpair()
    client.sendall(smb2.nbss_wrap(smb2.join_chain([req(smb2.CREATE, 1)])))

    class Boom:
        saw_echo = False

        def respond(self, payload):
            raise ValueError("mutator bug")

    class OneShot:
        def __init__(self):
            self.calls = 0

        def accept(self):
            self.calls += 1
            if self.calls > 1:
                raise KeyboardInterrupt                       # end the loop after one conn
            return server, ("127.0.0.1", 1)

    with pytest.raises(KeyboardInterrupt):
        smb_rig._serve_forever(OneShot(), writer, 7, lambda _c: Boom(), "fuzz", spawn=lambda fn: fn())
    client.close()
    err = Path(writer.dir) / "conn-7.error.txt"
    assert "mutator bug" in err.read_text()


def test_concurrent_connections_are_not_starved(seeds, tmp_path):
    """An idle mounted session must not block a new mount's NEGOTIATE."""
    corp = corpus.load_corpus(str(seeds))
    writer = cases.CaseWriter(str(tmp_path / "cases"), 1, {})
    srv = smb_rig._listen("127.0.0.1", 0)
    port = srv.getsockname()[1]
    def serve():
        with contextlib.suppress(OSError):                     # srv.close() ends accept()
            smb_rig._serve_forever(srv, writer, 0,
                                   lambda c: FuzzSession(corp, random.Random(c), Knobs.clean()), "t")

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    idle = socket.create_connection(("127.0.0.1", port))      # held open, never talks
    fresh = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        fresh.sendall(smb2.nbss_wrap(smb2.join_chain([req(smb2.NEGOTIATE, 1, sess=0, tree=0)])))
        neg, _ = smb_rig.read_pdu(fresh, b"")
        assert smb2.unpack_header(neg).command == smb2.NEGOTIATE
    finally:
        idle.close()
        fresh.close()
        srv.close()


def test_case_writer_is_thread_safe(tmp_path):
    w = cases.CaseWriter(str(tmp_path), 1, {})
    threads = [threading.Thread(target=lambda c=c: [w.save(c, "CREATE", b"x", "d") for _ in range(10)])
               for c in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    rows = cases.read_index(w.dir)
    assert [r.case for r in rows] == [f"{i:07d}" for i in range(1, 41)]
    assert all(Path(r.path).exists() for r in rows)


def test_credits_follow_client_request_and_abuse_is_budgeted(seeds):
    c = corpus.load_corpus(str(seeds))
    s = FuzzSession(c, random.Random(1), Knobs.clean())
    el = smb2.Element(smb2.Header(status=0, command=smb2.CREATE, flags=0, message_id=9,
                                  session_id=SESS, tree_id=TREE, credits=40), b"\x00" * 8)
    (out,) = s.respond(smb2.join_chain([el]))
    assert smb2.unpack_header(out.pdu).credits == 40
    huge = smb2.Element(smb2.replace(el.header, credits=60000, message_id=10), el.body)
    (out,) = s.respond(smb2.join_chain([huge]))
    assert smb2.unpack_header(out.pdu).credits == 512
    abuse = FuzzSession(c, random.Random(2), Knobs(budget=1, p_mutate=0, p_credit=1.0,
                                                   p_pending=0, p_next=0, p_oplock=0))
    outs = _drive(abuse, 5)
    abused = [o for o in outs if "credits=" in o.desc]
    assert len(abused) == 1 and abused[0].mutated


def ntlm_authenticate(user):
    name = user.encode("utf-16-le")
    hdr = bytearray(b"NTLMSSP\x00" + struct.pack("<I", 3) + b"\x00" * 52)
    struct.pack_into("<HHI", hdr, 36, len(name), len(name), len(hdr))
    return b"\xa1\x82" + bytes(hdr) + name


def test_ntlm_auth_user_and_corpus_identity(tmp_path):
    assert corpus.ntlm_auth_user(b"\x00" * 30 + ntlm_authenticate("GUEST")) == "GUEST"
    assert corpus.ntlm_auth_user(b"no ntlm here") is None
    negotiate = bytearray(ntlm_authenticate("x"))
    struct.pack_into("<I", negotiate, 2 + 8, 1)                # type 1, not AUTHENTICATE
    assert corpus.ntlm_auth_user(bytes(negotiate)) is None
    frames = [
        (0, smb2.join_chain([req(smb2.SESSION_SETUP, 3, b"\x19\x00" + b"\x00" * 22 + ntlm_authenticate("GUEST"))])),
        (1, smb2.join_chain([rsp(smb2.SESSION_SETUP, 3, b"L1" * 4)])),
    ]
    write_run(tmp_path / "seeds", "run-g", frames)
    assert corpus.load_corpus(str(tmp_path / "seeds")).auth_users == ("GUEST",)


def create_req_body(name):
    raw = name.encode("utf-16-le")
    body = bytearray(struct.pack("<H", 57) + b"\x00" * 54)
    struct.pack_into("<HH", body, 44, smb2.HDR + len(body) if raw else 0, len(raw))
    return bytes(body) + raw


def test_create_name_and_chain_signature():
    assert smb2.create_name(create_req_body("hello.txt")) == "hello.txt".encode("utf-16-le")
    assert smb2.create_name(create_req_body("")) == b""
    assert smb2.create_name(b"\x00" * 10) == b""
    sig = corpus.chain_signature([req(smb2.CREATE, 1, create_req_body("a")),
                                  req(smb2.QUERY_INFO, 2, qi_body(1, 0x12))])
    assert sig == ((smb2.CREATE, None, "a".encode("utf-16-le")), (smb2.QUERY_INFO, 0x112, b""))
    assert corpus.chain_signature([req(smb2.TREE_CONNECT, 1)]) is None
    assert corpus.chain_signature([req(smb2.CANCEL, 1)]) is None


def test_request_matched_chain_beats_random_template(tmp_path):
    """Share-root CREATE must get the root's recorded reply, not a random file's."""
    j = smb2.join_chain
    frames = []
    for i, name in enumerate(["", "hello.txt", "a", "b", "c"]):
        mid = 10 + i
        frames += [(0, j([req(smb2.CREATE, mid, create_req_body(name))])),
                   (1, j([rsp(smb2.CREATE, mid, create_rsp_body() + name.encode() + b"#")]))]
    write_run(tmp_path / "seeds", "run-c", frames)
    c = corpus.load_corpus(str(tmp_path / "seeds"))
    assert len(c.chains) == 5
    for seed in range(20):
        s = FuzzSession(c, random.Random(seed), Knobs.clean())
        (out,) = s.respond(j([req(smb2.CREATE, 99, create_req_body(""))]))
        assert smb2.split_chain(out.pdu)[0].body == create_rsp_body() + b"#"


def test_stats_and_replay_cli(seeds, tmp_path, capsys):
    w = _record_conn(seeds, tmp_path, Knobs(budget=1, p_mutate=1.0))
    smb_rig.main(["stats", "--cases", str(tmp_path / "cases")])
    assert "depth (connections reaching)" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="--run DIR and --conn N"):
        smb_rig.main(["replay"])
    with pytest.raises(SystemExit, match="no cases for conn 4"):
        smb_rig.main(["replay", "--run", w.dir, "--conn", "4"])
    with pytest.raises(SystemExit, match="no runs under"):
        smb_rig.main(["stats", "--cases", str(tmp_path / "none")])
