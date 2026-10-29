"""Tests for tools/smb-rig: Socket serving, proxy relay and the smb_rig.py command line."""

from __future__ import annotations

import contextlib
import json
import os
import random
import signal
import socket
import threading
from pathlib import Path

import pytest
from smb_rig_support import (
    CLEAN,
    SMB1_NEG,
    FuzzSession,
    K,
    Knobs,
    cases,
    corpus,
    make_seeds,
    record_conn,
    req,
    rsp,
    smb2,
    smb_rig,
    write_run,
)


@pytest.fixture()
def seeds(tmp_path):
    """Seed corpus directory shared by this file's tests."""
    return make_seeds(tmp_path)


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


def test_stats_and_replay_cli(seeds, tmp_path, capsys):
    w = record_conn(seeds, tmp_path, K(budget=1, p_mutate=1.0))
    smb_rig.main(["stats", "--cases", str(tmp_path / "cases")])
    assert "depth (connections reaching)" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="--run DIR and --conn N"):
        smb_rig.main(["replay"])
    with pytest.raises(SystemExit, match="no cases for conn 4"):
        smb_rig.main(["replay", "--run", w.dir, "--conn", "4"])
    with pytest.raises(SystemExit, match="no runs under"):
        smb_rig.main(["stats", "--cases", str(tmp_path / "none")])


# ---------------- review follow-ups: keepalives, validation, cleanup ----------------

def test_read_pdu_skips_nbss_keepalives():
    server, client = socket.socketpair()
    try:
        keepalive = smb2.nbss_wrap(b"", smb2.NBSS_KEEPALIVE)
        client.sendall(keepalive + keepalive + smb2.nbss_wrap(b"\xfeSMB-payload"))
        payload, rest = smb_rig.read_pdu(server, b"")
        assert payload == b"\xfeSMB-payload" and rest == b""
    finally:
        server.close()
        client.close()


def test_proxy_passes_keepalives_through_without_recording(tmp_path):
    rec = smb_rig.Recorder(str(tmp_path / "run"))
    cli_a, cli_b = socket.socketpair()
    up_a, up_b = socket.socketpair()
    t = threading.Thread(target=smb_rig._relay, args=(cli_a, up_a, rec))
    t.start()
    try:
        keepalive = smb2.nbss_wrap(b"", smb2.NBSS_KEEPALIVE)
        cli_b.sendall(keepalive)
        assert up_b.recv(16) == keepalive                      # type byte preserved
    finally:
        cli_b.close()
        t.join(timeout=5)
        for s in (cli_a, up_a, up_b):
            s.close()
    assert rec.n == 0


@pytest.mark.parametrize("argv", [["fuzz", "--budget", "-1"], ["fuzz", "--listen", "0"],
                                  ["fuzz", "--listen", "70000"], ["replay", "--conn", "-3"]])
def test_cli_rejects_bad_numbers(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        smb_rig.build_parser().parse_args(argv)
    err = capsys.readouterr().err
    assert exc.value.code == 2 and ("must be >= 0" in err or "not a TCP port" in err)


def _refuse_to_listen(*_args):
    raise OSError("address already in use")


def test_fuzz_stops_klog_tap_when_serving_fails(seeds, tmp_path, monkeypatch):
    stopped = []

    class FakeTap:
        seen: frozenset = frozenset()

        def stop(self):
            stopped.append(True)

    monkeypatch.setattr(smb_rig, "start_feedback", lambda writer, root: (None, None, FakeTap()))
    monkeypatch.setattr(smb_rig, "_listen", _refuse_to_listen)
    with pytest.raises(OSError, match="already in use"):
        smb_rig.main(["fuzz", "--seeds", str(seeds), "--cases", str(tmp_path / "c")])
    assert stopped == [True]


def test_sigterm_unwinds_so_cleanup_runs():
    previous = signal.getsignal(signal.SIGTERM)
    cleaned = []
    try:
        smb_rig._exit_on_sigterm()
        with pytest.raises(SystemExit) as exc:
            try:
                os.kill(os.getpid(), signal.SIGTERM)
                signal.pause() if hasattr(signal, "pause") else None
            finally:
                cleaned.append(True)
        assert exc.value.code == 128 + signal.SIGTERM and cleaned == [True]
    finally:
        signal.signal(signal.SIGTERM, previous)


def test_fuzz_meta_records_all_knobs(seeds, tmp_path, monkeypatch):
    monkeypatch.setattr(smb_rig, "_listen", _refuse_to_listen)
    with pytest.raises(OSError):
        smb_rig.main(["fuzz", "--no-klog", "--budget", "3", "--seeds", str(seeds),
                      "--cases", str(tmp_path / "c")])
    (run,) = (tmp_path / "c").iterdir()
    meta = json.loads((run / "meta.json").read_text())
    assert meta["knobs"]["budget"] == 3 and meta["knobs"]["warmup"] == Knobs().warmup
