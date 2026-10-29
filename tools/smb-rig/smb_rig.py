#!/usr/bin/env python3
"""smb-rig: malicious SMB2 server / recording proxy targeting the macOS kernel smbfs client.

Authorized local security research only (own machine). See README.md.

Modes:
  proxy   listen on --listen (default 4450), forward to a real SMB server on
          --upstream (default 1445), log every frame both directions into
          seeds/run-*/*.smbr -> builds the replay corpus.
  fuzz    answer the client from the recorded corpus (see corpus.py), with
          structure-aware mutations (see mutators.py). Every outgoing PDU is
          fsync'd to cases/run-*/ BEFORE it is sent, so the newest case after
          a kernel panic is the suspect.
  corpus  report which seed runs are usable and what templates they yield;
          --quarantine moves unusable runs to seeds/_quarantine/.

Seed record format: u32 magic 'SMBR' | u8 dir(0=req,1=resp) | u8 cmd | u32 msgid
| u32 len | payload (NBSS stripped). cmd/msgid are labels only; fuzz mode
re-parses the payload.
"""
from __future__ import annotations

import argparse
import os
import random
import select
import socket
import sys
import time

import corpus as corpus_mod
import smb2
from cases import CaseWriter
from fuzz_session import FuzzSession, Knobs

CLIENT_TIMEOUT_S = 15


class Recorder:
    def __init__(self, dirpath: str) -> None:
        self.dir = dirpath
        os.makedirs(dirpath, exist_ok=True)
        self.n = 0
        self.idx = os.path.join(dirpath, "INDEX.tsv")

    def save(self, direction: int, payload: bytes) -> None:
        chain = smb2.split_chain(payload)
        cmd, msgid = (chain[0].header.command, chain[0].header.message_id) if chain else (-1, 0)
        name = "+".join(smb2.cmd_name(e.header.command) for e in chain) or "NON_SMB2"
        fn = f"{self.n:06d}_{'req' if direction == 0 else 'rsp'}_{name}_{msgid:#x}.smbr"
        with open(os.path.join(self.dir, fn), "wb") as f:
            f.write(corpus_mod.write_record(direction, cmd, msgid, payload))
        with open(self.idx, "a") as f:
            f.write(f"{fn}\t{direction}\t{cmd}\t{msgid}\t{len(payload)}\n")
        self.n += 1


def _listen(bind: str, port: int) -> socket.socket:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(1)
    return srv


def _relay(cli: socket.socket, up: socket.socket, rec: Recorder) -> None:
    """select()-based bidirectional relay; EOF on either side ends the session."""
    bufs = {cli: b"", up: b""}
    for s in (cli, up):
        s.settimeout(None)                            # blocking; select() gates recv
    while True:
        rlist, _, xlist = select.select([cli, up], [], [cli, up])
        if xlist:
            return
        for src in rlist:
            dst, direction = (up, 0) if src is cli else (cli, 1)
            try:
                chunk = src.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            pdus, bufs[src] = smb2.nbss_split(bufs[src] + chunk)
            for _t, payload in pdus:
                rec.save(direction, payload)
                try:
                    dst.sendall(smb2.nbss_wrap(payload))
                except OSError:
                    return


def do_proxy(args: argparse.Namespace) -> None:
    rec = Recorder(os.path.join(args.seeds, time.strftime("run-%Y%m%d-%H%M%S")))
    srv = _listen(args.bind, args.listen)
    print(f"[proxy] listening {args.bind}:{args.listen} -> {args.upstream_host}:{args.upstream}")
    while True:
        cli, addr = srv.accept()
        print(f"[proxy] client {addr}")
        try:
            up = socket.create_connection((args.upstream_host, args.upstream), timeout=10)
        except OSError as e:
            print(f"[proxy] upstream connect failed: {e}")
            cli.close()
            continue
        try:
            _relay(cli, up, rec)
        finally:
            for s in (cli, up):
                s.close()
        print(f"[proxy] session ended, frames={rec.n}")


# ---------------- fuzz mode ----------------

def read_pdu(sock: socket.socket, buf: bytes) -> tuple[bytes, bytes]:
    """Block until one full NBSS PDU is buffered; return (payload, rest)."""
    while True:
        pdus, _rest = smb2.nbss_split(buf)
        if pdus:
            consumed = 4 + len(pdus[0][1])
            return pdus[0][1], buf[consumed:]
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionResetError("client closed")
        buf += chunk


def serve_connection(sock: socket.socket, session: FuzzSession, writer: CaseWriter,
                     conn: int) -> None:
    """Answer one client until it disconnects, times out, or sends ECHO."""
    buf = b""
    while True:
        payload, buf = read_pdu(sock, buf)
        outs = session.respond(payload)
        if not outs and payload[:4] != smb2.SMB2_SIG:
            writer.save(conn, "UNKNOWN_REQ", payload, "unanswered non-SMB2 request", ext="unknown")
        for out in outs:
            writer.save(conn, out.kind, out.pdu, out.desc)   # PROVENANCE: durable before send
            sock.sendall(smb2.nbss_wrap(out.pdu))
        if session.saw_echo:
            # client idles into ECHO keepalives: the cycle is over; dropping the
            # connection also exercises smbfs reconnect
            return


def do_fuzz(args: argparse.Namespace) -> None:
    corp = corpus_mod.load_corpus(args.seeds)
    _print_corpus(corp)
    if not corp.templates:
        sys.exit("no usable seed templates — run proxy mode first (see `corpus` mode)")
    seed = args.seed if args.seed is not None else int(time.time())
    knobs = Knobs(mutate_handshake=args.mutate_handshake)
    writer = CaseWriter(args.cases, seed, {"first_conn": args.first_conn, "knobs": knobs.__dict__,
                                           "seeds": os.path.abspath(args.seeds)})
    srv = _listen(args.bind, args.listen)
    print(f"[fuzz] seed={seed} cases -> {writer.dir}")
    print(f"[fuzz] listening {args.bind}:{args.listen}; run mount_smbfs against this port")
    conn = args.first_conn
    while True:
        cli, addr = srv.accept()
        # per-connection RNG: `--seed S --first-conn N` replays connection N exactly
        session = FuzzSession(corp, random.Random(f"{seed}:{conn}"), knobs)
        print(f"[fuzz] conn#{conn} from {addr} (case {writer.n + 1})")
        try:
            cli.settimeout(CLIENT_TIMEOUT_S)
            serve_connection(cli, session, writer, conn)
        except (ConnectionResetError, socket.timeout, OSError) as e:
            print(f"[fuzz] conn#{conn} ended: {type(e).__name__}: {e}")
        finally:
            cli.close()
        print(f"[fuzz] conn#{conn} done, cases={writer.n}")
        conn += 1


# ---------------- corpus mode ----------------

def _print_corpus(corp: corpus_mod.Corpus) -> None:
    for r in corp.runs:
        state = "ok" if r.usable else "UNUSABLE"
        note = f" stale-labels={r.stale_labels}" if r.stale_labels else ""
        print(f"[corpus] {os.path.basename(r.path)}: {state} frames={r.frames} "
              f"responses={r.responses} bad={r.bad_frames}{note}")
    print(f"[corpus] templates: {' '.join(corp.summary()) or '(none)'}")
    print(f"[corpus] multi-protocol negotiate reply: {'yes' if corp.mp_negotiate else 'NO'}")


def do_corpus(args: argparse.Namespace) -> None:
    corp = corpus_mod.load_corpus(args.seeds)
    _print_corpus(corp)
    if args.quarantine:
        for dest in corpus_mod.quarantine(args.seeds, corp.runs):
            print(f"[corpus] quarantined -> {dest}")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["proxy", "fuzz", "corpus"])
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--listen", type=int, default=4450)
    ap.add_argument("--upstream", type=int, default=1445, help="real smbd port")
    ap.add_argument("--upstream-host", default="127.0.0.1")
    ap.add_argument("--seeds", default="seeds")
    ap.add_argument("--cases", default="cases")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed (default: current time; recorded in the run's meta.json)")
    ap.add_argument("--first-conn", type=int, default=0,
                    help="starting connection number; with --seed, replays that connection")
    ap.add_argument("--mutate-handshake", action="store_true",
                    help="also mutate NEGOTIATE/SESSION_SETUP (can wedge mount() unkillably)")
    ap.add_argument("--quarantine", action="store_true", help="corpus mode: move unusable runs aside")
    a = ap.parse_args(argv)
    {"proxy": do_proxy, "fuzz": do_fuzz, "corpus": do_corpus}[a.mode](a)


if __name__ == "__main__":
    main()
