"""Shared helpers and fixtures for the tools/smb-rig test files.

Puts tools/smb-rig on sys.path and re-exports its modules, so test files
import them from here and import order cannot break the path setup.
"""

from __future__ import annotations

import collections
import random
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOL_DIR = REPO / "tools" / "smb-rig"
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import budget as budget_mod
import cases
import corpus
import favored
import klog
import mutators
import smb2
import smb_rig
import triage
from fuzz_session import FuzzSession, Knobs

__all__ = ['CLEAN', 'SESS', 'SMB1_NEG', 'TREE', 'FuzzSession', 'K', 'Knobs', 'budget_mod', 'cases', 'corpus', 'create_req_body', 'create_rsp_body', 'create_with_lease', 'drive_compounds', 'favored', 'klog', 'lease_ctx', 'make_seeds', 'mount_positions', 'mutators', 'ntlm_authenticate', 'qi_body', 'record_conn', 'replies', 'req', 'rsp', 'smb2', 'smb_rig', 'triage', 'with_ctx', 'write_run']


CLEAN = Knobs.clean()


SESS = 0x1CE77404


TREE = 0x5


def K(**kw):
    """Knobs with flat probabilities and no warm-up, for tests that pin exact behaviour."""
    return Knobs(spread=False, warmup=0, **kw)


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


def make_seeds(tmp_path):
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


def replies(outs):
    return [smb2.split_chain(o.pdu) for o in outs]


def drive_compounds(session, n=60):
    """Feed n CREATE+QUERY_INFO+CLOSE compounds; return all Outgoing."""
    outs = []
    for i in range(n):
        mid = 100 + 3 * i
        outs += session.respond(smb2.join_chain([
            req(smb2.CREATE, mid), req(smb2.QUERY_INFO, mid + 1, qi_body(1, 0x12), flags=smb2.FLAG_RELATED),
            req(smb2.CLOSE, mid + 2, flags=smb2.FLAG_RELATED)]))
    return outs


def record_conn(seeds, tmp_path, knobs, n=12):
    writer = cases.CaseWriter(str(tmp_path / "cases"), 5, {})
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random("5:0"), knobs)
    for o in drive_compounds(s, n):
        writer.save(0, o.kind, o.pdu, o.desc, req=o.req, mutated=o.mutated)
    writer.save(0, "UNKNOWN_REQ", b"junk", "x", ext="unknown", req=n + 1)
    return writer


def ntlm_authenticate(user):
    name = user.encode("utf-16-le")
    hdr = bytearray(b"NTLMSSP\x00" + struct.pack("<I", 3) + b"\x00" * 52)
    struct.pack_into("<HHI", hdr, 36, len(name), len(name), len(hdr))
    return b"\xa1\x82" + bytes(hdr) + name


def create_req_body(name):
    raw = name.encode("utf-16-le")
    body = bytearray(struct.pack("<H", 57) + b"\x00" * 54)
    struct.pack_into("<HH", body, 44, smb2.HDR + len(body) if raw else 0, len(raw))
    return bytes(body) + raw


def lease_ctx(key, parent=b"", extra=b""):
    data = key + struct.pack("<IIQ", 7, 0, 0) + parent + extra
    name = b"RqLs"
    ctx = struct.pack("<IHHHHI", 0, 16, 4, 0, 24, len(data)) + name + b"\x00" * 4 + data
    return ctx


def with_ctx(body_prefix, fields, ctx):
    body = bytearray(body_prefix)
    struct.pack_into("<II", body, fields, smb2.HDR + len(body), len(ctx))
    return bytes(body) + ctx


def create_with_lease(key):
    return with_ctx(create_req_body("")[:56], smb2.CTX_FIELDS_REQUEST, lease_ctx(key))


def mount_positions(session, mounts=30, per_mount=30):
    """Request positions (1-based, after TREE_CONNECT) that got body mutations."""
    hits = collections.Counter()
    mid = 10_000
    for _ in range(mounts):
        session.respond(smb2.join_chain([req(smb2.TREE_CONNECT, mid, tree=0)]))
        mid += 1
        for pos in range(1, per_mount + 1):
            (out, *_rest) = session.respond(smb2.join_chain([req(smb2.CREATE, mid, create_req_body("f"))]))
            mid += 1
            if out.mutated:
                hits[pos] += 1
    return hits
