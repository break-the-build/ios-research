"""Tests for tools/smb-rig: Seed corpus loading, request pairing, chain matching and identity (corpus.py)."""

from __future__ import annotations

import random
import struct

import pytest
from smb_rig_support import (
    SMB1_NEG,
    FuzzSession,
    Knobs,
    corpus,
    create_req_body,
    create_rsp_body,
    make_seeds,
    ntlm_authenticate,
    qi_body,
    req,
    rsp,
    smb2,
    write_run,
)


@pytest.fixture()
def seeds(tmp_path):
    """Seed corpus directory shared by this file's tests."""
    return make_seeds(tmp_path)


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
        body = smb2.split_chain(out.pdu)[0].body
        want = create_rsp_body() + b"#"
        assert body[:64] == want[:64] and body[80:] == want[80:]     # FileId (64..80) is fresh


def test_unknown_subkey_falls_back_to_any_template_of_that_command(tmp_path):
    j = smb2.join_chain
    frames = [(0, j([req(smb2.QUERY_INFO, 3, qi_body(1, 0x12))])),
              (1, j([rsp(smb2.QUERY_INFO, 3, b"Q1")])),
              (0, j([req(smb2.QUERY_INFO, 4, qi_body(2, 0x05))])),
              (1, j([rsp(smb2.QUERY_INFO, 4, b"Q2")]))]
    write_run(tmp_path / "seeds", "run-q", frames)
    c = corpus.load_corpus(str(tmp_path / "seeds"))
    assert c.latest(smb2.QUERY_INFO, 0x112).body == b"Q1"
    fallback = {c.pick(smb2.QUERY_INFO, 0x999, random.Random(s)).body for s in range(20)}
    assert fallback == {b"Q1", b"Q2"}
    assert c.pick(smb2.READ, None, random.Random(0)) is None
