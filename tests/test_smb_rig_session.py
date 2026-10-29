"""Tests for tools/smb-rig: FuzzSession: replies, budget placement, realism and mutation families."""

from __future__ import annotations

import random
import struct

import pytest
from smb_rig_support import (
    CLEAN,
    SESS,
    SMB1_NEG,
    TREE,
    FuzzSession,
    K,
    Knobs,
    budget_mod,
    corpus,
    create_with_lease,
    drive_compounds,
    make_seeds,
    mount_positions,
    qi_body,
    replies,
    req,
    smb2,
)


@pytest.fixture()
def seeds(tmp_path):
    """Seed corpus directory shared by this file's tests."""
    return make_seeds(tmp_path)


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
    knobs = K(budget=1, p_mutate=0, p_pending=1.0, p_double_final=1.0, p_next=0, p_oplock=0)
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


@pytest.mark.parametrize("budget", [0, 1, 2, 5])
def test_budget_caps_mutation_events_per_connection(seeds, budget):
    c = corpus.load_corpus(str(seeds))
    knobs = K(budget=budget, p_mutate=1.0, p_pending=0.5, p_next=0.5, p_oplock=0.5)
    s = FuzzSession(c, random.Random(9), knobs)
    outs = drive_compounds(s)
    assert s.budget.left == 0
    mutated_reqs = {o.req for o in outs if o.mutated}
    assert 0 < len(mutated_reqs) <= budget if budget else not mutated_reqs
    assert sum(1 for o in outs if not o.mutated) > 0          # session continues clean afterwards


def test_budget_refills_per_mount_on_a_reused_session(seeds):
    c = corpus.load_corpus(str(seeds))
    s = FuzzSession(c, random.Random(4), K(budget=1, p_mutate=1.0, p_pending=0, p_next=0,
                                               p_oplock=0, p_credit=0))
    mutated_per_mount = []
    for mount in range(3):
        s.respond(smb2.join_chain([req(smb2.TREE_CONNECT, 1000 + mount, tree=0)]))
        outs = drive_compounds(s, 5)
        mutated_per_mount.append(sum(o.mutated for o in outs))
    assert mutated_per_mount == [1, 1, 1]


@pytest.mark.parametrize("cmd", [smb2.LOGOFF, smb2.TREE_DISCONNECT, smb2.FLUSH, smb2.ECHO])
def test_trivial_body_replies_never_get_body_mutations(seeds, cmd):
    knobs = K(budget=50, p_mutate=1.0, p_pending=0, p_next=0, p_oplock=0, p_credit=0)
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(1), knobs)
    for i in range(20):
        (out,) = s.respond(smb2.join_chain([req(cmd, 300 + i)]))
        assert not out.mutated
    assert s.budget.left == 50


def test_clean_knobs_never_mutate_and_stamp_request_ordinals(seeds):
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(1), Knobs.clean())
    outs = drive_compounds(s, 10)
    assert not any(o.mutated for o in outs)
    assert [o.req for o in outs] == list(range(1, 11))
    assert all("clean" in o.desc for o in outs)


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
    abuse = FuzzSession(c, random.Random(2), K(budget=1, p_mutate=0, p_credit=1.0,
                                                   p_pending=0, p_next=0, p_oplock=0))
    outs = drive_compounds(abuse, 5)
    abused = [o for o in outs if "credits=" in o.desc]
    assert len(abused) == 1 and abused[0].mutated


def test_each_create_gets_a_fresh_file_id_and_lease_keys_are_tracked(seeds):
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(1), Knobs.clean())
    fids = []
    for i, key in enumerate([b"A" * 16, b"B" * 16, b"A" * 16]):
        (out,) = s.respond(smb2.join_chain([req(smb2.CREATE, 500 + i, create_with_lease(key))]))
        fids.append(smb2.split_chain(out.pdu)[0].body[64:80])
    assert len(set(fids)) == 3 and s.file_ids == fids
    assert s.lease_keys == [b"A" * 16, b"B" * 16]


def test_break_ack_request_gets_wellformed_reply(seeds):
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(1), Knobs.clean())
    lease_ack = struct.pack("<HHI", 36, 0, 0) + b"K" * 16 + struct.pack("<IQ", 1, 0)
    (out,) = s.respond(smb2.join_chain([req(smb2.OPLOCK_BREAK, 77, lease_ack)]))
    el = smb2.split_chain(out.pdu)[0]
    assert el.header.status == smb2.STATUS_SUCCESS and el.body == lease_ack and "break-ack" in out.desc


def test_unsolicited_break_targets_live_lease(seeds):
    knobs = K(budget=5, p_mutate=0, p_pending=0, p_next=0, p_credit=0, p_oplock=1.0, p_lease=1.0)
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(2), knobs)
    outs = s.respond(smb2.join_chain([req(smb2.CREATE, 600, create_with_lease(b"L" * 16))]))
    brk = [o for o in outs if o.kind == "OPLOCK_BREAK"]
    assert brk and smb2.split_chain(brk[0].pdu)[0].body[8:24] == b"L" * 16


def test_spread_places_budget_across_the_mount_and_protects_warmup(seeds):
    c = corpus.load_corpus(str(seeds))
    flat = mount_positions(FuzzSession(c, random.Random(7), Knobs(
        spread=False, warmup=0, p_mutate=0.25, p_pending=0, p_next=0, p_oplock=0, p_credit=0)))
    spread = mount_positions(FuzzSession(c, random.Random(7), Knobs(
        p_pending=0, p_next=0, p_oplock=0, p_credit=0)))
    def early(h):
        return sum(h[p] for p in (1, 2, 3, 4)) / max(1, sum(h.values()))

    def late(h):
        return sum(n for p, n in h.items() if p > 10)

    assert early(spread) < 0.5 * early(flat)                    # budget no longer front-loaded
    assert late(spread) > 2 * late(flat)                        # reaches deep in the mount
    assert spread[1] + spread[2] <= 0.15 * sum(spread.values())     # warm-up protected


# ---------------- Knobs validation and Budget in isolation ----------------

@pytest.mark.parametrize("kwargs", [{"p_mutate": 1.5}, {"p_warmup": -0.1}, {"budget": -1},
                                    {"warmup": -2}, {"horizon": 0}])
def test_knobs_reject_invalid_values(kwargs):
    with pytest.raises(ValueError):
        Knobs(**kwargs)


def make_budget(**overrides):
    cfg = {"budget": 2, "p_mutate": 0.25, "spread": True, "horizon": 10.0, "warmup": 2, "p_warmup": 0.0}
    cfg.update(overrides)
    return budget_mod.Budget(budget_mod.BudgetConfig(**cfg), random.Random(1))


def test_budget_never_spends_in_warmup_when_p_warmup_is_zero():
    b = make_budget()
    b.new_mount()
    for _ in range(2):
        b.on_request()
        assert not b.spend(1.0)
    b.on_request()
    assert b.spend(1.0) and b.left == 1


def test_budget_refills_and_learns_mount_length():
    b = make_budget(horizon=10.0)
    b.new_mount()
    for _ in range(21):
        b.on_request()
    b.new_mount()                                  # previous mount: 20 requests after its TC
    assert b.left == 2 and b.mount_pos == 0
    assert b.mount_len == pytest.approx(0.7 * 10 + 0.3 * 20)


def test_budget_body_p_flat_vs_spread():
    assert make_budget(spread=False).body_p() == 0.25
    b = make_budget(horizon=10.0)
    b.new_mount()
    b.on_request()
    assert b.body_p() == pytest.approx(2 / 10)
    for _ in range(20):
        b.on_request()                             # past the expected end: spend what is left
    assert b.body_p() == 1.0
    b.left = 0
    assert b.body_p() == 0.0 and not b.spend(1.0)
