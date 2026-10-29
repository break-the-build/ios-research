"""Per-connection response engine for smb-rig fuzz mode (no sockets here).

FuzzSession.respond(payload) turns one client PDU into the list of PDUs the
rig should send back, plus a description of every mutation applied. It
answers every element of a compound request, echoes the client's MessageId /
SessionId / TreeId per element, keeps recorded statuses on the handshake (so
NTLM's MORE_PROCESSING leg survives), and never answers CANCEL.

Mutation is budgeted (Knobs.budget events, refilled at every TREE_CONNECT,
i.e. per mount — smbfs reuses one TCP session across mounts). A client
usually abandons a session after its first malformed reply, so mutating every
reply mostly fuzzes early-abort paths; spending 1-2 events per mount keeps
sessions deep and makes any crash attributable to a single reply.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, replace

import mutators
import smb2
from corpus import Corpus, chain_signature

HANDSHAKE = (smb2.NEGOTIATE, smb2.SESSION_SETUP)
# session glue: mutated only with --mutate-handshake (a bad reply here ends
# the mount before any file-op parser runs, wasting the budget)
GLUE = smb2.SESSION_GLUE
MAX_CREDIT_GRANT = 512
CREDIT_ABUSE = (0, 0x7FFF, 0x8000, 0xFFFF)   # starvation / client credit-counter overflow


@dataclass(frozen=True)
class Knobs:
    """Mutation budget and per-opportunity probabilities."""
    mutate_handshake: bool = False
    budget: int = 2              # mutation events per mount (0 = clean replay)
    p_mutate: float = 0.25       # an eligible reply element spends one event
    p_status: float = 0.15       # ...as an error/warning reply carrying data
    p_pending: float = 0.05      # STATUS_PENDING interim + async final
    p_double_final: float = 0.30  # ...and a second async final (double completion)
    p_next: float = 0.10         # corrupt NextCommand in a compound reply
    p_oplock: float = 0.05       # unsolicited oplock break after a reply
    p_credit: float = 0.03       # absurd CreditResponse on one reply

    @classmethod
    def clean(cls) -> Knobs:
        return cls(budget=0)


@dataclass(frozen=True)
class Outgoing:
    kind: str                    # cmd chain, e.g. "CREATE+QUERY_INFO+CLOSE"
    pdu: bytes
    desc: str
    req: int = 0                 # ordinal of the client request this answers
    mutated: bool = False


class FuzzSession:
    def __init__(self, corpus: Corpus, rng: random.Random, knobs: Knobs) -> None:
        self.corpus = corpus
        self.rng = rng
        self.knobs = knobs
        self.budget = knobs.budget
        self.req_no = 0
        self.ss_leg = 0
        self.session_id = 0
        self.tree_id = 0
        self.file_ids: list[bytes] = []
        self.saw_echo = False

    def respond(self, payload: bytes) -> list[Outgoing]:
        self.req_no += 1
        if payload[:4] == smb2.SMB1_SIG:
            return self._respond_smb1(payload)
        chain = smb2.split_chain(payload)
        if not chain:
            return []
        replies: list[smb2.Element] = []
        descs: list[str] = []
        mutated = False
        sess, tree = self.session_id, self.tree_id
        # prefer the whole reply chain recorded for this exact request chain
        matched = self.corpus.chain_pick(chain_signature(chain), self.rng)
        for i, req in enumerate(chain):
            sess, tree = self._ids_for(req.header, sess, tree)
            if req.header.command == smb2.CANCEL:
                continue                              # CANCEL never gets a reply
            override = matched[i] if matched else None
            el, desc, sess, tree, mut = self._reply_element(req, sess, tree, override)
            descs.append(f"{smb2.cmd_name(el.header.command)}:{desc}")
            replies.append(el)
            mutated |= mut
        if not replies:
            return []
        if len(replies) == 1 and self._can_pend(replies[0]):
            out = self._pending(replies[0], descs[0], mutated)
        else:
            out = [self._compound(replies, descs, mutated)]
        if self.file_ids and self._spend(self.knobs.p_oplock):
            brk, d = mutators.oplock_break(self.rng.choice(self.file_ids), self.rng)
            out.append(Outgoing("OPLOCK_BREAK", smb2.join_chain([brk]), d, self.req_no, True))
        return out

    # -- helpers -----------------------------------------------------------

    def _spend(self, p: float) -> bool:
        """Consume one mutation event with probability p, if budget remains."""
        if self.budget <= 0 or self.rng.random() >= p:
            return False
        self.budget -= 1
        return True

    def _respond_smb1(self, payload: bytes) -> list[Outgoing]:
        if smb2.is_smb1_negotiate(payload) and self.corpus.mp_negotiate:
            return [Outgoing("SMB1_NEGOTIATE", self.corpus.mp_negotiate, "mp-negotiate(clean)", self.req_no)]
        return []

    def _ids_for(self, h: smb2.Header, sess: int, tree: int) -> tuple[int, int]:
        """Related compound elements carry 0xFF.. placeholders; inherit ids."""
        if not (h.is_related and h.session_id == smb2.RELATED_ID64):
            sess = h.session_id or sess
        if not (h.is_related and h.tree_id == smb2.RELATED_ID32):
            tree = h.tree_id or tree
        return sess, tree

    def _reply_element(self, req: smb2.Element, sess: int, tree: int,
                       override: smb2.Element | None = None
                       ) -> tuple[smb2.Element, str, int, int, bool]:
        cmd = req.header.command
        handshake = cmd in HANDSHAKE
        if cmd == smb2.TREE_CONNECT:
            # smbfs multiplexes successive mounts over one long-lived session,
            # so the budget is per mount (tree connect), not per TCP connection
            self.budget = self.knobs.budget
        if cmd == smb2.SESSION_SETUP:
            subkey, self.ss_leg = self.ss_leg, self.ss_leg + 1
        else:
            subkey = smb2.request_subkey(cmd, req.body)
        if override is not None:
            tmpl = override
        elif handshake:
            tmpl = self.corpus.latest(cmd, subkey)
        else:
            tmpl = self.corpus.pick(cmd, subkey, self.rng)
        mutated = False
        # grant what the client asked for (as Samba does), bounded; recorded
        # templates carry Samba's grants for a different credit history
        credits = min(max(req.header.credits, 1), MAX_CREDIT_GRANT)
        if tmpl is None:
            status, body, desc = smb2.STATUS_NOT_SUPPORTED, smb2.ERROR_BODY, "no-template"
        else:
            status, body = tmpl.header.status, tmpl.body
            if cmd == smb2.CREATE:
                body = smb2.echo_lease_key(req.body, body)
            desc = "clean"
            if cmd == smb2.SESSION_SETUP and sess == 0:
                sess = tmpl.header.session_id
            if cmd == smb2.TREE_CONNECT:
                tree = tmpl.header.tree_id
            if (cmd not in GLUE or self.knobs.mutate_handshake) and self._spend(self.knobs.p_mutate):
                status, body, desc = self._mutate(cmd, subkey, status, body)
                mutated = True
        if cmd == smb2.CREATE and status == smb2.STATUS_SUCCESS and len(body) >= 80:
            self.file_ids.append(body[64:80])
        if cmd == smb2.ECHO:
            self.saw_echo = True
        if cmd not in GLUE and self._spend(self.knobs.p_credit):
            credits = self.rng.choice(CREDIT_ABUSE)
            desc = f"{desc},credits={credits:#x}"
            mutated = True
        self.session_id, self.tree_id = sess, tree
        hdr = smb2.Header(status=status, command=cmd,
                          flags=smb2.FLAG_RESPONSE | (req.header.flags & smb2.FLAG_RELATED),
                          message_id=req.header.message_id, tree_id=tree, session_id=sess,
                          credit_charge=req.header.credit_charge, credits=credits)
        return smb2.Element(hdr, body), desc, sess, tree, mutated

    def _mutate(self, cmd: int, subkey: int | None, status: int, body: bytes
                ) -> tuple[int, bytes, str]:
        if status == smb2.STATUS_SUCCESS and self.rng.random() < self.knobs.p_status:
            return mutators.inject_status(cmd, subkey, body, self.rng)
        mbody, desc = mutators.mutate_body(cmd, subkey, body, self.rng)
        return status, mbody, desc

    def _can_pend(self, el: smb2.Element) -> bool:
        return el.header.command not in GLUE and self._spend(self.knobs.p_pending)

    def _pending(self, el: smb2.Element, desc: str, mutated: bool) -> list[Outgoing]:
        async_id = self.rng.getrandbits(32) | 1
        interim_hdr = replace(el.header, status=smb2.STATUS_PENDING).with_async_id(async_id)
        final = smb2.Element(el.header.with_async_id(async_id), el.body)
        name = smb2.cmd_name(el.header.command)
        n = self.req_no
        out = [Outgoing(name, smb2.join_chain([smb2.Element(interim_hdr, smb2.ERROR_BODY)]),
                        f"pending-interim async={async_id:#x}", n, True),
               Outgoing(name, smb2.join_chain([final]), f"pending-final {desc}", n, True)]
        if self.rng.random() < self.knobs.p_double_final:
            out.append(Outgoing(name, smb2.join_chain([final]), "pending-final-dup", n, True))
        return out

    def _compound(self, replies: list[smb2.Element], descs: list[str], mutated: bool) -> Outgoing:
        kind = "+".join(smb2.cmd_name(r.header.command) for r in replies)
        overrides: dict[int, int] = {}
        if len(replies) > 1 and self._spend(self.knobs.p_next):
            overrides, d = mutators.next_command_override(len(replies), self.rng)
            descs = descs + [d]
            mutated = True
        return Outgoing(kind, smb2.join_chain(replies, overrides), " | ".join(descs), self.req_no, mutated)
