"""Per-connection response engine for smb-rig fuzz mode (no sockets here).

FuzzSession.respond(payload) turns one client PDU into the list of PDUs the
rig should send back, plus a description of every mutation applied. It
answers every element of a compound request, echoes the client's MessageId /
SessionId / TreeId per element, keeps recorded statuses on the handshake (so
NTLM's MORE_PROCESSING leg survives), and never answers CANCEL.

When to mutate is decided by budget.Budget (per-mount, spread, warm-up
protected); what to mutate lives here and in mutators.py.
"""
from __future__ import annotations

import random
import struct
from dataclasses import dataclass, replace
from typing import Protocol

import mutators
import smb2
from budget import Budget, BudgetConfig
from corpus import Corpus, Key, chain_signature
from favored import FavoredStore

HANDSHAKE = (smb2.NEGOTIATE, smb2.SESSION_SETUP)
# session glue: mutated only with --mutate-handshake (a bad reply here ends
# the mount before any file-op parser runs, wasting the budget)
GLUE = smb2.SESSION_GLUE
# replies whose body is a fixed 4-byte StructureSize+Reserved: nothing for a
# client parser to index, so a mutation spent here is wasted budget
TRIVIAL_BODY = (smb2.LOGOFF, smb2.TREE_DISCONNECT, smb2.FLUSH, smb2.ECHO)
NO_MUTATE = GLUE + TRIVIAL_BODY
MAX_CREDIT_GRANT = 512
CREDIT_ABUSE = (0, 0x7FFF, 0x8000, 0xFFFF)   # starvation / client credit-counter overflow
FILE_ID_BASE = 0x5A00_0000_0000


@dataclass(frozen=True)
class Knobs:
    """Mutation budget and per-opportunity probabilities."""
    mutate_handshake: bool = False
    budget: int = 2              # mutation events per mount (0 = clean replay)
    p_mutate: float = 0.25       # flat body-mutation chance (only when spread=False)
    p_status: float = 0.15       # a body mutation becomes an error/warning reply carrying data
    p_pending: float = 0.05      # STATUS_PENDING interim + async final
    p_double_final: float = 0.30  # ...and a second async final (double completion)
    p_next: float = 0.10         # corrupt NextCommand in a compound reply
    p_oplock: float = 0.05       # unsolicited oplock/lease break after a reply
    p_credit: float = 0.03       # absurd CreditResponse on one reply
    p_favored: float = 0.5       # mutate a favored (log-novel) reply instead of the template
    p_lease: float = 0.7         # an unsolicited break targets a live lease, not an oplock
    spread: bool = True          # see budget.py
    horizon: float = 30.0        # initial guess of requests per mount
    warmup: int = 2              # requests after TREE_CONNECT that are protected...
    p_warmup: float = 0.1        # ...except with this probability

    def __post_init__(self) -> None:
        bad = [name for name, value in vars(self).items()
               if name.startswith("p_") and not 0.0 <= value <= 1.0]
        if bad:
            raise ValueError(f"probabilities must be in [0, 1]: {', '.join(bad)}")
        if self.budget < 0 or self.warmup < 0 or self.horizon <= 0:
            raise ValueError("budget and warmup must be >= 0 and horizon > 0")

    @classmethod
    def clean(cls) -> Knobs:
        return cls(budget=0)

    def budget_config(self) -> BudgetConfig:
        return BudgetConfig(self.budget, self.p_mutate, self.spread, self.horizon,
                            self.warmup, self.p_warmup)


@dataclass(frozen=True)
class ElementReply:
    element: smb2.Element
    desc: str
    sess: int
    tree: int
    mutated: bool                # any mutation (body, status or credits)
    body_mutated: bool           # body/status mutation: promotable by feedback
    key: Key


@dataclass(frozen=True)
class Outgoing:
    kind: str                    # cmd chain, e.g. "CREATE+QUERY_INFO+CLOSE"
    pdu: bytes
    desc: str
    req: int = 0                 # ordinal of the client request this answers
    mutated: bool = False
    # (cmd, subkey) + reply element for each body-mutated element: what the
    # feedback loop promotes when the kernel logs something new
    mutated_elements: tuple[tuple[Key, smb2.Element], ...] = ()


class Responder(Protocol):
    """What serve_connection needs from a session (FuzzSession, ReplaySession)."""

    @property
    def saw_echo(self) -> bool: ...

    def respond(self, payload: bytes) -> list[Outgoing]: ...


class FuzzSession:
    def __init__(self, corpus: Corpus, rng: random.Random, knobs: Knobs,
                 favored: FavoredStore | None = None) -> None:
        self.corpus = corpus
        self.rng = rng
        self.knobs = knobs
        self.favored = favored
        self.budget = Budget(knobs.budget_config(), rng)
        self.req_no = 0
        self.ss_leg = 0
        self.session_id = 0
        self.tree_id = 0
        self.opens = 0
        self.file_ids: list[bytes] = []
        self.lease_keys: list[bytes] = []
        self.saw_echo = False

    def respond(self, payload: bytes) -> list[Outgoing]:
        self.req_no += 1
        self.budget.on_request()
        if payload[:4] == smb2.SMB1_SIG:
            return self._respond_smb1(payload)
        chain = smb2.split_chain(payload)
        if not chain:
            return []
        replies: list[smb2.Element] = []
        descs: list[str] = []
        promotable: list[tuple[Key, smb2.Element]] = []
        mutated = False
        sess, tree = self.session_id, self.tree_id
        # prefer the whole reply chain recorded for this exact request chain
        matched = self.corpus.chain_pick(chain_signature(chain), self.rng)
        for i, req in enumerate(chain):
            sess, tree = self._ids_for(req.header, sess, tree)
            if req.header.command == smb2.CANCEL:
                continue                              # CANCEL never gets a reply
            r = self._reply_element(req, sess, tree, matched[i] if matched else None)
            sess, tree = r.sess, r.tree
            descs.append(f"{smb2.cmd_name(r.element.header.command)}:{r.desc}")
            replies.append(r.element)
            mutated |= r.mutated
            if r.body_mutated:
                promotable.append((r.key, r.element))
        if not replies:
            return []
        if len(replies) == 1 and self._can_pend(replies[0]):
            out = self._pending(replies[0], descs[0])
        else:
            out = [self._compound(replies, descs, mutated)]
        out[-1] = replace(out[-1], mutated_elements=tuple(promotable))
        brk = self._unsolicited_break()
        return out + ([brk] if brk else [])

    # -- reply construction ---------------------------------------------

    def _respond_smb1(self, payload: bytes) -> list[Outgoing]:
        if smb2.is_smb1_negotiate(payload) and self.corpus.mp_negotiate:
            return [Outgoing("SMB1_NEGOTIATE", self.corpus.mp_negotiate, "mp-negotiate(clean)", self.req_no)]
        return []

    @staticmethod
    def _ids_for(h: smb2.Header, sess: int, tree: int) -> tuple[int, int]:
        """Related compound elements carry 0xFF.. placeholders; inherit ids."""
        if not (h.is_related and h.session_id == smb2.RELATED_ID64):
            sess = h.session_id or sess
        if not (h.is_related and h.tree_id == smb2.RELATED_ID32):
            tree = h.tree_id or tree
        return sess, tree

    def _subkey(self, req: smb2.Element) -> int | None:
        if req.header.command == smb2.SESSION_SETUP:
            leg, self.ss_leg = self.ss_leg, self.ss_leg + 1
            return leg
        return smb2.request_subkey(req.header.command, req.body)

    def _template(self, cmd: int, subkey: int | None, override: smb2.Element | None
                  ) -> smb2.Element | None:
        if override is not None:
            return override
        if cmd in HANDSHAKE:
            return self.corpus.latest(cmd, subkey)
        return self.corpus.pick(cmd, subkey, self.rng)

    def _realistic_body(self, req: smb2.Element, tmpl: smb2.Element) -> bytes:
        """Template body adjusted to this request: lease key, fresh FileId, echoes."""
        cmd, body = req.header.command, tmpl.body
        if cmd == smb2.CREATE:
            body = smb2.echo_lease_key(req.body, body)
            if tmpl.header.status == smb2.STATUS_SUCCESS:
                self.opens += 1
                fid = struct.pack("<QQ", FILE_ID_BASE + self.opens, FILE_ID_BASE ^ self.opens)
                body = smb2.with_create_file_id(body, fid)
            key = smb2.lease_key_of(req.body)
            if key and key not in self.lease_keys:
                self.lease_keys.append(key)
        elif cmd == smb2.IOCTL:
            body = smb2.echo_ioctl_file_id(req.body, body)
        return body

    def _base_reply(self, req: smb2.Element, tmpl: smb2.Element | None) -> tuple[int, bytes, str]:
        """(status, body, desc) before any mutation."""
        if tmpl is not None:
            return tmpl.header.status, self._realistic_body(req, tmpl), "clean"
        if req.header.command == smb2.OPLOCK_BREAK:
            ack = smb2.break_ack_response(req.body)
            if ack is not None:
                return smb2.STATUS_SUCCESS, ack, "break-ack"
        return smb2.STATUS_NOT_SUPPORTED, smb2.ERROR_BODY, "no-template"

    def _reply_element(self, req: smb2.Element, sess: int, tree: int,
                       override: smb2.Element | None = None) -> ElementReply:
        cmd = req.header.command
        if cmd == smb2.TREE_CONNECT:
            self.budget.new_mount()
        subkey = self._subkey(req)
        tmpl = self._template(cmd, subkey, override)
        status, body, desc = self._base_reply(req, tmpl)
        if tmpl is not None and cmd == smb2.SESSION_SETUP and sess == 0:
            sess = tmpl.header.session_id
        if tmpl is not None and cmd == smb2.TREE_CONNECT:
            tree = tmpl.header.tree_id
        body_mutated = (tmpl is not None and self._body_mutable(cmd)
                        and self.budget.spend(self.budget.body_p()))
        if body_mutated:
            status, body, desc = self._mutate(cmd, subkey, status, body)
        self._observe(cmd, status, body)
        # grant what the client asked for (as Samba does), bounded; recorded
        # templates carry Samba's grants for a different credit history
        credits = min(max(req.header.credits, 1), MAX_CREDIT_GRANT)
        credit_mutated = cmd not in GLUE and self.budget.spend(self.knobs.p_credit)
        if credit_mutated:
            credits = self.rng.choice(CREDIT_ABUSE)
            desc = f"{desc},credits={credits:#x}"
        self.session_id, self.tree_id = sess, tree
        hdr = smb2.Header(status=status, command=cmd,
                          flags=smb2.FLAG_RESPONSE | (req.header.flags & smb2.FLAG_RELATED),
                          message_id=req.header.message_id, tree_id=tree, session_id=sess,
                          credit_charge=req.header.credit_charge, credits=credits)
        return ElementReply(smb2.Element(hdr, body), desc, sess, tree,
                            body_mutated or credit_mutated, body_mutated, (cmd, subkey))

    def _body_mutable(self, cmd: int) -> bool:
        return cmd not in NO_MUTATE or (self.knobs.mutate_handshake and cmd in GLUE)

    def _observe(self, cmd: int, status: int, body: bytes) -> None:
        """Track session state that later replies and breaks depend on."""
        end = smb2.CREATE_RSP_FILE_ID + smb2.FILE_ID_LEN
        if cmd == smb2.CREATE and status == smb2.STATUS_SUCCESS and len(body) >= end:
            self.file_ids.append(body[smb2.CREATE_RSP_FILE_ID:end])
        if cmd == smb2.ECHO:
            self.saw_echo = True

    # -- mutation families ----------------------------------------------

    def _mutate(self, cmd: int, subkey: int | None, status: int, body: bytes
                ) -> tuple[int, bytes, str]:
        prefix = ""
        if self.favored is not None and self.rng.random() < self.knobs.p_favored:
            fav = self.favored.pick((cmd, subkey), self.rng)
            if fav is not None:                       # stack on a reply that reached new code
                status, body, prefix = fav.header.status, fav.body, "fav+"
        if status == smb2.STATUS_SUCCESS and self.rng.random() < self.knobs.p_status:
            st, b, d = mutators.inject_status(cmd, subkey, body, self.rng)
            return st, b, prefix + d
        mbody, desc = mutators.mutate_body(cmd, subkey, body, self.rng)
        return status, mbody, prefix + desc

    def _unsolicited_break(self) -> Outgoing | None:
        if not (self.file_ids or self.lease_keys) or not self.budget.spend(self.knobs.p_oplock):
            return None
        if self.lease_keys and (not self.file_ids or self.rng.random() < self.knobs.p_lease):
            el, d = mutators.lease_break(self.rng.choice(self.lease_keys), self.rng)
        else:
            el, d = mutators.oplock_break(self.rng.choice(self.file_ids), self.rng)
        return Outgoing("OPLOCK_BREAK", smb2.join_chain([el]), d, self.req_no, True)

    def _can_pend(self, el: smb2.Element) -> bool:
        return el.header.command not in GLUE and self.budget.spend(self.knobs.p_pending)

    def _pending(self, el: smb2.Element, desc: str) -> list[Outgoing]:
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
        if len(replies) > 1 and self.budget.spend(self.knobs.p_next):
            overrides, d = mutators.next_command_override(len(replies), self.rng)
            descs = descs + [d]
            mutated = True
        return Outgoing(kind, smb2.join_chain(replies, overrides), " | ".join(descs), self.req_no, mutated)
