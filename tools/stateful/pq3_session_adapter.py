"""Stateful campaign adapter for pq3:handshake / pq3:rekey (#228 §5).

Models a PQ3-style post-quantum session as an ordered workflow so the
`stateful` engine explores history-dependent defect paths that single-shot
corpus fuzzing cannot reach:

    handshake -> [advance_epoch | rekey | send_* ]* -> teardown

Defects are *ordering* defects by construction:
  - rekey/replay before a completed handshake  -> session-state error
  - replaying a freed (stale) epoch transcript -> use-after-free family
  - message types 0x00/0xC0/0xFF epochs        -> memory-safety families

Executes against the framework's own CI-safe mock targets (in-process,
no radio). StepOutcome.status maps from the target's ExecResult outcome.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ios_research.stateful import ActionSpec, StepOutcome, WorkflowAdapter
from ios_research.targets.pq3 import HandshakeTarget, RekeyTarget

_HS = HandshakeTarget()
_RK = RekeyTarget()


def _transcript(magic: bytes, *, declared_extra: int = 0, epoch: int = 0,
                msg_type: int = 0x01, payload: bytes = b"body") -> bytes:
    body = (len(payload) + declared_extra).to_bytes(2, "big") \
        + epoch.to_bytes(2, "big") + bytes([msg_type & 0xFF]) + payload
    return magic + body


class Pq3Session(WorkflowAdapter):
    name = "pq3-session"
    version = "1.0.0"
    actions = (
        ActionSpec("handshake", (), "establish the initial PQ3 handshake"),
        ActionSpec("advance_epoch", (), "ratchet to the next epoch"),
        ActionSpec("rekey", (), "rekey: free the current epoch and ratchet"),
        ActionSpec("send_hs_message", (("msg_type", "int"),),
                   "send a handshake-stage message at the current epoch"),
        ActionSpec("replay_stale", (("poison", "bool"),),
                   "replay the most recently freed epoch's transcript"),
        ActionSpec("teardown", (), "drop session state"),
    )

    def __init__(self):
        self.reset()

    def reset(self):
        self.handshake_done = False
        self.epoch = -1
        self.freed_epochs: list[int] = []

    # -- actions ------------------------------------------------------------
    def perform(self, action_id: str, params: dict) -> StepOutcome:
        if action_id == "handshake":
            self.reset()
            res = _HS.execute(_transcript(_HS.magic, epoch=0))
            if res.outcome == "accepted":
                self.handshake_done = True
                self.epoch = 0
            return StepOutcome(action_id, {}, "ok" if self.handshake_done
                               else "error", {"epoch": self.epoch})

        if action_id == "advance_epoch":
            if not self.handshake_done:
                return StepOutcome(action_id, {}, "error",
                                   {"reason": "no-session"})
            if self.epoch >= 0:
                self.freed_epochs.append(self.epoch)
            self.epoch += 1
            res = _RK.execute(_transcript(_RK.magic, epoch=self.epoch))
            return self._finish(res, action_id, params)

        if action_id == "rekey":
            if not self.handshake_done:
                # Real stacks reject rekey without a session; model it.
                return StepOutcome(action_id, dict(params), "error",
                                   {"reason": "not-handshaked"})
            if self.epoch >= 0:
                self.freed_epochs.append(self.epoch)
            self.epoch += 1
            data = _transcript(_RK.magic, epoch=self.epoch)
            return self._finish(_RK.execute(data), action_id, params)

        if action_id == "send_hs_message":
            mt = int(params.get("msg_type", 1)) & 0xFF
            if not self.handshake_done:
                return StepOutcome(action_id, dict(params), "invalid",
                                   {"reason": "not-handshaked"})
            return self._finish(
                _HS.execute(_transcript(_HS.magic, epoch=self.epoch,
                                        msg_type=mt)),
                action_id, params)

        if action_id == "replay_stale":
            poison = bool(params.get("poison"))
            if not self.freed_epochs:
                return StepOutcome(action_id, dict(params), "invalid",
                                   {"reason": "nothing-stale"})
            stale = self.freed_epochs.pop()
            payload = b"\xde\xad" if poison else b"ok"
            # Replaying a freed epoch state is the UAF signature.
            res = _RK.execute(_transcript(_RK.magic, epoch=stale,
                                          payload=payload))
            out = self._finish(res, action_id, params)
            if res.outcome == "accepted":
                out.observation["note"] = f"stale epoch {stale} accepted"
            return out

        if action_id == "teardown":
            self.reset()
            return StepOutcome(action_id, {}, "ok")

        return StepOutcome(action_id, dict(params), "invalid")

    def _finish(self, res, action_id, params) -> StepOutcome:
        status = {"accepted": "ok", "rejected": "invalid", "crash": "error",
                  "timeout": "timeout"}.get(res.outcome, "error")
        obs = {"detail": res.detail[:120], "epoch": self.epoch}
        if status != "ok":
            obs["reason"] = res.detail[:80]
        return StepOutcome(action_id, dict(params), status, obs)

ADAPTER = Pq3Session()
