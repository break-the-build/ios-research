"""Stateful campaign adapter for wifiaware:publish/subscribe/datapath (#228 §5).

Models a Wi-Fi Aware discovery session lifecycle so the `stateful` engine
explores history-dependent defect paths:

    start_publish -> [subscribe | send_frame ]* -> reclaim | teardown

Defects are ordering defects by construction:
  - send/use after the frame buffer was reclaimed  -> use-after-free family
  - subscribe/datapath before publish              -> session-state error
  - tlv_count=0 / oversized / confused attributes  -> memory-safety families

Executes against the framework's own CI-safe mock targets (in-process, no
radio). StepOutcome.status maps from the target's ExecResult outcome.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ios_research.stateful import ActionSpec, StepOutcome, WorkflowAdapter
from ios_research.targets.wifiaware import (DatapathTarget, PublishTarget,
                                            SubscribeTarget)

_PUB = PublishTarget()
_SUB = SubscribeTarget()
_DP = DatapathTarget()

_RECLAIM_MARKER = b"\xde\xad"
_CONFUSION_ATTR = 0xC0


def _frame(magic: bytes, *, declared_extra: int = 0, attr_id: int = 0x01,
           tlv_count: int = 1, payload: bytes = b"data") -> bytes:
    body = (len(payload) + declared_extra).to_bytes(2, "big") \
        + bytes([attr_id & 0xFF, tlv_count & 0xFF]) + payload
    return magic + body


class WifiAwareSession(WorkflowAdapter):
    name = "wifiaware-session"
    version = "1.0.0"
    actions = (
        ActionSpec("start_publish", (("service", "str"),),
                   "publish a service; opens the discovery session"),
        ActionSpec("subscribe", (), "subscribe; requires an active publish"),
        ActionSpec("open_datapath", (), "request the data path; requires "
                                        "publish+subscribe"),
        ActionSpec("send_frame", (("stage", "int"),),
                   "send a discovery frame at the current stage"),
        ActionSpec("reclaim", (), "reclaim the frame buffer while the "
                                  "session stays logically alive"),
        ActionSpec("teardown", (), "tear the session down"),
    )

    def __init__(self):
        self.reset()

    def reset(self):
        self.publishing = False
        self.subscribed = False
        self.datapath_open = False
        self.reclaimed = False
        self.stage = 0

    def perform(self, action_id: str, params: dict) -> StepOutcome:
        if action_id == "start_publish":
            self.reset()
            res = _PUB.execute(_frame(_PUB.magic))
            if res.outcome == "accepted":
                self.publishing = True
                self.stage += 1
            return StepOutcome(action_id, dict(params),
                               "ok" if self.publishing else "error",
                               {"stage": self.stage})

        if action_id == "subscribe":
            if not self.publishing:
                return StepOutcome(action_id, {}, "error",
                                   {"reason": "not-publishing"})
            res = _SUB.execute(_frame(_SUB.magic))
            out = self._finish(res, action_id, params)
            if out.status == "ok":
                self.subscribed = True
                self.stage += 1
            return out

        if action_id == "open_datapath":
            if not (self.publishing and self.subscribed):
                return StepOutcome(action_id, {}, "error",
                                   {"reason": "no-discovery"})
            res = _DP.execute(_frame(_DP.magic))
            out = self._finish(res, action_id, params)
            if out.status == "ok":
                self.datapath_open = True
            return out

        if action_id == "send_frame":
            stage = int(params.get("stage", 0)) & 0xFF
            if not self.publishing:
                return StepOutcome(action_id, dict(params), "invalid",
                                   {"reason": "not-publishing"})
            # After reclaim the parser touches a dead buffer: UAF family.
            payload = _RECLAIM_MARKER if self.reclaimed else b"data"
            target = (_SUB if self.subscribed else _PUB)
            res = target.execute(_frame(target.magic, attr_id=stage,
                                        payload=payload))
            return self._finish(res, action_id, params)

        if action_id == "reclaim":
            if not self.publishing:
                return StepOutcome(action_id, {}, "invalid",
                                   {"reason": "not-publishing"})
            self.reclaimed = True
            return StepOutcome(action_id, {}, "ok",
                               {"reclaimed": True})

        if action_id == "teardown":
            self.reset()
            return StepOutcome(action_id, {}, "ok")

        return StepOutcome(action_id, dict(params), "invalid")

    def _finish(self, res, action_id, params) -> StepOutcome:
        status = {"accepted": "ok", "rejected": "invalid", "crash": "error",
                  "timeout": "timeout"}.get(res.outcome, "error")
        obs = {"detail": res.detail[:120], "stage": self.stage}
        if status != "ok":
            obs["reason"] = res.detail[:80]
        return StepOutcome(action_id, dict(params), status, obs)


ADAPTER = WifiAwareSession()
