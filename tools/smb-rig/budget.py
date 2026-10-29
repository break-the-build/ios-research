"""Mutation budget policy for one smb-rig connection.

Owns *when* a mutation may happen; FuzzSession owns *what* it is.

* The budget refills at every TREE_CONNECT (smbfs reuses one TCP session for
  successive mounts) and, with `refill_every`, every N requests within a
  mount, so a long-lived mount keeps being fuzzed. Measured: after the
  warm-up a mutated reply was never the last request of its mount (0/158,
  median 21 requests followed), so mutations do not end sessions and the
  budget is a rate, not a session-saving device.
* The first `warmup` requests after a TREE_CONNECT (mount_smbfs's share
  check) are protected except with probability `p_warmup`: mutating them
  failed about half of those mounts.
* With `spread`, the body-mutation chance is budget-left / requests expected
  to remain in the current window, so mutations land evenly instead of on the
  window's first requests. The window is `refill_every` requests or, when
  that is 0, the mount (its length learned as a running average).
"""
from __future__ import annotations

import random
from dataclasses import dataclass

MOUNT_LEN_DECAY = 0.7                  # weight of history in the mount-length average


@dataclass(frozen=True)
class BudgetConfig:
    budget: int
    p_mutate: float
    spread: bool
    horizon: float
    warmup: int
    p_warmup: float
    refill_every: int = 0              # also refill every N requests within a mount (0 = off)


class Budget:
    def __init__(self, config: BudgetConfig, rng: random.Random) -> None:
        self.config = config
        self.rng = rng
        self.left = config.budget
        self.mount_pos = 0                 # requests since the last TREE_CONNECT
        self.mount_len = config.horizon    # running average of requests per mount

    def on_request(self) -> None:
        self.mount_pos += 1
        every = self.config.refill_every
        if every and self.mount_pos > self.config.warmup and self._window_pos() == 1:
            self.left = self.config.budget

    def new_mount(self) -> None:
        if self.mount_pos > 1:
            observed = self.mount_pos - 1
            self.mount_len = MOUNT_LEN_DECAY * self.mount_len + (1 - MOUNT_LEN_DECAY) * observed
        self.mount_pos = 0
        self.left = self.config.budget

    def spend(self, p: float) -> bool:
        """Consume one mutation event with probability p, if budget remains."""
        if self.left <= 0 or self.rng.random() >= p:
            return False
        if self.mount_pos <= self.config.warmup and self.rng.random() >= self.config.p_warmup:
            return False                   # protect mount_smbfs's share check
        self.left -= 1
        return True

    def body_p(self) -> float:
        """Body-mutation chance: flat, or spread evenly over the rest of the window."""
        if not self.config.spread:
            return self.config.p_mutate
        if self.config.refill_every:
            remaining = self.config.refill_every - self._window_pos() + 1
        else:
            remaining = self.mount_len - self.mount_pos + 1
        return min(1.0, self.left / max(1.0, remaining))

    def _window_pos(self) -> int:
        """1-based position inside the current refill window (after the warm-up)."""
        return (self.mount_pos - self.config.warmup - 1) % self.config.refill_every + 1
