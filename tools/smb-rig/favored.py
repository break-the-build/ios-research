"""Favored mutated replies: the evolutionary half of smb-rig's feedback loop.

When a mutated reply makes the kernel emit a smbfs log template never seen
before (klog.py), that reply reached a new error path. It is promoted here
and later mutations of the same (command, subkey) start from it with
probability Knobs.p_favored, so mutations stack along paths the kernel has
shown it actually parses -- coverage-guided fuzzing without kernel coverage.
"""
from __future__ import annotations

import os
import random
import threading
import time

import smb2
from cases import durable_write
from corpus import Key

CAP_PER_KEY = 64


class FavoredStore:
    def __init__(self, run_dir: str | None = None) -> None:
        self._lock = threading.Lock()
        self._items: dict[Key, list[smb2.Element]] = {}
        self._dir = os.path.join(run_dir, "favored") if run_dir else None
        self.promoted = 0

    def add(self, key: Key, el: smb2.Element, reason: str, case: int) -> None:
        with self._lock:
            items = self._items.setdefault(key, [])
            if any(e.body == el.body and e.header.status == el.header.status for e in items):
                return
            if len(items) >= CAP_PER_KEY:
                items.pop(0)
            items.append(el)
            self.promoted += 1
            n = self.promoted
        if self._dir:
            os.makedirs(self._dir, exist_ok=True)
            name = f"{n:05d}-{smb2.cmd_name(key[0])}-{key[1] if key[1] is not None else 'x'}"
            durable_write(os.path.join(self._dir, name + ".rsp"), smb2.join_chain([el]))
            with open(os.path.join(self._dir, "favored.tsv"), "a") as f:
                f.write(f"{name}\t{case}\t{reason}\n")

    def pick(self, key: Key, rng: random.Random) -> smb2.Element | None:
        with self._lock:
            items = self._items.get(key)
            return rng.choice(items) if items else None

    def __len__(self) -> int:
        with self._lock:
            return sum(len(v) for v in self._items.values())


class RecentMutations:
    """Mutated replies sent in the last few seconds, for log attribution."""

    WINDOW_S = 2.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: list[tuple[float, int, tuple[tuple[Key, smb2.Element], ...]]] = []

    def add(self, case: int, elements: tuple[tuple[Key, smb2.Element], ...],
            now: float | None = None) -> None:
        if not elements:
            return
        t = time.monotonic() if now is None else now
        with self._lock:
            self._items.append((t, case, elements))
            self._items = [x for x in self._items if t - x[0] <= self.WINDOW_S * 4]

    def window(self, now: float | None = None) -> list[tuple[int, tuple[tuple[Key, smb2.Element], ...]]]:
        t = time.monotonic() if now is None else now
        with self._lock:
            return [(case, els) for (ts, case, els) in self._items if t - ts <= self.WINDOW_S]
