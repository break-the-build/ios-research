"""Crash-durable case storage for smb-rig.

A kernel panic discards the unified buffer cache, so a case that was only
write()n before send() is exactly the file that will be missing after reboot.
Every case and index line is therefore fsync'd (F_FULLFSYNC on Darwin, which
also flushes the drive cache) before the bytes go on the wire.

Each rig start gets its own run directory, so restarting after a panic never
overwrites the previous run's cases.
"""
from __future__ import annotations

import fcntl
import json
import os
import time


def _full_sync(fd: int) -> None:
    os.fsync(fd)
    full = getattr(fcntl, "F_FULLFSYNC", None)
    if full is not None:
        try:
            fcntl.fcntl(fd, full)
        except OSError:
            pass                          # filesystem without F_FULLFSYNC: fsync stands


def _sync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_write(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        _full_sync(f.fileno())
    _sync_dir(os.path.dirname(path) or ".")


def utc_stamp(t: float | None = None) -> str:
    t = time.time() if t is None else t
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t % 1 * 1000):03d}Z"


class CaseWriter:
    """cases/run-<UTC>-seed<S>/NNNNNNN.<ext> + INDEX.tsv + meta.json."""

    INDEX_COLUMNS = ("case", "utc", "conn", "kind", "bytes", "desc")

    def __init__(self, root: str, seed: int, meta: dict) -> None:
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        base = os.path.join(root, f"run-{stamp}-seed{seed}")
        path, n = base, 1
        while os.path.exists(path):                   # two starts in one second
            n += 1
            path = f"{base}-{n}"
        os.makedirs(path)
        self.dir = path
        self.n = 0
        self.index = os.path.join(path, "INDEX.tsv")
        durable_write(os.path.join(path, "meta.json"),
                      json.dumps({"seed": seed, "started": utc_stamp(), **meta}, indent=2).encode())
        durable_write(self.index, ("\t".join(self.INDEX_COLUMNS) + "\n").encode())

    def save(self, conn: int, kind: str, data: bytes, desc: str, ext: str = "rsp") -> str:
        """Persist one case durably; returns its path. Call BEFORE sending."""
        self.n += 1
        path = os.path.join(self.dir, f"{self.n:07d}.{ext}")
        durable_write(path, data)
        line = "\t".join((f"{self.n:07d}", utc_stamp(), str(conn), kind, str(len(data)),
                          desc.replace("\t", " ").replace("\n", " ")))
        with open(self.index, "a") as f:
            f.write(line + "\n")
            f.flush()
            _full_sync(f.fileno())
        return path
