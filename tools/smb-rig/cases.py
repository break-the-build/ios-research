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
import threading
import time
from dataclasses import dataclass


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

    # req = ordinal of the client request answered (replay groups by it);
    # mut = 1 when this PDU carries a mutation (the post-panic suspect set)
    INDEX_COLUMNS = ("case", "utc", "conn", "req", "mut", "kind", "bytes", "desc")

    def __init__(self, root: str, seed: int, meta: dict, tag: str | None = None) -> None:
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        base = os.path.join(root, f"run-{stamp}-{tag or f'seed{seed}'}")
        path, n = base, 1
        while os.path.exists(path):                   # two starts in one second
            n += 1
            path = f"{base}-{n}"
        os.makedirs(path)
        self.dir = path
        self.n = 0
        self._lock = threading.Lock()
        self.index = os.path.join(path, "INDEX.tsv")
        durable_write(os.path.join(path, "meta.json"),
                      json.dumps({"seed": seed, "started": utc_stamp(), **meta}, indent=2).encode())
        durable_write(self.index, ("\t".join(self.INDEX_COLUMNS) + "\n").encode())

    def save(self, conn: int, kind: str, data: bytes, desc: str, ext: str = "rsp",
             req: int = 0, mutated: bool = False) -> str:
        """Persist one case durably; returns its path. Call BEFORE sending.

        Serialised across connection threads so case numbers and index order
        match the global send order (the post-panic suspect is the last line).
        """
        with self._lock:
            self.n += 1
            path = os.path.join(self.dir, f"{self.n:07d}.{ext}")
            durable_write(path, data)
            line = "\t".join((f"{self.n:07d}", utc_stamp(), str(conn), str(req), str(int(mutated)),
                              kind, str(len(data)), desc.replace("\t", " ").replace("\n", " ")))
            with open(self.index, "a") as f:
                f.write(line + "\n")
                f.flush()
                _full_sync(f.fileno())
            return path


@dataclass(frozen=True)
class CaseRow:
    case: str
    utc: str
    conn: int
    req: int
    mutated: bool
    kind: str
    size: int
    desc: str
    path: str


def read_index(run_dir: str) -> list[CaseRow]:
    """Parse a run's INDEX.tsv (tolerates a torn final line after a panic)."""
    rows: list[CaseRow] = []
    with open(os.path.join(run_dir, "INDEX.tsv")) as f:
        header = f.readline().rstrip("\n").split("\t")
        for line in f:
            vals = line.rstrip("\n").split("\t")
            if len(vals) != len(header):
                continue
            r = dict(zip(header, vals))
            ext = "unknown" if r["kind"] == "UNKNOWN_REQ" else "rsp"
            rows.append(CaseRow(r["case"], r["utc"], int(r["conn"]), int(r.get("req", 0)),
                                r.get("mut", "0") == "1", r["kind"], int(r["bytes"]), r["desc"],
                                os.path.join(run_dir, f"{r['case']}.{ext}")))
    return rows


def latest_run(root: str) -> str | None:
    runs = sorted((os.path.join(root, d) for d in os.listdir(root) if d.startswith("run-")),
                  key=os.path.getmtime) if os.path.isdir(root) else []
    return runs[-1] if runs else None
