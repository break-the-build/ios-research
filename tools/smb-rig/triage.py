"""Post-run triage for smb-rig: depth statistics and exact connection replay.

stats  — how deep connections got (did the client reach CREATE / QUERY_DIR /
         READ ...?), how often a connection ended right after a mutated reply
         (client rejected it), and the newest mutated cases (panic suspects).
replay — re-serve one recorded connection byte-for-byte. Only MessageIds are
         re-patched (in place, so corrupted NextCommand chains survive) to
         match the live client's requests; requests past the recorded ones are
         answered by a clean session so the mount can proceed.
"""
from __future__ import annotations

import os
import struct
import unicodedata
from collections import Counter
from dataclasses import dataclass

import smb2
from cases import CaseRow
from fuzz_session import FuzzSession, Outgoing

DEPTH_COMMANDS = ("TREE_CONNECT", "CREATE", "QUERY_DIR", "QUERY_INFO", "READ", "WRITE",
                  "IOCTL", "SET_INFO", "CHANGE_NOTIFY")
SUSPECTS_SHOWN = 5


@dataclass(frozen=True)
class RunStats:
    conns: int
    mounts: int                      # TREE_CONNECT replies (smbfs reuses sessions)
    cases: int
    mutated: int
    kinds: dict[str, int]
    reached: dict[str, int]          # command -> connections that got a reply for it
    ended_on_mutation: int           # connections whose final case was mutated
    suspects: tuple[CaseRow, ...]    # newest mutated cases, newest last


def _commands(kind: str) -> list[str]:
    return kind.split("+")


def run_stats(rows: list[CaseRow]) -> RunStats:
    responses = [r for r in rows if r.kind != "UNKNOWN_REQ"]
    by_conn: dict[int, list[CaseRow]] = {}
    for r in responses:
        by_conn.setdefault(r.conn, []).append(r)
    kinds: Counter[str] = Counter(c for r in responses for c in _commands(r.kind))
    reached = {cmd: sum(1 for rs in by_conn.values()
                        if any(cmd in _commands(r.kind) for r in rs))
               for cmd in DEPTH_COMMANDS}
    ended = sum(1 for rs in by_conn.values() if rs[-1].mutated)
    mutated = [r for r in responses if r.mutated]
    return RunStats(len(by_conn), kinds.get("TREE_CONNECT", 0), len(responses), len(mutated),
                    dict(kinds), reached, ended, tuple(mutated[-SUSPECTS_SHOWN:]))


def format_stats(s: RunStats) -> list[str]:
    pct = (lambda n: f"{100 * n / s.conns:.0f}%") if s.conns else (lambda n: "-")
    lines = [(f"connections={s.conns} mounts={s.mounts} cases={s.cases} mutated={s.mutated} "
              f"ended-on-mutated-reply={s.ended_on_mutation} ({pct(s.ended_on_mutation)})"),
             "depth (connections reaching):  " + "  ".join(
                 f"{c}={n}({pct(n)})" for c, n in s.reached.items()),
             "replies by command:  " + "  ".join(f"{k}={v}" for k, v in sorted(s.kinds.items()))]
    if s.suspects:
        lines.append("newest mutated cases (panic suspects, newest last):")
        lines += [f"  {r.case} {r.utc} conn={r.conn} req={r.req} {r.kind}: {r.desc[:120]}"
                  for r in s.suspects]
    return lines


KLOG_FILE = "klog.tsv"
KLOG_SHOWN = 15


def format_klog(run_dir: str) -> list[str]:
    """Kernel-log coverage for a run: templates, first sightings and their cases."""
    path = os.path.join(run_dir, KLOG_FILE)
    if not os.path.exists(path):
        return ["kernel log: not captured (run without --no-klog)"]
    counts: Counter[str] = Counter()
    new: list[tuple[str, str]] = []
    alerts: list[tuple[str, str]] = []
    with open(path) as f:
        for line in f:
            cols = line.rstrip("\n").split("\t")
            if len(cols) < 4:
                continue                              # torn final line after a panic
            counts[cols[3]] += 1
            flags = cols[2].split(",")
            if "NEW" in flags:
                new.append((cols[1], cols[3]))
            if "ALERT" in flags:
                alerts.append((cols[1], cols[4] if len(cols) > 4 else cols[3]))
    lines = [(f"kernel log: {sum(counts.values())} smbfs messages, {len(counts)} templates, "
              f"{len(new)} new this run, {len(alerts)} ALERT")]
    lines += [f"  ALERT @case {case}: {msg[:110]}" for case, msg in alerts[:KLOG_SHOWN]]
    lines += [f"  NEW @case {case}: {tmpl[:110]}" for case, tmpl in new[:KLOG_SHOWN]]
    if len(new) > KLOG_SHOWN:
        lines.append(f"  ... {len(new) - KLOG_SHOWN} more in {path}")
    return lines


LISTINGS_FILE = "listings.tsv"         # written by runner.sh: utc \t listed name
LEAKS_SHOWN = 20
UNICODE_FORMS = ("NFC", "NFD")         # macOS may hand back either normalisation


@dataclass(frozen=True)
class LeakCandidate:
    utc: str
    name: str


UTC_SECONDS = len("2026-01-01T00:00:00")  # compare runner (s) and INDEX (ms) stamps at 1 s


def read_listings(path: str, start_utc: str = "", end_utc: str = "~") -> dict[str, str]:
    """name -> first UTC it was listed, within [start_utc, end_utc] (to the second)."""
    lo, hi = start_utc[:UTC_SECONDS], end_utc[:UTC_SECONDS]
    names: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                utc, _, name = line.rstrip("\n").partition("\t")
                if name and lo <= utc[:UTC_SECONDS] <= hi:
                    names.setdefault(name, utc)
    except OSError:
        return {}
    return names


def find_leaks(rows: list[CaseRow], listings: dict[str, str]) -> list[LeakCandidate]:
    """Names the client listed whose bytes appear in no reply we sent.

    smbfs builds names from server replies; a name we never sent most likely
    came from an out-of-bounds read past a directory reply -- kernel memory
    disclosure that a release kernel does not panic on. Expect a few false
    positives (character mapping); every hit deserves a look.
    """
    sent = b"".join(_read_case(r) for r in rows if r.kind != "UNKNOWN_REQ")
    leaks = []
    for name, utc in sorted(listings.items(), key=lambda kv: kv[1]):
        if name in (".", ".."):
            continue
        encodings = {unicodedata.normalize(form, name).encode("utf-16-le", "surrogatepass")
                     for form in UNICODE_FORMS}
        if not any(e in sent for e in encodings):
            leaks.append(LeakCandidate(utc, name))
    return leaks


def format_leaks(leaks: list[LeakCandidate], listings_seen: int) -> list[str]:
    if not listings_seen:
        return ["leak oracle: no listings captured (runner.sh writes cases/listings.tsv)"]
    lines = [f"leak oracle: {listings_seen} listed names checked, {len(leaks)} not found in any reply"]
    lines += [f"  LEAK? {c.utc} {c.name!r}" for c in leaks[:LEAKS_SHOWN]]
    return lines


def _read_case(row: CaseRow) -> bytes:
    try:
        with open(row.path, "rb") as f:
            return f.read()
    except OSError:
        return b""                                      # torn by a panic


def patch_message_ids(pdu: bytes, ids: list[int]) -> bytes:
    """Overwrite MessageId of successive chain elements in place.

    Walks the PDU's own NextCommand links and stops at the first invalid one,
    so a deliberately corrupted chain is preserved byte-for-byte. Unsolicited
    notifications (MessageId 0xFFFF...) are left alone.
    """
    b = bytearray(pdu)
    off, idx = 0, 0
    while off + smb2.HDR <= len(b) and b[off:off + 4] == smb2.SMB2_SIG and idx < len(ids):
        if struct.unpack_from("<Q", b, off + 24)[0] != smb2.NO_MESSAGE_ID:
            struct.pack_into("<Q", b, off + 24, ids[idx])
            idx += 1
        nxt = struct.unpack_from("<I", b, off + 20)[0]
        if nxt < smb2.HDR or off + nxt > len(b):
            break
        off += nxt
    return bytes(b)


class ReplaySession:
    """Serves a recorded connection; duck-types FuzzSession for serve_connection."""

    def __init__(self, rows: list[CaseRow], fallback: FuzzSession) -> None:
        self.groups: dict[int, list[CaseRow]] = {}
        for r in rows:
            if r.kind != "UNKNOWN_REQ":
                self.groups.setdefault(r.req, []).append(r)
        self.fallback = fallback

    @property
    def saw_echo(self) -> bool:
        return self.fallback.saw_echo

    def respond(self, payload: bytes) -> list[Outgoing]:
        # the clean fallback sees every request so its session state stays real
        live = self.fallback.respond(payload)
        group = self.groups.get(self.fallback.req_no)
        if group is None:
            return live
        ids = [el.header.message_id for el in smb2.split_chain(payload)
               if el.header.command != smb2.CANCEL]
        out = []
        for r in group:
            with open(r.path, "rb") as f:
                pdu = f.read()
            out.append(Outgoing(r.kind, patch_message_ids(pdu, ids), f"replay {r.case}: {r.desc}",
                                self.fallback.req_no, r.mutated))
        return out
