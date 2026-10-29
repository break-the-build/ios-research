"""Seed corpus for smb-rig fuzz mode.

Seed files (seeds/run-*/NNNNNN_*.smbr) are re-parsed from their raw payloads;
the cmd/msgid stored in each record header is ignored, because runs recorded
before the header-offset fix carry wrong labels there (cmd=256,
msgid=0xfeff00000000).

Responses are paired with the request that carried the same MessageId, so a
template is keyed by (command, subkey):
  * SESSION_SETUP -> leg index within the connection (0 = challenge, 1 = final)
  * QUERY_INFO / QUERY_DIRECTORY / IOCTL -> smb2.request_subkey()
  * everything else -> None
Compound recordings are split into per-element templates.
"""
from __future__ import annotations

import glob
import os
import random
import shutil
import struct
from dataclasses import dataclass, field

import smb2

MAGIC = b"SMBR"
REC_HDR = "<BBII"                       # direction, cmd, msgid, len
REC_HDR_LEN = len(MAGIC) + struct.calcsize(REC_HDR)
QUARANTINE_DIR = "_quarantine"

Key = tuple[int, "int | None"]


@dataclass(frozen=True)
class RunReport:
    path: str
    frames: int
    responses: int
    bad_frames: int
    stale_labels: int

    @property
    def usable(self) -> bool:
        return self.bad_frames == 0 and self.responses > 0


@dataclass(frozen=True)
class Corpus:
    templates: dict[Key, tuple[smb2.Element, ...]]
    mp_negotiate: bytes | None
    runs: tuple[RunReport, ...] = field(default=())

    def latest(self, cmd: int, subkey: int | None) -> smb2.Element | None:
        """Deterministic choice (handshake glue): newest exact match."""
        cands = self._candidates(cmd, subkey)
        return cands[-1] if cands else None

    def pick(self, cmd: int, subkey: int | None, rng: random.Random) -> smb2.Element | None:
        """Random choice among recorded responses for diversity."""
        cands = self._candidates(cmd, subkey)
        return rng.choice(cands) if cands else None

    def _candidates(self, cmd: int, subkey: int | None) -> tuple[smb2.Element, ...]:
        exact = self.templates.get((cmd, subkey))
        if exact:
            return exact
        # no exact sub-type recorded: any response for this command
        return tuple(el for (c, _s), els in self.templates.items() if c == cmd for el in els)

    def summary(self) -> list[str]:
        return [f"{smb2.cmd_name(c)}[{s if s is None else hex(s)}]x{len(v)}"
                for (c, s), v in sorted(self.templates.items(), key=lambda kv: (kv[0][0], kv[0][1] or -1))]


def read_record(raw: bytes) -> tuple[int, int, int, bytes] | None:
    if raw[:4] != MAGIC or len(raw) < REC_HDR_LEN:
        return None
    direction, cmd, msgid, ln = struct.unpack_from(REC_HDR, raw, 4)
    return direction, cmd, msgid, raw[REC_HDR_LEN:REC_HDR_LEN + ln]


def write_record(direction: int, cmd: int, msgid: int, data: bytes) -> bytes:
    return MAGIC + struct.pack(REC_HDR, direction, cmd & 0xFF, msgid & 0xFFFFFFFF, len(data)) + data


def run_dirs(seeds_dir: str) -> list[str]:
    return sorted(d for d in glob.glob(os.path.join(seeds_dir, "*"))
                  if os.path.isdir(d) and not os.path.basename(d).startswith("_"))


def _frames(run_dir: str):
    for fp in sorted(glob.glob(os.path.join(run_dir, "*.smbr"))):
        with open(fp, "rb") as f:
            rec = read_record(f.read())
        if rec is not None:
            yield rec


def _valid_chain(chain: list[smb2.Element], direction: int) -> bool:
    return bool(chain) and all(
        el.header.command <= smb2.MAX_COMMAND
        and el.header.is_response == (direction == 1) for el in chain)


class _RunPairer:
    """Pairs response elements with their requests inside one recorded run."""

    def __init__(self) -> None:
        self.reqs: dict[int, Key] = {}
        self.ss_legs = 0
        self.after_smb1 = False

    def reset(self) -> None:
        self.reqs, self.ss_legs = {}, 0

    def on_request(self, el: smb2.Element) -> None:
        cmd = el.header.command
        if cmd == smb2.NEGOTIATE:
            self.reset()
        if cmd == smb2.SESSION_SETUP:
            sub, self.ss_legs = self.ss_legs, self.ss_legs + 1
        else:
            sub = smb2.request_subkey(cmd, el.body)
        self.reqs[el.header.message_id] = (cmd, sub)

    def key_for(self, el: smb2.Element) -> Key:
        key = self.reqs.get(el.header.message_id)
        if key is None or key[0] != el.header.command:
            return (el.header.command, None)
        return key


def scan_run(run_dir: str, sink: dict[Key, list[smb2.Element]] | None = None
             ) -> tuple[RunReport, bytes | None]:
    """Validate one run; when sink is given, add its templates to it."""
    pairer = _RunPairer()
    frames = responses = bad = stale = 0
    mp: bytes | None = None
    for direction, rec_cmd, rec_mid, payload in _frames(run_dir):
        frames += 1
        if payload[:4] == smb2.SMB1_SIG:
            if direction == 0 and smb2.is_smb1_negotiate(payload):
                pairer.reset()
                pairer.after_smb1 = True
            continue
        chain = smb2.split_chain(payload)
        if not _valid_chain(chain, direction):
            bad += 1
            continue
        first = chain[0].header
        if (first.command & 0xFF, first.message_id & 0xFFFFFFFF) != (rec_cmd, rec_mid):
            stale += 1
        for el in chain:
            if direction == 0:
                pairer.on_request(el)
                continue
            if el.header.status == smb2.STATUS_PENDING:
                continue                              # interim reply, not a template
            responses += 1
            if (el.header.command == smb2.NEGOTIATE and pairer.after_smb1
                    and el.header.message_id == 0 and el.header.message_id not in pairer.reqs):
                pairer.after_smb1 = False
                mp = mp or payload                    # reply to the SMB1 multi-protocol negotiate
                continue
            if sink is not None:
                sink.setdefault(pairer.key_for(el), []).append(el)
    report = RunReport(run_dir, frames, responses, bad, stale)
    return report, mp


def load_corpus(seeds_dir: str) -> Corpus:
    templates: dict[Key, list[smb2.Element]] = {}
    reports, mp = [], None
    for d in run_dirs(seeds_dir):
        report, _ = scan_run(d)
        reports.append(report)
        if not report.usable:
            continue
        _, run_mp = scan_run(d, templates)
        mp = run_mp or mp                             # newest usable run wins
    frozen = {k: tuple(v) for k, v in templates.items()}
    return Corpus(frozen, mp, tuple(reports))


def quarantine(seeds_dir: str, reports: tuple[RunReport, ...]) -> list[str]:
    """Move unusable runs to seeds/_quarantine/ (never deletes)."""
    dest_root = os.path.join(seeds_dir, QUARANTINE_DIR)
    moved = []
    for r in reports:
        if r.usable:
            continue
        os.makedirs(dest_root, exist_ok=True)
        dest = os.path.join(dest_root, os.path.basename(r.path))
        shutil.move(r.path, dest)
        moved.append(dest)
    return moved
