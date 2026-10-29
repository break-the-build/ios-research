"""Structure-aware response mutators for smb-rig.

Priority is the fields client parsers trust to index into the response:
Offset/Length pairs and NextEntryOffset chains. Offsets in SMB2 bodies are
relative to the start of the SMB2 header, so body position = value - HDR.
Every mutator returns a new bytes object plus a short description that is
written to the case index for triage.
"""
from __future__ import annotations

import random
import struct
from dataclasses import dataclass

import smb2


@dataclass(frozen=True)
class Field:
    offset: int          # body-relative
    size: int            # 1, 2 or 4 bytes


_FMT = {1: "<B", 2: "<H", 4: "<I"}

# Offset/length fields in fixed response bodies (MS-SMB2 2.2.x)
LENGTH_FIELDS: dict[int, tuple[Field, ...]] = {
    smb2.NEGOTIATE: (Field(6, 2), Field(56, 2), Field(58, 2), Field(60, 4)),
    smb2.SESSION_SETUP: (Field(4, 2), Field(6, 2)),
    smb2.CREATE: (Field(80, 4), Field(84, 4)),
    smb2.READ: (Field(2, 1), Field(4, 4), Field(8, 4)),
    smb2.IOCTL: (Field(24, 4), Field(28, 4), Field(32, 4), Field(36, 4)),
    smb2.QUERY_DIRECTORY: (Field(2, 2), Field(4, 4)),
    smb2.QUERY_INFO: (Field(2, 2), Field(4, 4)),
    smb2.CHANGE_NOTIFY: (Field(2, 2), Field(4, 4)),
}

# NextEntryOffset-linked variable records: (start-offset field, per-entry fields)
CREATE_CONTEXT_FIELDS = (Field(0, 4), Field(4, 2), Field(6, 2), Field(10, 2), Field(12, 4))
NOTIFY_FIELDS = (Field(0, 4), Field(8, 4))
STREAM_INFO_FIELDS = (Field(0, 4), Field(4, 4))            # FileStreamInformation (xattrs)
FULL_EA_FIELDS = (Field(0, 4), Field(5, 1), Field(6, 2))   # FileFullEaInformation
DIR_NAMES_FIELDS = (Field(0, 4), Field(8, 4))              # FileNamesInformation
DIR_DEFAULT_FIELDS = (Field(0, 4), Field(60, 4))           # *DirectoryInformation: FileNameLength@60

QI_FILE = 1
FILE_FULL_EA_INFORMATION = 15
FILE_STREAM_INFORMATION = 22
FILE_NAMES_INFORMATION = 0x0C
MAX_CHAIN_ENTRIES = 64

SYMLINK_ERROR_TAG = 0x4C4D5953
IO_REPARSE_TAG_SYMLINK = 0xA000000C


def _u(body: bytes | bytearray, f: Field) -> int:
    return struct.unpack_from(_FMT[f.size], body, f.offset)[0]


def _fits(body: bytes | bytearray, f: Field) -> bool:
    return f.offset + f.size <= len(body)


def interesting(value: int, size: int, msg_len: int, rng: random.Random) -> int:
    """Boundary values for an offset/length field of a message of msg_len bytes."""
    mask = (1 << (8 * size)) - 1
    cands = (0, 1, mask, mask >> 1, value + 1, value - 1, value + 8, value * 2,
             smb2.HDR, msg_len, msg_len - 1, msg_len + 1, msg_len + 0x1000)
    return rng.choice(cands) & mask


def chain_fields(cmd: int, subkey: int | None, body: bytes) -> list[Field]:
    """Absolute body positions of every entry field in the response's chain."""
    start_field, per_entry = _chain_spec(cmd, subkey)
    if start_field is None or not _fits(body, start_field):
        return []
    off = _u(body, start_field) - smb2.HDR
    out: list[Field] = []
    for _ in range(MAX_CHAIN_ENTRIES):
        if off < 0 or off + 4 > len(body):
            break
        out += [Field(off + f.offset, f.size) for f in per_entry
                if off + f.offset + f.size <= len(body)]
        nxt = struct.unpack_from("<I", body, off)[0]
        if nxt == 0:
            break
        off += nxt
    return out


def _chain_spec(cmd: int, subkey: int | None) -> tuple[Field | None, tuple[Field, ...]]:
    if cmd == smb2.CREATE:
        return Field(80, 4), CREATE_CONTEXT_FIELDS
    if cmd == smb2.CHANGE_NOTIFY:
        return Field(2, 2), NOTIFY_FIELDS
    if cmd == smb2.QUERY_DIRECTORY:
        per = DIR_NAMES_FIELDS if subkey == FILE_NAMES_INFORMATION else DIR_DEFAULT_FIELDS
        return Field(2, 2), per
    if cmd == smb2.QUERY_INFO and subkey is not None:
        if subkey == (QI_FILE << 8) | FILE_STREAM_INFORMATION:
            return Field(2, 2), STREAM_INFO_FIELDS
        if subkey == (QI_FILE << 8) | FILE_FULL_EA_INFORMATION:
            return Field(2, 2), FULL_EA_FIELDS
    return None, ()


def _stomp(b: bytearray, f: Field, rng: random.Random) -> str:
    old = _u(b, f)
    new = interesting(old, f.size, smb2.HDR + len(b), rng)
    struct.pack_into(_FMT[f.size], b, f.offset, new)
    return f"@{f.offset}:{old:#x}->{new:#x}"


def mutate_body(cmd: int, subkey: int | None, body: bytes, rng: random.Random
                ) -> tuple[bytes, str]:
    """Apply 1-4 mutations, weighted toward offset/length/chain fields."""
    b = bytearray(body)
    all_chained = chain_fields(cmd, subkey, body)
    descs = []
    for _ in range(rng.randint(1, 4)):
        # re-filter every pass: an earlier truncation may have cut fields off
        fixed = [f for f in LENGTH_FIELDS.get(cmd, ()) if _fits(b, f)]
        chained = [f for f in all_chained if _fits(b, f)]
        r = rng.random()
        if r < 0.40 and fixed:
            descs.append("len" + _stomp(b, rng.choice(fixed), rng))
        elif r < 0.65 and chained:
            descs.append("chain" + _stomp(b, rng.choice(chained), rng))
        elif r < 0.85 and len(b) >= 4:
            size = rng.choice((2, 4))
            descs.append("raw" + _stomp(b, Field(rng.randrange(len(b) - size + 1), size), rng))
        elif r < 0.93 and b:
            o = rng.randrange(len(b))
            b[o] ^= 1 << rng.randrange(8)
            descs.append(f"flip@{o}")
        else:
            b, d = _resize(b, rng)
            descs.append(d)
    return bytes(b), ",".join(descs) or "none"


def _resize(b: bytearray, rng: random.Random) -> tuple[bytearray, str]:
    if b and rng.random() < 0.5:
        n = rng.randrange(len(b))
        return b[:n], f"trunc->{n}"
    extra = rng.choice((1, 7, 64, 256, 4096))
    return b + bytes(rng.getrandbits(8) for _ in range(extra)), f"extend+{extra}"


def error_body(byte_count: int, context_count: int, data: bytes) -> bytes:
    return struct.pack("<HBBI", 9, context_count, 0, byte_count) + (data or b"\x00")


def symlink_error(rng: random.Random) -> tuple[int, bytes, str]:
    """STATUS_STOPPED_ON_SYMLINK with a Symbolic Link Error Response (2.2.2.2.1)."""
    sub = "target\\x".encode("utf-16-le")
    prn = "x".encode("utf-16-le")
    path = sub + prn
    names = ("symlink_len", "reparse_len", "unparsed", "sub_off", "sub_len", "prn_off", "prn_len")
    tail_len = 4 + 4 + 2 + 2 * 5 + 4 + len(path)
    vals = [tail_len, 12 + len(path), 0, 0, len(sub), len(sub), len(prn)]
    victim = rng.randrange(len(vals))
    vals[victim] = interesting(vals[victim], 4 if victim == 0 else 2, smb2.HDR + 8 + 4 + tail_len, rng)
    data = struct.pack("<IIIHHHHHHI", vals[0], SYMLINK_ERROR_TAG, IO_REPARSE_TAG_SYMLINK,
                       *vals[1:], 0) + path
    status = smb2.STATUS_STOPPED_ON_SYMLINK
    return status, error_body(len(data), 0, data), f"symlink:{names[victim]}={vals[victim]:#x}"


def inject_status(cmd: int, subkey: int | None, body: bytes, rng: random.Random
                  ) -> tuple[int, bytes, str]:
    """Replace a success reply with an error/warning reply that carries data."""
    r = rng.random()
    if r < 0.4:
        return symlink_error(rng)
    if r < 0.7:
        # warning status: the client still parses the (mutated) success body
        mbody, d = mutate_body(cmd, subkey, body, rng)
        return smb2.STATUS_BUFFER_OVERFLOW, mbody, "overflow+" + d
    data = bytes(rng.getrandbits(8) for _ in range(rng.choice((0, 8, 48))))
    count = interesting(len(data), 4, smb2.HDR + 8 + len(data), rng)
    ctx = rng.choice((0, 1, 2, 0xFF))
    status = rng.choice((0xC0000022, 0xC0000034, 0xC000000D))
    return status, error_body(count, ctx, data), f"error:{status:#x} ctx={ctx} bc={count:#x}"


def oplock_break(file_id: bytes, rng: random.Random) -> tuple[smb2.Element, str]:
    """Unsolicited Oplock Break Notification (2.2.23.1)."""
    level = rng.choice((0x00, 0x01, 0x08, 0x09, 0xFF))
    body = struct.pack("<HBBI", 24, level, 0, 0) + file_id[:16].ljust(16, b"\x00")
    hdr = smb2.Header(status=smb2.STATUS_SUCCESS, command=smb2.OPLOCK_BREAK,
                      flags=smb2.FLAG_RESPONSE, message_id=smb2.NO_MESSAGE_ID, credits=0)
    return smb2.Element(hdr, body), f"oplock_break:level={level:#x}"


LEASE_BREAK_SIZE = 44                 # Lease Break Notification (2.2.23.2)
LEASE_ACK_REQUIRED = 0x01
LEASE_STATES = (0x0, 0x1, 0x3, 0x5, 0x7, 0x2, 0x4, 0xFFFFFFFF)   # R=1 H=2 W=4, plus invalid


def lease_break(lease_key: bytes, rng: random.Random) -> tuple[smb2.Element, str]:
    """Server-initiated lease break against a lease the client really holds.

    The client keys its lease table by LeaseKey; a break for a live key drives
    smbfs's lease state machine (state downgrade, ack, epoch handling) rather
    than bouncing off the size check the way an oplock-shaped break does.
    """
    epoch = rng.choice((0, 1, 2, 0x7FFF, 0xFFFF))
    flags = rng.choice((0, LEASE_ACK_REQUIRED, 0xFFFFFFFF))
    cur, new = rng.choice(LEASE_STATES), rng.choice(LEASE_STATES)
    reason, access, share = 0, rng.choice((0, 0xFFFFFFFF)), rng.choice((0, 7))
    body = (struct.pack("<HHI", LEASE_BREAK_SIZE, epoch, flags) + lease_key[:16].ljust(16, b"\x00")
            + struct.pack("<IIIII", cur, new, reason, access, share))
    hdr = smb2.Header(status=smb2.STATUS_SUCCESS, command=smb2.OPLOCK_BREAK,
                      flags=smb2.FLAG_RESPONSE, message_id=smb2.NO_MESSAGE_ID, credits=0)
    return smb2.Element(hdr, body), f"lease_break:epoch={epoch:#x},flags={flags:#x},{cur:#x}->{new:#x}"


def next_command_override(n_elements: int, rng: random.Random) -> tuple[dict[int, int], str]:
    idx = rng.randrange(n_elements - 1)
    val = rng.choice((0, 1, 8, smb2.HDR - 8, smb2.HDR, 0x7FFFFFF8, 0xFFFFFFF8))
    return {idx: val}, f"next[{idx}]={val:#x}"
