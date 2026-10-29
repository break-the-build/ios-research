"""SMB2 wire helpers for smb-rig: NBSS framing, header layout, compound chains.

Header layout (MS-SMB2 2.2.1.2, sync form) — offsets are from the start of
the 64-byte header:
  0 ProtocolId 4s | 4 StructureSize H | 6 CreditCharge H | 8 Status I
  12 Command H | 14 CreditRequest/Response H | 16 Flags I | 20 NextCommand I
  24 MessageId Q | 32 Reserved I | 36 TreeId I | 40 SessionId Q | 48 Signature 16s
Async form (FLAG_ASYNC) reuses bytes 32..39 as a single u64 AsyncId.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, replace

SMB2_SIG = b"\xfeSMB"
SMB1_SIG = b"\xffSMB"
SMB1_NEGOTIATE = 0x72
HDR = 64
HDR_FMT = "<4sHHIHHIIQIIQ16s"
assert struct.calcsize(HDR_FMT) == HDR

FLAG_RESPONSE = 0x1
FLAG_ASYNC = 0x2
FLAG_RELATED = 0x4
FLAG_SIGNED = 0x8

NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT, TREE_DISCONNECT = 0, 1, 2, 3, 4
CREATE, CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL, CANCEL = 5, 6, 7, 8, 9, 10, 11, 12
ECHO, QUERY_DIRECTORY, CHANGE_NOTIFY, QUERY_INFO, SET_INFO, OPLOCK_BREAK = 13, 14, 15, 16, 17, 18
MAX_COMMAND = OPLOCK_BREAK

CMD_NAMES = {
    NEGOTIATE: "NEGOTIATE", SESSION_SETUP: "SESSION_SETUP", LOGOFF: "LOGOFF",
    TREE_CONNECT: "TREE_CONNECT", TREE_DISCONNECT: "TREE_DISCONNECT",
    CREATE: "CREATE", CLOSE: "CLOSE", FLUSH: "FLUSH", READ: "READ",
    WRITE: "WRITE", LOCK: "LOCK", IOCTL: "IOCTL", CANCEL: "CANCEL",
    ECHO: "ECHO", QUERY_DIRECTORY: "QUERY_DIR", CHANGE_NOTIFY: "CHANGE_NOTIFY",
    QUERY_INFO: "QUERY_INFO", SET_INFO: "SET_INFO", OPLOCK_BREAK: "OPLOCK_BREAK",
}

STATUS_SUCCESS = 0x00000000
STATUS_PENDING = 0x00000103
STATUS_BUFFER_OVERFLOW = 0x80000005
STATUS_STOPPED_ON_SYMLINK = 0x8000002D
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
STATUS_NOT_SUPPORTED = 0xC00000BB

NO_MESSAGE_ID = 0xFFFFFFFFFFFFFFFF      # unsolicited server notifications
RELATED_ID32 = 0xFFFFFFFF               # TreeId placeholder in related requests
RELATED_ID64 = 0xFFFFFFFFFFFFFFFF       # SessionId placeholder in related requests
ZERO_SIGNATURE = b"\x00" * 16

# SMB2 ERROR response body (2.2.2) with ByteCount=0 still carries 1 data byte
ERROR_BODY = struct.pack("<HBBI", 9, 0, 0, 0) + b"\x00"


def cmd_name(cmd: int) -> str:
    return CMD_NAMES.get(cmd, str(cmd))


@dataclass(frozen=True)
class Header:
    status: int
    command: int
    flags: int
    message_id: int
    tree_id: int = 0
    session_id: int = 0
    credit_charge: int = 0
    credits: int = 1
    next_command: int = 0
    reserved: int = 0
    signature: bytes = ZERO_SIGNATURE

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_RESPONSE)

    @property
    def is_related(self) -> bool:
        return bool(self.flags & FLAG_RELATED)

    def with_async_id(self, async_id: int) -> Header:
        """Async form: AsyncId occupies the Reserved+TreeId bytes."""
        return replace(self, flags=self.flags | FLAG_ASYNC,
                       reserved=async_id & 0xFFFFFFFF, tree_id=async_id >> 32)


@dataclass(frozen=True)
class Element:
    """One SMB2 message inside a (possibly compound) PDU."""
    header: Header
    body: bytes


def pack_header(h: Header) -> bytes:
    return struct.pack(HDR_FMT, SMB2_SIG, HDR, h.credit_charge, h.status,
                       h.command, h.credits, h.flags, h.next_command,
                       h.message_id, h.reserved, h.tree_id, h.session_id,
                       h.signature)


def unpack_header(buf: bytes, off: int = 0) -> Header | None:
    if len(buf) - off < HDR:
        return None
    (sig, size, charge, status, cmd, credits, flags, nxt, mid, rsv, tid, sid,
     sig16) = struct.unpack_from(HDR_FMT, buf, off)
    if sig != SMB2_SIG or size != HDR:
        return None
    return Header(status=status, command=cmd, flags=flags, message_id=mid,
                  tree_id=tid, session_id=sid, credit_charge=charge,
                  credits=credits, next_command=nxt, reserved=rsv,
                  signature=sig16)


def split_chain(pdu: bytes) -> list[Element]:
    """Split a compound PDU on NextCommand. Stops at the first bad link."""
    out: list[Element] = []
    off = 0
    while True:
        h = unpack_header(pdu, off)
        if h is None:
            return out
        nxt = h.next_command
        if nxt and (nxt < HDR or off + nxt > len(pdu)):
            nxt = 0                                   # malformed link: take rest
        end = off + nxt if nxt else len(pdu)
        out.append(Element(h, pdu[off + HDR:end]))
        if not nxt:
            return out
        off += nxt


def _pad8(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 8)


def join_chain(elements: list[Element],
               next_overrides: dict[int, int] | None = None) -> bytes:
    """Serialise elements as one PDU; non-final elements are 8-byte padded.

    next_overrides maps element index -> forced NextCommand value (mutation).
    """
    overrides = next_overrides or {}
    parts = []
    for i, el in enumerate(elements):
        last = i == len(elements) - 1
        body = el.body if last else _pad8(el.body)
        nxt = 0 if last else HDR + len(body)
        nxt = overrides.get(i, nxt) & 0xFFFFFFFF
        parts.append(pack_header(replace(el.header, next_command=nxt)) + body)
    return b"".join(parts)


def request_subkey(cmd: int, body: bytes) -> int | None:
    """Sub-type that selects a matching response template for a request."""
    if cmd == QUERY_INFO and len(body) >= 4:
        return (body[2] << 8) | body[3]               # InfoType, FileInfoClass
    if cmd == QUERY_DIRECTORY and len(body) >= 3:
        return body[2]                                # FileInformationClass
    if cmd == IOCTL and len(body) >= 8:
        return struct.unpack_from("<I", body, 4)[0]   # CtlCode
    return None


def is_smb1_negotiate(payload: bytes) -> bool:
    return payload[:4] == SMB1_SIG and len(payload) > 4 and payload[4] == SMB1_NEGOTIATE


def nbss_wrap(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def nbss_split(buf: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    """Return complete NBSS PDUs (type, payload) and the unconsumed rest."""
    out, off = [], 0
    while len(buf) - off >= 4:
        n = int.from_bytes(buf[off + 1:off + 4], "big")
        if len(buf) - off < 4 + n:
            break
        out.append((buf[off], buf[off + 4:off + 4 + n]))
        off += 4 + n
    return out, buf[off:]
