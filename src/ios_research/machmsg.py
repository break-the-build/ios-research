"""Mach message model for kernel-boundary research (XNU ``mach_msg`` subset).

Packs and parses a deterministic, simplified subset of the Mach message format
that XNU exposes to userspace: the 28-byte header (bits, size, remote/local
ports, voucher, id) plus inline port descriptors, out-of-line (OOL) memory
descriptors and trailing payload.

This is a *model*, not a kernel interface: it exists so campaigns can exercise
kernel-boundary parsing logic (descriptor accounting, region bounds,
right-type validation) entirely in-process on CI-safe mock targets. Field
semantics mirror XNU closely enough that generated messages are realistic
inputs for structure-aware mutation.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

HEADER_FMT = "<7I"           # bits, size, remote, local, voucher, id, pad
HEADER_SIZE = struct.calcsize(HEADER_FMT)          # 28 bytes
COMPLEX_FLAG = 0x80000000                          # MACH_MSG_TYPE_BIT complex
PORT_COUNT_MASK = 0x0000FF00                       # port descriptor count
OOL_COUNT_MASK = 0x000000FF                        # OOL descriptor count
PORT_RIGHT_LIMIT = 16                              # sane send-right budget

DESC_PORT = 0x00                                    # port right descriptor
DESC_OOL = 0x01                                     # out-of-line memory

MACH_MSG_SUCCESS = 0x0


class MachMessageError(ValueError):
    """Raised when fields cannot be packed into a valid message."""


@dataclass
class PortDescriptor:
    name: int = 0
    kind: int = DESC_PORT


@dataclass
class OOLDescriptor:
    address: int = 0
    size: int = 0
    kind: int = DESC_OOL


@dataclass
class MachMessage:
    bits: int = COMPLEX_FLAG
    remote: int = 1
    local: int = 0
    voucher: int = 0
    msg_id: int = 0
    ports: list[PortDescriptor] = field(default_factory=list)
    ool_regions: list[OOLDescriptor] = field(default_factory=list)
    payload: bytes = b""

    @property
    def complex(self) -> bool:
        return bool(self.bits & COMPLEX_FLAG)

    def to_dict(self) -> dict:
        return {
            "bits": self.bits, "complex": self.complex,
            "remote": self.remote, "local": self.local,
            "voucher": self.voucher, "id": self.msg_id,
            "ports": [p.name for p in self.ports],
            "ool_sizes": [o.size for o in self.ool_regions],
            "payload_size": len(self.payload),
        }


def pack(msg: MachMessage) -> bytes:
    """Serialize a message. Raises :class:`MachMessageError` on bad fields."""
    if msg.complex and (len(msg.ports) + len(msg.ool_regions)) == 0:
        raise MachMessageError(
            "complex message requires at least one descriptor")
    if len(msg.ports) > PORT_RIGHT_LIMIT or len(msg.ool_regions) > 0xFF:
        raise MachMessageError("descriptor counts exceed encodable limits")
    if any(p.name > 0xFFFFFFFF for p in msg.ports):
        raise MachMessageError("port names must fit u32")

    desc_bytes = bytearray()
    for port in msg.ports:
        desc_bytes += struct.pack("<BBI", DESC_PORT, 0, port.name)
    for region in msg.ool_regions:
        desc_bytes += struct.pack("<BBII", DESC_OOL, 0,
                                  min(region.size, 0xFFFFFFFF),
                                  region.address)

    body = bytes(desc_bytes) + msg.payload
    size = HEADER_SIZE + len(body)
    if size > 0xFFFF:
        raise MachMessageError("message too large for u32 size field model")

    bits = msg.bits & ~(PORT_COUNT_MASK | OOL_COUNT_MASK)
    if msg.complex:
        bits |= ((len(msg.ports) & 0xFF) << 8) | (len(msg.ool_regions) & 0xFF)
    header = struct.pack(HEADER_FMT, bits, size, msg.remote, msg.local,
                         msg.voucher, msg.msg_id & 0xFFFFFFFF, 0)
    return header + body


# --- parse / validate ---------------------------------------------------------
_PARSE_OK = "ok"


def parse(data: bytes) -> tuple[int, str, MachMessage | None]:
    """Parse raw bytes -> ``(status_code, detail, message_or_None)``.

    Status codes are stable strings used as outcome evidence by targets:
    ok, err_short_header, err_size_underflow, err_complex_empty,
    err_descriptor_bounds, err_ool_overflow, err_right_overflow,
    err_truncated_body.
    """
    if len(data) < HEADER_SIZE:
        return "err_short_header", "fewer than 28 header bytes", None

    bits, size, remote, local, voucher, msg_id, _pad = \
        struct.unpack_from(HEADER_FMT, data, 0)
    if size < HEADER_SIZE:
        return "err_size_underflow", f"declared size {size} < header", None
    if size > len(data):
        return "err_truncated_body", \
            f"declared size {size} exceeds buffer {len(data)}", None

    body = data[HEADER_SIZE:size]
    msg = MachMessage(bits=bits, remote=remote, local=local,
                      voucher=voucher, msg_id=msg_id)

    if not bits & COMPLEX_FLAG:
        msg.payload = body
        return _PARSE_OK, "simple message", msg

    n_ports = (bits & PORT_COUNT_MASK) >> 8
    n_ool = bits & OOL_COUNT_MASK
    total = n_ports + n_ool
    if total == 0:
        return "err_complex_empty", "complex bit set without descriptors", None

    offset = 0
    for _ in range(n_ports):
        if offset + 6 > len(body):
            return "err_descriptor_bounds", "port descriptor overruns body", None
        kind, _r, name = struct.unpack_from("<BBI", body, offset)
        if kind != DESC_PORT:
            return "err_descriptor_bounds", \
                f"expected port descriptor tag {DESC_PORT:#x}", None
        msg.ports.append(PortDescriptor(name=name))
        offset += 6
    if n_ports > PORT_RIGHT_LIMIT:
        return "err_right_overflow", \
            f"{n_ports} port rights exceed limit {PORT_RIGHT_LIMIT}", None

    for _ in range(n_ool):
        if offset + 10 > len(body):
            return "err_descriptor_bounds", "OOL descriptor overruns body", None
        kind, _r, rsize, addr = struct.unpack_from("<BBII", body, offset)
        if kind != DESC_OOL:
            return "err_descriptor_bounds", \
                f"expected OOL descriptor tag {DESC_OOL:#x}", None
        offset += 10
        if offset + rsize > len(body):
            return "err_ool_overflow", \
                f"OOL region {rsize} exceeds remaining {len(body)-offset}", None
        msg.ool_regions.append(OOLDescriptor(address=addr, size=rsize))

    msg.payload = body[offset:]
    return _PARSE_OK, "complex message", msg
