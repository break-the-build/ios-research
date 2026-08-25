"""Format-aware seeds and structure mutation for the mac-native targets.

A real decode target is far more productive when seeded with *valid* container
inputs and mutated in a structure-aware way (perturbing length/size fields and
chunk boundaries) rather than flipping random bytes in random noise. These seeds
are tiny, well-formed containers; the mutators steer toward the size/offset math
that image and audio decoders are historically fragile around.

Authorized-research note: these only shape *input bytes*; they never generate an
exploit payload.
"""

from __future__ import annotations

import base64
import struct
import zlib

# --- tiny valid seeds ------------------------------------------------------

# 1x1 PNG (opaque), 8-bit RGBA.
_PNG_1x1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC")
# 1x1 GIF87a.
_GIF_1x1 = (b"GIF87a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff,"
            b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
# 2x2 24-bit BMP.
_BMP_2x2 = bytes.fromhex(
    "424d3a0000000000000036000000280000000200000002000000010018000000"
    "0000040000001300000013000000000000000000000000ff0000ff0000000000"
    "ffffff00ffffff000000")
# Little-endian TIFF header (magic + first-IFD offset), padded.
_TIFF = b"II*\x00\x08\x00\x00\x00" + b"\x00" * 24
# 16x16 1-bpp ICO with a BMP DIB payload header.
_ICO = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00" + b"\x00" * 40


def _wav(pcm: bytes = b"\x00\x00\x00\x00") -> bytes:
    """Minimal 8kHz mono 16-bit PCM WAV."""
    data_chunk = b"data" + struct.pack("<I", len(pcm)) + pcm
    fmt = b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, 8000, 16000, 2, 16)
    body = b"WAVE" + fmt + data_chunk
    return b"RIFF" + struct.pack("<I", len(body)) + body


_AIFF = (b"FORM" + struct.pack(">I", 4) + b"AIFF")

# Tiny Annex-B elementary-stream fragments for the VideoToolbox target.  These
# are deliberately self-contained fixtures, derived from the public H.264/AVC
# and H.265/HEVC NAL-unit framing specifications: a four-byte start code plus
# parameter-set / IDR headers and short payloads.  They are not complete media
# files; keeping them small lets mutations exercise parameter-set parsing and
# rejection paths without shipping third-party media samples.
_H264_ANNEX_B = (
    b"\x00\x00\x00\x01\x67\x42\x00\x1e\xf4\x0b\x04\xb2"
    b"\x00\x00\x00\x01\x68\xce\x06\xe2"
    b"\x00\x00\x00\x01\x65\x88\x84\x00")
_HEVC_ANNEX_B = (
    b"\x00\x00\x00\x01\x40\x01\x0c\x01\xff"
    b"\x00\x00\x00\x01\x42\x01\x01\x01\x60"
    b"\x00\x00\x00\x01\x44\x01\xc0\x73\xc0"
    b"\x00\x00\x00\x01\x26\x01\xaf")

def _sfnt(tables: list[tuple[bytes, bytes]], sfnt_version: bytes = b"\x00\x01\x00\x00") -> bytes:
    """Minimal TrueType/OpenType container with the given (tag, payload) tables."""
    head = struct.pack(">IIIIHHqqhhhhHHhhh",
                       0x00010000, 0x00010000, 0, 0x5F0F3CF5, 3, 1000,
                       0, 0, 0, 0, 1000, 1000, 0, 8, 2, 0, 0)
    hhea = struct.pack(">IIHhHHHHHHHhhhhH",
                       0x00010000, 800, 0, 0, 0, 1000, 0, 0, 1, 0, 0, 0,
                       0, 0, 0, 4)
    maxp = struct.pack(">IH", 0x00010000, 4)
    cmap_stub = struct.pack(">HHHHI", 0, 1, 3, 1, 12) + struct.pack(">HHH", 6, 10, 65)
    tables = [(b"head", head), (b"hhea", hhea), (b"maxp", maxp),
              (b"cmap", cmap_stub)] + list(tables)
    n = len(tables)
    entry_selector = max(n.bit_length() - 1, 0)
    header_size = 12 + 16 * n
    offset = header_size
    entries: list[bytes] = []
    body: list[bytes] = []
    for tag, payload in tables:
        pad = (-len(payload)) % 4
        entries.append(tag + b"\x00\x00" + struct.pack(">III", 0, offset, len(payload)))
        body.append(payload + b"\x00" * pad)
        offset += len(payload) + pad
    return sfnt_version + struct.pack(">HHH", n, 16, entry_selector * 16) \
        + b"".join(entries) + b"".join(body)


_SEEDS = {
    "imageio": [_PNG_1x1, _GIF_1x1, _BMP_2x2, _TIFF, _ICO],
    "audiotoolbox": [_wav(), _AIFF],
    "videotoolbox": [_H264_ANNEX_B, _HEVC_ANNEX_B],
    "coregraphics": [_PNG_1x1, b"%PDF-1.4\n%%EOF\n", bytes(64)],
    "coretext": [
        _sfnt([]),                                        # bare valid sfnt
        _sfnt([(b"glyf", b"\x00\x00\x00\x00"),
               (b"loca", b"\x00\x00\x00\x00\x00\x00")]),
        b"OTTO" + b"\x00" * 60,                           # CFF-flavoured stub
        b"ttcf" + struct.pack(">II", 0x00010000, 1) + b"\x00" * 52,
    ],
    # Self-test markers trigger the harness's deliberate ASan bugs; the trailing
    # padding gives ddmin something to shrink while preserving the signature.
    "selftest": [b"OOB" + b"." * 24, b"WRT" + b"." * 24,
                 b"UAF" + b"." * 24, b"clean" + b"." * 24],
}


def seeds(key: str) -> list[bytes]:
    return list(_SEEDS.get(key, []))


# --- structure-aware mutation ----------------------------------------------

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def _iter_png_chunks(data: bytes):
    """Yield ``(offset, length, ctype, chunk_bytes)`` for each PNG chunk."""
    pos = len(_PNG_MAGIC)
    n = len(data)
    while pos + 8 <= n:
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8]
        end = pos + 12 + length  # len(4) + type(4) + data(length) + crc(4)
        chunk = data[pos:min(end, n)]
        yield pos, length, ctype, chunk
        if end <= pos or end > n:
            break
        pos = end


def _mutate_png(data: bytes, rng) -> bytes | None:
    chunks = list(_iter_png_chunks(data))
    if not chunks:
        return None
    pos, length, ctype, _chunk = rng.choice(chunks)
    out = bytearray(data)
    choice = rng.randrange(4)
    if choice == 0:
        # Corrupt the declared chunk length -> steers size/offset math.
        new_len = rng.choice([0, length + 1, 0x7FFFFFFF, 0xFFFFFFFF])
        out[pos:pos + 4] = int(new_len & 0xFFFFFFFF).to_bytes(4, "big")
    elif choice == 1 and length > 0:
        # Flip a byte inside the chunk payload.
        i = pos + 8 + rng.randrange(length)
        if i < len(out):
            out[i] ^= 1 << rng.randrange(8)
    elif choice == 2:
        # Break the CRC (last 4 bytes of the chunk) if present.
        crc_at = pos + 8 + length
        if crc_at + 4 <= len(out):
            out[crc_at] ^= 0xFF
    else:
        # Mangle the chunk type tag (e.g. IHDR -> IHDX) to hit unknown paths.
        out[pos + 7] ^= 0x01
    return bytes(out)


_SFNT_TAGS = (b"glyf", b"loca", b"head", b"hhea", "hmtx".encode(), b"maxp",
              b"name", b"post", b"CFF ", b"cmap", b"fvar", b"gvar",
              b"GSUB", b"GPOS", b"kern", b"morx")


def _mutate_sfnt(data: bytes, rng) -> bytes | None:
    """Perturb sfnt table directory / size fields to stress offset math."""
    if len(data) < 12:
        return None
    out = bytearray(data)
    num_tables = int.from_bytes(out[4:6], "big")
    choice = rng.randrange(4)
    if choice == 0 and num_tables:
        # Corrupt a table entry's offset/length pair.
        i = rng.randrange(num_tables)
        base = 12 + 16 * i
        if base + 16 <= len(out):
            field = rng.randrange(2)
            pos = base + 8 + 4 * field
            new = rng.choice([0, 1, 0x7FFFFFFF, 0xFFFFFFFF])
            out[pos:pos + 4] = int(new).to_bytes(4, "big")
    elif choice == 1:
        # Cap at 0xFFFF: a corrupted num_tables must not overflow the field.
        out[4:6] = rng.choice([0, 1, min(num_tables + 1, 0xFFFF),
                               0xFFFF]).to_bytes(2, "big")
    elif choice == 2 and len(out) > 20:
        i = 12 + rng.randrange(len(out) - 12)
        out[i] ^= 1 << rng.randrange(8)
    else:
        # Splice a plausible table tag over an existing one.
        tag = _SFNT_TAGS[rng.randrange(len(_SFNT_TAGS))]
        if len(out) >= 20:
            i = rng.randrange(max(1, min(8, len(out) - 4)))
            out[i:i + 4] = tag
    return bytes(out)


def structure_mutate(key: str, data: bytes, rng) -> bytes | None:
    """Format-aware mutation; returns None to fall back to generic mutation."""
    if data[:len(_PNG_MAGIC)] == _PNG_MAGIC:
        return _mutate_png(data, rng)
    magic4 = data[:4]
    if magic4 in (b"\x00\x01\x00\x00", b"OTTO", b"true", b"ttcf"):
        return _mutate_sfnt(data, rng)
    return None
