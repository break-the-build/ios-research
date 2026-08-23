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

_SEEDS = {
    "imageio": [_PNG_1x1, _GIF_1x1, _BMP_2x2, _TIFF, _ICO],
    "audiotoolbox": [_wav(), _AIFF],
    "coregraphics": [_PNG_1x1, b"%PDF-1.4\n%%EOF\n", bytes(64)],
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


def structure_mutate(key: str, data: bytes, rng) -> bytes | None:
    """Format-aware mutation; returns None to fall back to generic mutation."""
    if data[:len(_PNG_MAGIC)] == _PNG_MAGIC:
        return _mutate_png(data, rng)
    return None
