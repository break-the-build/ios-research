"""Deterministic mutation strategies for fuzzing.

All mutation is driven by a seeded RNG so that a given ``(seed, iteration)`` pair
always produces the same mutated input. This underpins reproducible experiments
and deterministic regression tests.

Strategies only *transform inputs*. They never generate exploit payloads; the
goal is to elicit abnormal behavior and crashes from controlled targets.
"""

from __future__ import annotations

import random

# Interesting boundary/integer values commonly implicated in parser defects.
_INTERESTING_BYTES = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]
_INTERESTING_INTS = [0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF]

STRATEGIES = (
    "byte",
    "truncation",
    "insertion",
    "deletion",
    "boundary",
    "integer",
    "structure_aware",
)


def rng_for(seed: int, iteration: int) -> random.Random:
    """Return a deterministic RNG for a specific fuzzing iteration."""
    return random.Random((seed << 32) ^ (iteration * 2654435761 & 0xFFFFFFFF))


def _b(data: bytes) -> bytearray:
    return bytearray(data) if data else bytearray(b"\x00")


def mutate_byte(data: bytes, rng: random.Random) -> bytes:
    out = _b(data)
    for _ in range(rng.randint(1, 4)):
        i = rng.randrange(len(out))
        out[i] ^= 1 << rng.randrange(8)
    return bytes(out)


def mutate_truncation(data: bytes, rng: random.Random) -> bytes:
    if len(data) <= 1:
        return data
    cut = rng.randrange(1, len(data))
    return data[:cut]


def mutate_insertion(data: bytes, rng: random.Random) -> bytes:
    out = _b(data)
    pos = rng.randint(0, len(out))
    chunk = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
    return bytes(out[:pos]) + chunk + bytes(out[pos:])


def mutate_deletion(data: bytes, rng: random.Random) -> bytes:
    if len(data) <= 1:
        return data
    start = rng.randrange(len(data))
    end = min(len(data), start + rng.randint(1, 4))
    return data[:start] + data[end:]


def mutate_boundary(data: bytes, rng: random.Random) -> bytes:
    out = _b(data)
    i = rng.randrange(len(out))
    out[i] = rng.choice(_INTERESTING_BYTES)
    return bytes(out)


def mutate_integer(data: bytes, rng: random.Random) -> bytes:
    out = _b(data)
    width = rng.choice([1, 2, 4])
    if len(out) < width:
        out.extend(b"\x00" * (width - len(out)))
    pos = rng.randrange(0, len(out) - width + 1)
    value = rng.choice(_INTERESTING_INTS) & ((1 << (8 * width)) - 1)
    out[pos:pos + width] = value.to_bytes(width, "big")
    return bytes(out)


def mutate_structure_aware(data: bytes, rng: random.Random) -> bytes:
    """Format-aware mutation of the mock record header.

    Edits the fields the mock parser inspects (magic, version, record type,
    declared length) toward values that exercise its documented defect paths.
    """
    out = bytearray(b"MOCK" + b"\x01\x01" + b"\x00\x02" + b"ok")
    src = _b(data)
    # Preserve some payload from the source if present.
    if len(src) > 8:
        out = bytearray(b"MOCK") + out[4:8] + src[8:]
    else:
        out = bytearray(out)
    choice = rng.randrange(5)
    if choice == 0:  # oversized declared length -> OOB read
        out[6:8] = (0xFFFF).to_bytes(2, "big")
    elif choice == 1:  # null-dispatch record type
        out[5] = 0xFF
    elif choice == 2:  # use-after-free marker in payload
        out = out[:8] + bytearray(b"\xde\xad") + out[8:]
    elif choice == 3:  # version 0 integer underflow
        out[4] = 0x00
    elif choice == 4:  # type confusion tag
        out = out[:8] + bytearray(b"\x7fT") + out[8:]
    return bytes(out)


_DISPATCH = {
    "byte": mutate_byte,
    "truncation": mutate_truncation,
    "insertion": mutate_insertion,
    "deletion": mutate_deletion,
    "boundary": mutate_boundary,
    "integer": mutate_integer,
    "structure_aware": mutate_structure_aware,
}


def mutate(data: bytes, seed: int, iteration: int,
           strategies: tuple[str, ...] = STRATEGIES) -> tuple[bytes, str]:
    """Deterministically mutate ``data`` for ``(seed, iteration)``.

    Returns ``(mutated_bytes, strategy_name)``.
    """
    rng = rng_for(seed, iteration)
    strategy = strategies[rng.randrange(len(strategies))]
    return _DISPATCH[strategy](data, rng), strategy
