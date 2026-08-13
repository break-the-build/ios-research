"""Shared structure-aware mutators used by targets.

Kept separate so targets can reuse them without import cycles.
"""

from __future__ import annotations

from .. import mutation


def mock_record(data: bytes, rng) -> bytes:
    return mutation.mutate_structure_aware(data, rng)


def audio(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock audio container.

    Container layout after ``magic``::

        [declared_length u16 BE][channels u8][codec u8][payload...]

    Edits steer the header toward the shared audio defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"body"
    declared = len(payload)
    channels = 2
    codec = 1
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        declared = 0xFFFF
    elif choice == 1:    # zero channels -> integer/divide error
        channels = 0
    elif choice == 2:    # use-after-free marker
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 3:    # codec type confusion
        codec = 0xC0
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # assertion path codec
        codec = 0x7E
    header = declared.to_bytes(2, "big") + bytes([channels & 0xFF, codec & 0xFF])
    return magic + header + payload
