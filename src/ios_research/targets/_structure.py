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


def bluetooth(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock Bluetooth frame.

    Frame layout after ``magic``::

        [declared_length u16 BE][pkt_type u8][handle_flags u8][payload...]

    Edits steer the header toward the shared Bluetooth defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    pkt_type = 1
    flags = 0
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        declared = 0xFFFF
    elif choice == 1:    # null connection handle -> NULL_DEREFERENCE
        pkt_type = 0x00
    elif choice == 2:    # fragment-reassembly flag -> use-after-free
        flags |= 0x01
    elif choice == 3:    # PDU type confusion
        pkt_type = 0xC0
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # assertion path packet type
        pkt_type = 0x7E
    header = declared.to_bytes(2, "big") + bytes([pkt_type & 0xFF, flags & 0xFF])
    return magic + header + payload


def wifi(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock Wi-Fi management frame.

    Frame layout after ``magic``::

        [declared_length u16 BE][frame_subtype u8][ie_count u8][payload...]

    Edits steer the header toward the shared Wi-Fi defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    subtype = 1
    ie_count = 2
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        declared = 0xFFFF
    elif choice == 1:    # zero element count -> integer/divide error
        ie_count = 0
    elif choice == 2:    # reclaimed-buffer marker -> use-after-free
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 3:    # frame subtype confusion
        subtype = 0xC0
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # assertion path subtype
        subtype = 0x7E
    header = declared.to_bytes(2, "big") + bytes([subtype & 0xFF, ie_count & 0xFF])
    return magic + header + payload


def nfc(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock NDEF-style message.

    Message layout after ``magic``::

        [declared_length u16 BE][record_tnf u8][id_length u8][payload...]

    Edits steer the header toward the shared NFC defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    tnf = 1
    id_length = 0
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        declared = 0xFFFF
    elif choice == 1:    # oversized ID length -> OOB write in record-ID copy
        id_length = 0xFF
    elif choice == 2:    # unknown TNF -> type confusion
        tnf = 0x06
    elif choice == 3:    # empty TNF with non-zero ID -> assertion path
        tnf = 0x00
        id_length = 4
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # keep valid; exercises generic mutation fallback
        pass
    header = declared.to_bytes(2, "big") + bytes([tnf & 0xFF, id_length & 0xFF])
    return magic + header + payload


def messaging(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock message envelope (#85).

    Envelope layout after ``magic``::

        [declared_length u16 BE][part_count u8][encoding u8][payload...]

    Edits steer the header toward the shared messaging defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    part_count = 1
    encoding = 1
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        # kept below the 0xF000 timeout gate so this path stays reachable
        # (unlike earlier modules' 0xFFFF choice, which times out first)
        declared = 0x00FF
    elif choice == 1:    # zero part count -> integer/divide error
        part_count = 0
    elif choice == 2:    # released-buffer marker -> use-after-free
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 3:    # decoder-state type confusion
        encoding = 0xC0
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # assertion path encoding
        encoding = 0x7E
    header = declared.to_bytes(2, "big") + bytes([part_count & 0xFF,
                                                  encoding & 0xFF])
    return magic + header + payload


def locked_device(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock locked-device record (#86).

    Record layout after ``magic``::

        [declared_length u16 BE][record_type u8][flags u8][payload...]

    Edits steer the header toward the shared locked-device defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    record_type = 1
    flags = 0
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        # kept below the 0xF000 timeout gate so this path stays reachable
        declared = 0x00FF
    elif choice == 1:    # compressed flag without zero terminator -> integer
        flags = 0x80
        payload = b"\xff" * len(payload) or b"\xff"
        declared = len(payload)
    elif choice == 2:    # released-buffer marker -> use-after-free
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 3:    # privileged record-type confusion
        record_type = 0xC0
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # assertion path record type
        record_type = 0x7E
    header = declared.to_bytes(2, "big") + bytes([record_type & 0xFF,
                                                  flags & 0xFF])
    return magic + header + payload
def netip(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock IP-stack message.

    Message layout after ``magic``::

        [declared_length u16 BE][rr_type u8][opt_flags u8][payload...]

    Edits steer toward the shared netip defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    rr_type = 1
    opt_flags = 2
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        declared = 0xFFFF
    elif choice == 1:    # zero rr_type -> null rdata pointer dereference
        rr_type = 0x00
    elif choice == 2:    # decompression flag -> use-after-free
        opt_flags |= 0x01
    elif choice == 3:    # rr-type confusion
        rr_type = 0xC0
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # assertion path rr_type
        rr_type = 0x7E
    header = declared.to_bytes(2, "big") + bytes([rr_type & 0xFF,
                                                  opt_flags & 0xFF])
    return magic + header + payload
def wifiaware(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock Wi-Fi Aware frame (#103).

    Frame layout after ``magic``::

        [declared_length u16 BE][attr_id u8][tlv_count u8][payload...]

    Edits steer the header toward the shared Wi-Fi Aware defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    attr_id = 1
    tlv_count = 3
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        declared = 0xFFFF
    elif choice == 1:    # zero TLV count -> integer/divide error
        tlv_count = 0
    elif choice == 2:    # reclaimed-buffer marker -> use-after-free
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 3:    # attribute type confusion
        attr_id = 0xC0
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # assertion path attribute id
        attr_id = 0x7E
    header = declared.to_bytes(2, "big") + bytes([attr_id & 0xFF,
                                                  tlv_count & 0xFF])
    return magic + header + payload
def pq3(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock PQ3 transcript message (#104).

    Message layout after ``magic``::

        [declared_length u16 BE][epoch u16 BE][msg_type u8][payload...]

    Edits steer the header toward the shared PQ3 defect paths.
    """
    payload = data[len(magic) + 5:] if len(data) > len(magic) + 5 else b"data"
    declared = len(payload)
    epoch = 1
    msg_type = 1
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read in transcript copy
        declared = 0xFFFF
    elif choice == 1:    # zero message type -> null epoch-state dereference
        msg_type = 0x00
    elif choice == 2:    # maximum-epoch sentinel -> integer wrap in ratchet state
        epoch = 0xFFFF
    elif choice == 3:    # stale-epoch replay marker -> use-after-free
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # epoch-invariant assertion message type
        msg_type = 0x7E
    header = declared.to_bytes(2, "big") + epoch.to_bytes(2, "big") + \
        bytes([msg_type & 0xFF])
    return magic + header + payload
def continuity(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock Continuity beacon record.

    Record layout after ``magic``::

        [declared_length u16 BE][rec_type u8][rec_flags u8][payload...]

    Edits steer the header toward the shared Continuity defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    rec_type = 1
    rec_flags = 0
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        # kept below the 0xF000 timeout gate so this path stays reachable
        declared = 0xFFFF
    elif choice == 1:    # null record type -> NULL_DEREFERENCE
        rec_type = 0x00
    elif choice == 2:    # scaling flag bit -> integer overflow in offsets
        rec_flags |= 0x02
    elif choice == 3:    # reclaimed-buffer marker -> use-after-free
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # assertion path record type
        rec_type = 0x7E
    header = declared.to_bytes(2, "big") + bytes([rec_type & 0xFF,
                                                  rec_flags & 0xFF])
    return magic + header + payload
def ipc(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock IPC envelope (#107).

    Envelope layout after ``magic``::

        [declared_length u16 BE][item_type u8][item_count u8][payload...]

    Edits steer the header toward the shared trust-boundary decode paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    item_type = 1
    item_count = 2
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        declared = 0xFFFF
    elif choice == 1:    # null extension endpoint -> NULL_DEREFERENCE
        item_type = 0x00
    elif choice == 2:    # oversized item count -> fixed-table OOB write
        item_count = 9
    elif choice == 3:    # released-attachment marker -> use-after-free
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # incompatible schema reinterpretation
        item_type = 0xC0
    header = declared.to_bytes(2, "big") + bytes([item_type & 0xFF,
                                                  item_count & 0xFF])
    return magic + header + payload
def xpc(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock XPC/Mach message.

    Message layout after ``magic``::

        [declared_length u16 BE][entry_type u8][entry_count u8][payload...]

    Edits steer the header toward the shared XPC defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    entry_type = 1
    entry_count = 2
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        declared = 0xFFFF
    elif choice == 1:    # entry type 0 -> null connection-context dereference
        entry_type = 0x00
    elif choice == 2:    # zero entry count -> divide-by-zero table scaling
        entry_count = 0
    elif choice == 3:    # released-dictionary marker -> use-after-free
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # typed-slot value confusion
        entry_type = 0xC0
    header = declared.to_bytes(2, "big") + bytes([entry_type & 0xFF,
                                                  entry_count & 0xFF])
    return magic + header + payload
def docimp(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock document container.

    Container layout after ``magic``::

        [declared_length u16 BE][part_class u8][part_flags u8][payload...]

    Edits steer the header toward the shared document-importer defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    part_class = 1
    part_flags = 0
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        declared = 0xFFFF
    elif choice == 1:    # null part class -> NULL_DEREFERENCE
        part_class = 0x00
    elif choice == 2:    # table-expansion flag -> integer error
        part_flags |= 0x04
    elif choice == 3:    # released-buffer marker -> use-after-free
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # schema-state type confusion
        part_class = 0xC0
    header = declared.to_bytes(2, "big") + bytes([part_class & 0xFF,
                                                  part_flags & 0xFF])
    return magic + header + payload
def signeddoc(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock signed document (#110).

    Document layout after ``magic``::

        [declared_length u16 BE][asn1_class u8][der_flags u8][payload...]

    Edits steer the header toward the shared signed-document defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    asn1_class = 1
    der_flags = 0
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        declared = 0xFFFF
    elif choice == 1:    # ASN.1 class 0 -> empty certificate chain dereference
        asn1_class = 0x00
    elif choice == 2:    # indefinite-length DER flag -> length arithmetic overflow
        der_flags |= 0x08
    elif choice == 3:    # released SET-OF marker -> use-after-free
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # OID arc class confusion
        asn1_class = 0xC0
    header = declared.to_bytes(2, "big") + bytes([asn1_class & 0xFF,
                                                  der_flags & 0xFF])
    return magic + header + payload
def proxapp(magic: bytes, data: bytes, rng) -> bytes:
    """Format-aware mutation of the normalized mock proximity record (#111).

    Record layout after ``magic``::

        [declared u16 BE][tlv_type u8][tlv_flags u8][payload...]

    Edits steer the header toward the shared proximity defect paths.
    """
    payload = data[len(magic) + 4:] if len(data) > len(magic) + 4 else b"data"
    declared = len(payload)
    tlv_type = 1
    tlv_flags = 0
    choice = rng.randrange(6)
    if choice == 0:      # oversized declared length -> OOB read
        declared = 0xFFFF
    elif choice == 1:    # copy flag set -> OOB write in TLV copy
        tlv_flags |= 0x01
    elif choice == 2:    # TLV type 0 -> null method-handler dereference
        tlv_type = 0x00
    elif choice == 3:    # released-buffer marker -> use-after-free
        payload = b"\xde\xad" + payload
        declared = len(payload)
    elif choice == 4:    # oversized -> timeout path
        declared = 0xF100
    elif choice == 5:    # session-state type confusion
        tlv_type = 0xC0
    header = declared.to_bytes(2, "big") + bytes([tlv_type & 0xFF,
                                                  tlv_flags & 0xFF])
    return magic + header + payload
