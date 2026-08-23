"""Fixture mutator plugins for the grammar-plugin interface (#41).

Two safe, deterministic example formats:

* ``ChunkedBinPlugin``  — a chunked binary container:
  ``[u16 chunk_count][ (u16 len, bytes payload) ] * chunk_count``
* ``NestedTlvPlugin``   — a nested TLV structure:
  ``[type u8][len u8][value]`` where value may itself contain nested TLVs.

They exist so tests can prove the interface contract without user code and so
researchers have reference implementations. They perform no I/O.
"""

from __future__ import annotations

import random
import struct


class ChunkedBinPlugin:
    plugin_id = "chunked-bin"
    version = "1.0.0"

    MAX_CHUNKS = 256
    MAX_CHUNK_LEN = 4096

    def parse(self, data: bytes):
        if len(data) < 2:
            return None
        (count,) = struct.unpack_from(">H", data, 0)
        chunks = []
        offset = 2
        for _ in range(min(count, self.MAX_CHUNKS)):
            if offset + 2 > len(data):
                break
            (length,) = struct.unpack_from(">H", data, offset)
            offset += 2
            payload = data[offset:offset + length]
            offset += length
            chunks.append(payload)
        return {"chunks": chunks}

    def generate(self, rng: random.Random):
        count = rng.randint(1, 4)
        return {"chunks": [bytes(rng.randrange(256)
                                for _ in range(rng.randint(0, 16)))
                           for _ in range(count)]}

    def mutate(self, node, rng: random.Random):
        chunks = list(node["chunks"])
        if not chunks:
            return None
        choice = rng.randrange(5)
        if choice == 0 and len(chunks) > 1:          # drop a chunk
            del chunks[rng.randrange(len(chunks))]
        elif choice == 1:                            # truncate a chunk
            i = rng.randrange(len(chunks))
            cut = rng.randrange(0, len(chunks[i]) + 1)
            chunks[i] = chunks[i][:cut]
        elif choice == 2:                            # duplicate a chunk
            i = rng.randrange(len(chunks))
            chunks.insert(rng.randrange(len(chunks) + 1), chunks[i])
        elif choice == 3:                            # flip a byte
            i = rng.randrange(len(chunks))
            blob = bytearray(chunks[i]) or bytearray(b"\x00")
            pos = rng.randrange(len(blob))
            blob[pos] ^= 1 << rng.randrange(8)
            chunks[i] = bytes(blob)
        else:                                        # append a chunk
            chunks.append(bytes(rng.randrange(256)
                                for _ in range(rng.randint(0, 8))))
        return {"chunks": chunks[:self.MAX_CHUNKS]}

    def crossover(self, a, b, rng: random.Random):
        left, right = a["chunks"], b["chunks"]
        if not left or not right:
            return None
        cut = rng.randint(0, len(left))
        merged = left[:cut] + right[cut:]             # structural interleave
        return {"chunks": merged[:self.MAX_CHUNKS]}

    def repair(self, node):
        chunks = [c[:self.MAX_CHUNK_LEN] if isinstance(c, (bytes, bytearray))
                  else b"" for c in node["chunks"]]
        return {"chunks": chunks[:self.MAX_CHUNKS]}

    def serialize(self, node) -> bytes:
        chunks = node["chunks"]
        out = struct.pack(">H", len(chunks))
        for chunk in chunks:
            out += struct.pack(">H", len(chunk)) + chunk
        return out

    def validity_score(self, data: bytes) -> float | None:
        node = self.parse(data)
        if node is None:
            return None
        declared = struct.unpack_from(">H", data, 0)[0]
        found = len(node["chunks"])
        consistent = found == min(declared, self.MAX_CHUNKS)
        return 1.0 if consistent else 0.25


class NestedTlvPlugin:
    plugin_id = "nested-tlv"
    version = "1.0.0"

    MAX_DEPTH = 8
    MAX_VALUE_LEN = 1024

    TYPES = (0x01, 0x02, 0x03)

    def parse(self, data: bytes, _depth: int = 0):
        if not data or _depth > self.MAX_DEPTH:
            return None
        values = []
        offset = 0
        while offset < len(data):
            if offset + 2 > len(data):
                return None
            tlv_type = data[offset]
            length = data[offset + 1]
            offset += 2
            if tlv_type not in self.TYPES:
                return None
            value = data[offset:offset + length]
            if len(value) != length:
                return None
            offset += length
            if tlv_type == 0x03:                      # container: nested TLV
                child = self.parse(value, _depth + 1)
                if child is None:
                    return None
                values.append((tlv_type, child))
            else:
                values.append((tlv_type, value))
        return values

    def generate(self, rng: random.Random, _depth: int = 0):
        items = []
        for _ in range(rng.randint(1, 3)):
            tlv_type = rng.choice(self.TYPES[:2] if _depth >= self.MAX_DEPTH - 1
                                  else self.TYPES)
            if tlv_type == 0x03:
                items.append((0x03, self.generate(rng, _depth + 1)))
            else:
                items.append((tlv_type, bytes(rng.randrange(256)
                                              for _ in range(rng.randint(0, 8)))))
        return items

    def mutate(self, node, rng: random.Random, _depth: int = 0):
        if not node:
            return None
        index = rng.randrange(len(node))
        out = list(node)
        tlv_type, value = out[index]
        choice = rng.randrange(4)
        if choice == 0:                               # drop an element
            del out[index]
        elif tlv_type == 0x03:                        # mutate inside container
            child = self.mutate(value, rng, _depth + 1)
            out[index] = (tlv_type, child if child is not None else value)
        elif choice == 1:                             # truncate scalar
            out[index] = (tlv_type, value[:rng.randrange(len(value) + 1)])
        elif choice == 2:                             # flip a bit
            blob = bytearray(value) or bytearray(b"\x00")
            pos = rng.randrange(len(blob))
            blob[pos] ^= 1 << rng.randrange(8)
            out[index] = (tlv_type, bytes(blob))
        else:                                         # retype scalar <-> type1
            new_type = 0x01 if tlv_type == 0x02 else 0x02
            out[index] = (new_type, value)
        return out

    def crossover(self, a, b, rng: random.Random):
        if not a or not b:
            return None
        cut = rng.randint(0, len(a))
        tail = list(b[max(0, len(b) - rng.randint(0, len(b))):])
        merged = list(a[:cut]) + tail
        return merged[:16]

    def repair(self, node, _depth: int = 0):
        if _depth > self.MAX_DEPTH:
            return []
        repaired = []
        for item in node[:64]:
            try:
                tlv_type, value = item
            except (TypeError, ValueError):
                continue
            if tlv_type not in self.TYPES:
                continue
            if tlv_type == 0x03:
                if not isinstance(value, list):
                    continue
                repaired.append(
                    (0x03, self.repair(value, _depth + 1)))
            else:
                if isinstance(value, (bytes, bytearray)):
                    repaired.append((tlv_type,
                                     bytes(value)[:self.MAX_VALUE_LEN]))
        return repaired

    def serialize(self, node) -> bytes:
        out = bytearray()
        for tlv_type, value in node:
            if tlv_type == 0x03:
                inner = self.serialize(value)
                out.append(tlv_type)
                out.append(min(len(inner), 255))
                out.extend(inner[:255])
            else:
                out.append(tlv_type)
                out.append(len(value))
                out.extend(value)
        return bytes(out)

    def validity_score(self, data: bytes) -> float | None:
        return 1.0 if self.parse(data) is not None else 0.0


CHUNKED_BIN_PLUGIN = ChunkedBinPlugin()
NESTED_TLV_PLUGIN = NestedTlvPlugin()
