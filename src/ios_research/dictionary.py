"""Fuzzing dictionaries: portable token formats, discovery, and provenance.

A *dictionary* is a bounded list of tokens (magic values, tags, version gates,
length constants) that the mutator can insert or overwrite into inputs. This
closes the gap where generic byte mutation has to guess multi-byte parser
constants (issue #30).

Supported on-disk format (libFuzzer-compatible subset):

    # full-line comment
    // also a comment
    png_magic="\x89PNG\r\n\x1a\n"
    jpeg_soi="\xFF\xD8"
    bare_token="MOBC"

Escapes: ``\\xNN``, ``\\\\``, ``\\"``, ``\\n``, ``\\r``, ``\\t``. Tokens are
validated (bounded count/size) and canonically ordered so a given dictionary
file always yields an identical, deterministic token list.

Discovery builds candidate tokens from authorized local artifacts such as seed
corpora; discovered tokens carry their provenance and never leave the machine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .errors import ValidationError

MAX_TOKENS = 4096
MAX_TOKEN_LENGTH = 128
MAX_NAME_LENGTH = 64

_NAME = r"[A-Za-z0-9_.\-]{1,%d}" % MAX_NAME_LENGTH
_LINE = re.compile(
    r"^(?:(?P<name>%s)\s*=\s*)?" % _NAME + r'"(?P<value>(?:[^"\\]|\\.)*)"$')
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}


@dataclass(frozen=True)
class DictionaryToken:
    """One dictionary entry. ``name`` may be empty for anonymous tokens."""

    name: str
    value: bytes
    origin: str = "dictionary"       # dictionary | discovery:<source>
    source: str = ""                 # file path or corpus id (provenance)

    def to_dict(self) -> dict:
        return {"name": self.name,
                "hex": self.value.hex(),
                "origin": self.origin,
                "source": self.source}


def _unescape(body: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.extend(ch.encode("utf-8"))
            i += 1
            continue
        if i + 1 >= len(body):
            raise ValidationError("dictionary escape at end of line")
        nxt = body[i + 1]
        if nxt == "x":
            hex_part = body[i + 2:i + 4]
            if len(hex_part) != 2 or not re.fullmatch(r"[0-9a-fA-F]{2}", hex_part):
                raise ValidationError(f"invalid \\xNN escape near '{body[i:]}'")
            out.append(int(hex_part, 16))
            i += 4
            continue
        if nxt not in _ESCAPES:
            raise ValidationError(f"unsupported escape '\\{nxt}'")
        out.extend(_ESCAPES[nxt].encode("ascii"))
        i += 2
    return bytes(out)


def parse_dictionary(text: str, *, source: str = "") -> list[DictionaryToken]:
    """Parse dictionary text into validated tokens (deterministic order)."""
    tokens: list[DictionaryToken] = []
    seen_names: set[str] = set()
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        match = _LINE.match(line)
        if match is None:
            raise ValidationError(
                f"invalid dictionary line {lineno}: expected name=\"value\"")
        name = match.group("name") or ""
        try:
            value = _unescape(match.group("value"))
        except ValidationError as exc:
            raise ValidationError(f"dictionary line {lineno}: {exc.message}") from exc
        if not value:
            raise ValidationError(f"dictionary line {lineno}: empty token")
        if len(value) > MAX_TOKEN_LENGTH:
            raise ValidationError(
                f"dictionary line {lineno}: token exceeds "
                f"{MAX_TOKEN_LENGTH} bytes")
        if name and name in seen_names:
            raise ValidationError(
                f"dictionary line {lineno}: duplicate token name '{name}'")
        if name:
            seen_names.add(name)
        tokens.append(DictionaryToken(name=name, value=value, source=source))
        if len(tokens) > MAX_TOKENS:
            raise ValidationError(
                f"dictionary exceeds {MAX_TOKENS} tokens")
    return tokens


def load_dictionary(path: str | Path) -> list[DictionaryToken]:
    """Load and validate a dictionary file."""
    path = Path(path)
    if not path.is_file():
        raise ValidationError(f"dictionary file not found: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValidationError(f"cannot read dictionary {path}: {exc}") from exc
    return parse_dictionary(text, source=str(path))


def tokens_to_records(tokens: list[DictionaryToken]) -> list[dict]:
    """Serialize tokens for session persistence."""
    return [token.to_dict() for token in tokens]


def tokens_from_records(records: list[dict],
                        source: str = "session") -> list[DictionaryToken]:
    """Rebuild validated tokens from persisted records."""
    tokens: list[DictionaryToken] = []
    seen_names: set[str] = set()
    for record in records or []:
        try:
            value = bytes.fromhex(record["hex"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError("invalid persisted dictionary record") from exc
        name = str(record.get("name", ""))
        if not value or len(value) > MAX_TOKEN_LENGTH:
            raise ValidationError("persisted dictionary token out of bounds")
        if name and name in seen_names:
            raise ValidationError(f"duplicate persisted token name '{name}'")
        seen_names.add(name)
        tokens.append(DictionaryToken(
            name=name, value=value,
            origin=str(record.get("origin", "dictionary")),
            source=str(record.get("source", source))))
    if len(tokens) > MAX_TOKENS:
        raise ValidationError(f"dictionary exceeds {MAX_TOKENS} tokens")
    return tokens


# --- discovery ---------------------------------------------------------------

_DISCOVERY_RUN = re.compile(rb"[A-Za-z0-9_\-\x80-\xff]{4,16}")
_MAX_DISCOVERY_SOURCES = 64


def discover_tokens(sources: list[bytes], *, source_name: str = "seeds",
                    limit: int = 256) -> list[DictionaryToken]:
    """Extract candidate tokens from authorized local byte sources.

    Deterministic: candidates are ordered by (descending frequency across
    sources, then ascending value). Only runs of 4..16 non-space bytes are
    considered, capped at ``limit`` entries. Provenance records the caller-
    supplied ``source_name`` so lineage shows where a token came from.
    """
    if limit > MAX_TOKENS:
        limit = MAX_TOKENS
    counts: dict[bytes, int] = {}
    for blob in list(sources)[:_MAX_DISCOVERY_SOURCES]:
        for run in set(_DISCOVERY_RUN.findall(blob)):
            counts[run] = counts.get(run, 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [DictionaryToken(name="", value=value,
                            origin=f"discovery:{source_name}",
                            source=source_name)
            for value, _count in ordered[:limit]]
