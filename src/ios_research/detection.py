"""Defensive detection signatures: a deterministic YARA-style rule engine.

This module detects *known malicious capability combinations* inside binary
samples (for example, spyware-like surveillance plus exfiltration strings).
It is purely analytical: it reads files the researcher points it at and
reports textual/hexadecimal pattern matches. It never creates payloads,
never modifies samples, and never touches other processes or devices.

Rule format (JSON)::

    {
      "schema": 1,
      "rules": [
        {
          "name": "family_example_indicator",
          "family": "example-family",
          "severity": "high",
          "description": "...",
          "meta": {"reference": "..."},
          "filesize": {"min": 0, "max": 10485760},
          "strings": [
            {"id": "$a", "type": "ascii",   "value": "AVCaptureDevice",
             "nocase": false},
            {"id": "$b", "type": "utf16le", "value": "..."},
            {"id": "$c", "type": "hex",     "value": "DE AD ?? BE EF"}
          ],
          "condition": {"at_least": 2, "of": ["$a", "$b", "$c"]}
        }
      ]
    }

Conditions are ``{"all": [...]}``, ``{"any": [...]}``, or
``{"at_least": n, "of": [...]}``. All matching is deterministic: matches are
reported in rule order, then offset order.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .errors import ValidationError
from .hashing import sha256_bytes

SCHEMA_VERSION = 1

# Cap per string id so scans stay bounded and deterministic.
MAX_MATCHES_PER_STRING = 16


@dataclass(frozen=True)
class StringPattern:
    sid: str
    kind: str            # ascii | utf16le | hex
    pattern: bytes       # literal bytes, or hex with b"\x00" placeholders
    mask: bytes | None   # parallel mask for hex wildcards (None = exact)
    nocase: bool = False


@dataclass(frozen=True)
class Rule:
    name: str
    family: str
    severity: str
    description: str
    strings: tuple[StringPattern, ...]
    condition: dict[str, Any]
    filesize_min: int = 0
    filesize_max: int | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StringMatch:
    sid: str
    offset: int

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.sid, "offset": self.offset}


@dataclass(frozen=True)
class RuleMatch:
    rule: str
    family: str
    severity: str
    description: str
    strings: tuple[StringMatch, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "family": self.family,
            "severity": self.severity,
            "description": self.description,
            "strings": [s.to_dict() for s in self.strings],
        }


# ---------------------------------------------------------------------------
# Pattern compilation
# ---------------------------------------------------------------------------

_HEX_PAIR = re.compile(r"^\s*(?:[0-9A-Fa-f]{2}|\?\?)\s*$")


def _parse_hex(value: str) -> tuple[bytes, bytes]:
    """Parse ``"DE AD ?? 0A"`` into ``(pattern, mask)`` byte pairs.

    Mask byte ``0x00`` means wildcard at that position, ``0xFF`` means exact.
    """
    parts = value.split()
    if not parts:
        raise ValueError("empty hex pattern")
    out = bytearray()
    mask = bytearray()
    for part in parts:
        if not _HEX_PAIR.match(part):
            raise ValueError(f"bad hex token '{part}'")
        if part.strip() == "??":
            out.append(0x00)
            mask.append(0x00)
        else:
            out.append(int(part, 16))
            mask.append(0xFF)
    return bytes(out), bytes(mask)


def _compile_string(spec: dict[str, Any]) -> StringPattern:
    sid = spec.get("id", "")
    kind = spec.get("type", "")
    value = spec.get("value")
    if not sid.startswith("$"):
        raise ValueError(f"string id '{sid}' must start with '$'")
    if kind == "ascii":
        if not isinstance(value, str) or not value:
            raise ValueError(f"{sid}: ascii strings need a non-empty value")
        return StringPattern(sid=sid, kind=kind, pattern=value.encode("utf-8"),
                             mask=None,
                             nocase=bool(spec.get("nocase", False)))
    if kind == "utf16le":
        if not isinstance(value, str) or not value:
            raise ValueError(f"{sid}: utf16le strings need a non-empty value")
        return StringPattern(sid=sid, kind=kind,
                             pattern=value.encode("utf-16-le"), mask=None)
    if kind == "hex":
        if not isinstance(value, str):
            raise ValueError(f"{sid}: hex strings need a text value")
        try:
            pattern, mask = _parse_hex(value)
        except ValueError as exc:
            raise ValueError(f"{sid}: {exc}") from None
        return StringPattern(sid=sid, kind=kind, pattern=pattern, mask=mask)
    raise ValueError(f"{sid}: unsupported string type '{kind}'")


def _find_all(data: bytes, pat: StringPattern) -> list[int]:
    """Return up to MAX_MATCHES_PER_STRING match offsets, ascending."""
    hay = data
    needle = pat.pattern
    if pat.nocase:
        hay = hay.lower()
        needle = needle.lower()
    offsets: list[int] = []
    start = 0
    while len(offsets) < MAX_MATCHES_PER_STRING:
        idx = hay.find(needle, start)
        if idx < 0:
            break
        if pat.mask is None:
            offsets.append(idx)
        else:
            end = idx + len(pat.mask)
            if end <= len(data):
                window = data[idx:end]
                if all(m == 0 or (w & m) == p
                       for w, m, p in zip(window, pat.mask, pat.pattern)):
                    offsets.append(idx)
        start = idx + 1
    return offsets


# ---------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------

def _eval_condition(condition: dict[str, Any], hits: dict[str, bool],
                    rule_name: str) -> bool:
    if not isinstance(condition, dict) or not condition:
        raise ValidationError(
            f"rule '{rule_name}': condition must be a non-empty object")
    keys = set(condition)
    if keys == {"all"}:
        items = condition["all"]
        if not isinstance(items, list):
            raise ValidationError(f"rule '{rule_name}': 'all' takes a list")
        return all(_eval_atom(i, hits, rule_name) for i in items)
    if keys == {"any"}:
        items = condition["any"]
        if not isinstance(items, list):
            raise ValidationError(f"rule '{rule_name}': 'any' takes a list")
        return any(_eval_atom(i, hits, rule_name) for i in items)
    if keys == {"at_least", "of"}:
        n, items = condition["at_least"], condition["of"]
        if not isinstance(n, int) or not isinstance(items, list) or n < 0:
            raise ValidationError(
                f"rule '{rule_name}': need integer 'at_least' and list 'of'")
        return sum(_eval_atom(i, hits, rule_name)
                   for i in items) >= n
    raise ValidationError(
        f"rule '{rule_name}': unsupported condition form {sorted(keys)}")


def _eval_atom(item: Any, hits: dict[str, bool], rule_name: str) -> bool:
    if isinstance(item, dict):
        return _eval_condition(item, hits, rule_name)
    if not isinstance(item, str):
        raise ValidationError(f"rule '{rule_name}': condition items must be "
                              f"string ids or nested conditions")
    if item not in hits:
        raise ValidationError(
            f"rule '{rule_name}': condition references unknown string "
            f"'{item}'")
    return hits[item]


# ---------------------------------------------------------------------------
# Ruleset loading and validation
# ---------------------------------------------------------------------------

def parse_rules(doc: dict[str, Any], *, source: str = "<memory>") -> list[Rule]:
    """Parse and validate a rules document; raises :class:`ValidationError`."""
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA_VERSION:
        raise ValidationError(
            f"{source}: rules document must have \"schema\": {SCHEMA_VERSION}")
    raw_rules = doc.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ValidationError(f"{source}: 'rules' must be a non-empty list")
    seen_names: set[str] = set()
    rules: list[Rule] = []
    for i, raw in enumerate(raw_rules):
        where = f"{source}: rules[{i}]"
        if not isinstance(raw, dict):
            raise ValidationError(f"{where}: rule must be an object")
        name = raw.get("name", "")
        if not name or not re.fullmatch(r"[a-z0-9_]+", name):
            raise ValidationError(
                f"{where}: 'name' must be snake_case, got '{name}'")
        if name in seen_names:
            raise ValidationError(f"{where}: duplicate rule name '{name}'")
        seen_names.add(name)
        severity = raw.get("severity", "info")
        if severity not in ("info", "low", "medium", "high", "critical"):
            raise ValidationError(f"{where}: invalid severity '{severity}'")
        raw_strings = raw.get("strings")
        if not isinstance(raw_strings, list) or not raw_strings:
            raise ValidationError(f"{where} ({name}): needs 'strings'")
        compiled: list[StringPattern] = []
        seen_ids: set[str] = set()
        for spec in raw_strings:
            if not isinstance(spec, dict):
                raise ValidationError(f"{where} ({name}): string must be object")
            try:
                sp = _compile_string(spec)
            except ValueError as exc:
                raise ValidationError(f"{where} ({name}): {exc}") from None
            if sp.sid in seen_ids:
                raise ValidationError(
                    f"{where} ({name}): duplicate string id '{sp.sid}'")
            seen_ids.add(sp.sid)
            compiled.append(sp)
        condition = raw.get("condition")
        size = raw.get("filesize") or {}
        if not isinstance(size, dict):
            raise ValidationError(f"{where} ({name}): 'filesize' must be object")
        fmin = size.get("min", 0)
        fmax = size.get("max")
        if not isinstance(fmin, int) or fmin < 0 or \
                (fmax is not None and not isinstance(fmax, int)):
            raise ValidationError(f"{where} ({name}): bad filesize bounds")
        rule = Rule(
            name=name,
            family=str(raw.get("family", "unknown")),
            severity=severity,
            description=str(raw.get("description", "")),
            strings=tuple(compiled),
            condition=condition if isinstance(condition, dict) else {},
            filesize_min=fmin,
            filesize_max=fmax,
            meta=dict(raw.get("meta") or {}),
        )
        # Validate condition references eagerly (against this rule's ids).
        _validate_condition(rule)
        rules.append(rule)
    return rules


def _validate_condition(rule: Rule) -> None:
    known = {sp.sid for sp in rule.strings}

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if isinstance(node, dict):
            sub = next(iter(node), None)
            if sub not in ("all", "any", "at_least"):
                raise ValidationError(
                    f"rule '{rule.name}': malformed nested condition "
                    f"{sorted(node)}")
            if sub == "at_least" and "of" not in node:
                raise ValidationError(
                    f"rule '{rule.name}': 'at_least' requires 'of'")
            walk(node.get(sub))
            return
        if isinstance(node, str):
            if node not in known:
                raise ValidationError(
                    f"rule '{rule.name}': condition references unknown "
                    f"string '{node}'")
            return
        raise ValidationError(
            f"rule '{rule.name}': malformed condition entry {node!r}")

    cond = rule.condition
    if not cond:
        raise ValidationError(
            f"rule '{rule.name}': missing 'condition'")
    key = next(iter(cond))
    if key not in ("all", "any"):
        if key != "at_least" or "of" not in cond:
            raise ValidationError(
                f"rule '{rule.name}': unsupported condition form "
                f"{sorted(cond)}")
        if not isinstance(cond.get("at_least"), int):
            raise ValidationError(
                f"rule '{rule.name}': 'at_least' must be an integer")
        walk(cond.get("of"))
        return
    walk(cond.get(key))


def load_rules(path: str) -> list[Rule]:
    with open(path, "r", encoding="utf-8") as fh:
        try:
            doc = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValidationError(
                f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})")
    return parse_rules(doc, source=path)


def lint(doc: dict[str, Any], *, source: str = "<memory>") -> list[str]:
    """Validate a rules document, returning human-readable issues (empty=ok)."""
    issues: list[str] = []
    try:
        parse_rules(doc, source=source)
    except ValidationError as exc:
        issues.append(exc.message)
    return issues


def builtin_rules_path() -> str:
    import os
    return os.path.join(os.path.dirname(__file__), "signatures",
                        "builtin.json")


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_bytes(data: bytes, rules: list[Rule]) -> dict[str, Any]:
    """Scan ``data`` against compiled ``rules``; fully deterministic output."""
    matches: list[dict[str, Any]] = []
    for rule in rules:
        if len(data) < rule.filesize_min:
            continue
        if rule.filesize_max is not None and len(data) > rule.filesize_max:
            continue
        offsets: dict[str, list[int]] = {}
        for sp in rule.strings:
            found = _find_all(data, sp)
            offsets[sp.sid] = found
        hits = {sid: bool(found) for sid, found in offsets.items()}
        if not _eval_condition(rule.condition, hits, rule.name):
            continue
        strings = sorted(
            (StringMatch(sid=sid, offset=off)
             for sid, found in offsets.items() for off in found),
            key=lambda m: (m.offset, m.sid))
        matches.append(RuleMatch(
            rule=rule.name, family=rule.family, severity=rule.severity,
            description=rule.description,
            strings=tuple(strings)).to_dict())
    return {
        "size": len(data),
        "sha256": sha256_bytes(data),
        "rules_evaluated": len(rules),
        "matches": matches,
    }


# Refuse to buffer samples larger than this by default: scanning is an
# analytical operation and must not become a memory-exhaustion vector.
DEFAULT_MAX_SAMPLE_BYTES = 64 * 1024 * 1024


def scan_file(path: str, rules: list[Rule], *,
              max_sample_bytes: int = DEFAULT_MAX_SAMPLE_BYTES) -> dict[str, Any]:
    if max_sample_bytes < 0:
        raise ValidationError("max_sample_bytes must be non-negative")
    with open(path, "rb") as fh:
        # Read one byte past the cap so oversize inputs are detected exactly,
        # without ever buffering more than cap+1 bytes.
        data = fh.read(max_sample_bytes + 1)
    if len(data) > max_sample_bytes:
        raise ValidationError(
            f"sample exceeds the {max_sample_bytes}-byte scan cap "
            f"({max_sample_bytes + 1}+ bytes); split it or raise "
            f"max_sample_bytes explicitly")
    result = scan_bytes(data, rules)
    result["path"] = path
    return result
