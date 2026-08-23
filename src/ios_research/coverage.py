"""Optional, deterministic coverage-feedback primitives.

Targets may expose stable feature identifiers through
``Target.coverage_features``.  This module deliberately does not attempt to
instrument a target or infer coverage from a crash: collecting coverage is the
responsibility of an explicitly configured, authorized target adapter.  When a
target has no adapter, callers receive ``None`` and retain the historic
deterministic scheduling behaviour.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from .targets.base import ExecResult


MAX_FEATURES_PER_INPUT = 4096
MAX_FEATURE_LENGTH = 256


class CoverageAdapter(Protocol):
    """Optional adapter implemented by an authorized instrumented target."""

    def coverage_features(self, data: bytes, result: ExecResult) -> Iterable[str] | None:
        """Return stable opaque feature IDs, or ``None`` if unavailable."""


def normalize_features(features: Iterable[object] | None) -> tuple[str, ...] | None:
    """Validate and canonically order provider-supplied feature IDs.

    Feature IDs are intentionally opaque strings.  Sorting and de-duplicating
    makes persistence, minimization, and resumed scheduling deterministic.
    Invalid provider output is ignored rather than being converted into a
    synthetic signal; a coverage adapter must provide stable IDs explicitly.
    """
    if features is None:
        return None
    if isinstance(features, (str, bytes)):
        return None
    try:
        values = list(features)
    except TypeError:
        return None
    if len(values) > MAX_FEATURES_PER_INPUT:
        return None
    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            return None
        feature = value.strip()
        if (not feature or len(feature) > MAX_FEATURE_LENGTH
                or any(ch.isspace() for ch in feature)):
            return None
        normalized.add(feature)
    return tuple(sorted(normalized))


class SanitizerCoverageFileAdapter:
    """Read the stable guard map emitted by the bundled native driver.

    ``-fsanitize-coverage=trace-pc-guard`` assigns deterministic guard numbers
    for a given instrumented harness build.  The driver emits only guard
    numbers observed while the authorized target entry point is active.  This
    adapter namespaces those numbers by target ID; it does not collect code,
    addresses, or any data outside that process.
    """

    @staticmethod
    def read(path: str | Path, namespace: str) -> tuple[str, ...] | None:
        try:
            lines = Path(path).read_text(encoding="ascii").splitlines()
        except (OSError, UnicodeError):
            return None
        if not lines or lines[0] != "IOSR_SANCOV_V1":
            return None
        guards: list[str] = []
        for line in lines[1:]:
            value = line.strip()
            if not value.isdecimal() or int(value) <= 0:
                return None
            guards.append(f"sancov:{namespace}:guard:{int(value)}")
        # A version header with no guards is valid measured coverage (zero
        # target guards); callers can distinguish it from unsupported.
        return normalize_features(guards)
