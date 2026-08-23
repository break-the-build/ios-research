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
