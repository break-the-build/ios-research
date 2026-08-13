"""Injectable clock.

Wall-clock time is inherently nondeterministic. To keep experiments and tests
reproducible, all timestamps flow through a Clock that can be frozen in tests
and CI via the ``IOS_RESEARCH_FROZEN_TIME`` environment variable.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone


class Clock:
    def now(self) -> datetime:
        frozen = os.environ.get("IOS_RESEARCH_FROZEN_TIME")
        if frozen:
            return datetime.fromtimestamp(float(frozen), tz=timezone.utc)
        return datetime.now(timezone.utc)

    def now_iso(self) -> str:
        return self.now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


_CLOCK = Clock()


def now_iso() -> str:
    return _CLOCK.now_iso()
