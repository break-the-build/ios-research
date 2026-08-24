"""Regression test for issue #167: the experiment-loop environment loader.

The dotted import ``tools.experiment_loop.ios_env`` must import cleanly and
register the ios-research environments with the experiment-loop registry.

Skipped unless the experiment-loop engine checkout exists (CI without the
engine stays green) and ``tools/`` is importable from this repository.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ENGINE_REPO = Path("/Users/danny/dev/experiment-loop")

pytestmark = pytest.mark.skipif(
    not ENGINE_REPO.exists(),
    reason=f"experiment-loop engine checkout not found at {ENGINE_REPO}",
)


def _ensure_import_paths() -> None:
    for candidate in (REPO_ROOT, REPO_ROOT / "src"):
        if candidate.is_dir() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))


def test_ios_env_package_imports_and_registers() -> None:
    _ensure_import_paths()
    try:
        importlib.import_module("tools")
    except ImportError as exc:
        pytest.skip(f"tools/ package not importable from {REPO_ROOT}: {exc}")

    ios_env = importlib.import_module("tools.experiment_loop.ios_env")

    base = pytest.importorskip(
        "experiment_loop.environments.base",
        reason="experiment-loop engine not installed/importable",
    )
    registered = set(base.available_environments())

    # Exact registry names as declared by each module's `name` class attribute.
    expected = {
        "ios_research_fuzzer",            # fuzzer          (goals 05, 06)
        "ios_research_fuzzer_engine",     # fuzzer_engine   (goal 05)
        "ios_research_minimizer",         # minimizer       (goal 09)
        "ios_research_corpus",            # corpus          (goal 07)
        "ios_research_crash_analysis",    # crash_analysis  (goals 08, 11)
        "ios_research_differential",      # differential    (goal 12)
        "ios_research",                   # research        (goal 13)
        "ios_research_agent",             # agent           (goals 14, 15)
        "ios_research_reporting",         # reporting       (goal 17)
        "ios_research_device_matching",   # device_matching (goal 18)
    }

    missing = sorted(expected - registered)
    assert not missing, f"environments not registered after importing {ios_env!r}: {missing}"
