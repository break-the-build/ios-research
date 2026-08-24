"""Regression tests for tools/campaign/run_campaign.py (#189).

The 2026-08-23 session left this runner with REPO = parents[1], which
resolved to <repo>/tools and pointed the sys.path bootstrap at a
non-existent directory. It only worked behind the editable install.
These tests load the module by file path and pin the path math so the
bootstrap stays honest even where ios_research is not installed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "tools" / "campaign" / "run_campaign.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("run_campaign_tool", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repo_root_resolution():
    mod = _load_runner()
    assert mod.REPO == REPO
    assert (mod.REPO / "src" / "ios_research").is_dir()


def test_bootstrap_puts_package_src_on_sys_path():
    mod = _load_runner()
    src = str(REPO / "src")
    assert src in sys.path or str(mod.REPO / "src") in sys.path


def test_seed_globs_and_dictionaries_cover_registered_targets():
    mod = _load_runner()
    from ios_research.targets.mac import MAC_FRAMEWORKS
    campaign_keys = {"imageio", "audiotoolbox", "coregraphics", "coretext"}
    assert campaign_keys <= set(MAC_FRAMEWORKS)
    assert campaign_keys <= set(mod.SEED_GLOBS)
    assert campaign_keys <= set(mod.DICTIONARIES)
    for key, tokens in mod.DICTIONARIES.items():
        assert tokens.startswith('"') and tokens.endswith("\n")
