"""Shared pytest fixtures.

Tests run against a temporary workspace with a frozen clock so that all
timestamps and derived identifiers are deterministic.
"""

from __future__ import annotations

import os
import pytest

from ios_research.context import Context
from ios_research.workspace import Workspace
from ios_research import __version__
from ios_research.clock import now_iso


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch):
    # Freeze time to a fixed epoch for deterministic outputs.
    monkeypatch.setenv("IOS_RESEARCH_FROZEN_TIME", "1700000000")
    yield


@pytest.fixture
def workspace(tmp_path) -> Workspace:
    ws = Workspace(tmp_path / ".ios-research")
    ws.init(framework_version=__version__, created_at=now_iso())
    return ws


@pytest.fixture
def ctx(workspace) -> Context:
    return Context(workspace_path=str(workspace.root), assume_yes=True)
