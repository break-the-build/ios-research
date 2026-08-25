"""Regression tests for tools/campaign/confirm_on_device.py console-capture
race handling (RESEARCH-LOG 2026-08-25: fast-exiting apps could yield an
empty devicectl console and a false ERROR verdict).

Loads the tool by file path, mirroring tests/test_campaign_runner_tool.py.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "campaign" / "confirm_on_device.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("confirm_on_device", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_race_retry_recovers_definitive_verdict():
    mod = _load_tool()
    calls = {"n": 0}

    def flaky(timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            return 0, ""                      # console race: nothing captured
        return 0, "PROBE OPEN_OK\nPROBE DONE no-hang"

    code, console, meta = mod.launch_with_retry(flaky, timeout=5.0)
    assert mod.parse_verdict(console, timed_out=False) == "OPEN_OK"
    assert calls["n"] == 2
    assert [m["verdict"] for m in meta] == ["ERROR", "OPEN_OK"]
    assert meta[0]["probe_lines"] == 0


def test_probe_error_is_not_retried():
    """A definitive PROBE ERROR line must short-circuit (no backoff sleep)."""
    mod = _load_tool()
    calls = {"n": 0}

    def failing_app(timeout):
        calls["n"] += 1
        return 0, "PROBE ERROR cannot open input"

    code, console, meta = mod.launch_with_retry(failing_app, timeout=5.0,
                                                attempts=3)
    assert calls["n"] == 1
    assert len(meta) == 1
    assert meta[0]["verdict"] == "ERROR"


def test_persistent_race_exhausts_attempts_and_reports_last():
    mod = _load_tool()
    calls = {"n": 0}

    def always_empty(timeout):
        calls["n"] += 1
        return 0, ""

    code, console, meta = mod.launch_with_retry(always_empty, timeout=5.0)
    assert calls["n"] == mod.CONSOLE_RACE_ATTEMPTS
    assert all(m["verdict"] == "ERROR" for m in meta)


def test_hang_timeout_maps_to_hang_without_retry():
    """timed_out launches already have a verdict; never burn retries on them."""
    mod = _load_tool()
    calls = {"n": 0}

    def hanging(timeout):
        calls["n"] += 1
        return 124, "PROBE OPEN_OK"           # opened, never reached DONE

    code, console, meta = mod.launch_with_retry(hanging, timeout=0.05,
                                                attempts=3)
    assert calls["n"] == 1
    assert meta[0]["verdict"] == "HANG"
