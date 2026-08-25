"""Regression tests for the bounded mock-campaign profiler."""

from __future__ import annotations

import json

import pytest

from ios_research.cli import main
from ios_research.profiling import profile_campaign


def test_profile_campaign_reports_required_stages():
    result = profile_campaign(max_cases=20, seed=7)
    assert result["executed_cases"] == 20
    assert result["wall_seconds"] > 0
    assert set(result["stages"]) == {
        "mutation", "target_execution", "sanitizer_report_parsing",
        "persistence"}
    assert result["stages"]["mutation"]["calls"] == 20
    assert result["stages"]["target_execution"]["calls"] == 20
    assert result["stages"]["sanitizer_report_parsing"]["calls"] == 0


def test_profile_campaign_rejects_non_mock_target():
    with pytest.raises(ValueError, match="mock targets"):
        profile_campaign(target_id="mac:imageio", max_cases=1)


def test_benchmark_profile_cli_json(capsys):
    assert main(["benchmark", "profile", "--max-cases", "10", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["data"]["executed_cases"] == 10


def test_benchmark_profile_cli_rejects_real_target(capsys):
    assert main(["benchmark", "profile", "--target", "mac:imageio", "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["exit_code"] == 2
