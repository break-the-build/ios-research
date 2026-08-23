"""Keep experiment-loop goals uniquely identifiable and machine-readable."""

from __future__ import annotations

import json
from pathlib import Path


GOALS = Path(__file__).parents[1] / "goals"


def test_every_executable_goal_has_a_unique_explicit_id() -> None:
    definitions = [
        json.loads(path.read_text())
        for path in sorted(GOALS.glob("*.json"))
    ]
    ids = [definition.get("id") for definition in definitions]
    assert all(isinstance(goal_id, str) and goal_id for goal_id in ids)
    assert len(ids) == len(set(ids))


def test_goal_constraints_are_declared_metrics() -> None:
    for path in sorted(GOALS.glob("*.json")):
        definition = json.loads(path.read_text())
        metrics = {metric["name"] for metric in definition["metrics"]}
        assert definition["primary_metric"] in metrics, path
        assert {constraint["metric"] for constraint in definition["constraints"]} <= metrics, path
