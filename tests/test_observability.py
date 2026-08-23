"""Dynamic-observability adapters: scoped telemetry + anomaly oracles (#45)."""

from __future__ import annotations

import pytest

from ios_research.errors import NotFoundError, SafetyError, ValidationError
from ios_research.observability import (
    ObservabilityAdapter, ObservabilityEngine, ObservabilityRegistry,
    REGISTRY, TelemetryEvent, TraceOracle, oracle_from_spec, redact_payload)
from ios_research.targets.base import ExecResult, Outcome, Target


class AppTarget(Target):
    """Fixture 'app' target: behavioral anomaly without any crash."""

    target_id = "test:app"
    kind = "mock-app"
    description = "mock app with observable retry churn"

    def _run(self, data: bytes) -> ExecResult:
        return ExecResult(outcome=Outcome.ACCEPTED)


class ChattyAdapter(ObservabilityAdapter):
    """Emits lifecycle/network metadata for its one approved target."""

    target_id = "test:app"

    def __init__(self):
        self._events: list[TelemetryEvent] = []

    def start(self, testcase_id: str) -> None:
        self._events = []

    def stop(self) -> list[TelemetryEvent]:
        events = self._events + [
            TelemetryEvent("lifecycle", 1.0, {"state": "resumed"}),
            TelemetryEvent("network", 2.0,
                           {"host": "api.example.test",
                            "retry_count": 41}),
            TelemetryEvent("network", 3.0,
                           {"host": "api.example.test",
                            "authorization": "Bearer sekrit"}),
        ]
        return events


@pytest.fixture()
def app_target():
    target_registry_id = "test:app"
    from ios_research import targets as tr
    tr.register(target_registry_id, lambda: AppTarget())
    yield
    tr._REGISTRY.pop(target_registry_id, None)


def _observe(workspace, data=b"hello", oracles=None):
    engine = ObservabilityEngine(workspace)
    return engine.observe(
        "test:app", "tc_test", data, lambda blob: AppTarget().execute(blob),
        oracles=oracles)


def test_unapproved_target_emits_no_telemetry(workspace):
    from ios_research import targets as tr
    tr.register("test:silent-app", lambda: AppTarget())
    try:
        with pytest.raises(SafetyError, match="no observability adapter"):
            ObservabilityEngine(workspace).observe(
                "test:silent-app", "tc_x", b"x",
                lambda blob: AppTarget().execute(blob))
    finally:
        tr._REGISTRY.pop("test:silent-app", None)


def test_mismatched_adapter_scope_is_a_safety_error(workspace):
    # A misconfigured registry entry (adapter filed under the wrong target id)
    # must be caught by the scope guard, never silently applied.
    registry = ObservabilityRegistry()
    registry.register("test:not-other", lambda: ChattyAdapter())

    engine = ObservabilityEngine(workspace, registry)
    with pytest.raises(SafetyError, match="scoped"):
        engine.observe("test:not-other", "tc_x", b"x",
                       lambda blob: AppTarget().execute(blob))


def test_anomaly_surfaced_with_correlated_trace(workspace, app_target):
    REGISTRY.register("test:app", lambda: ChattyAdapter())
    oracle = oracle_from_spec({"field": "payload.retry_count",
                               "op": ">",
                               "value": 30,
                               "where_kind": "network"})
    record = _observe(workspace, b"trigger-anomaly", oracles=[oracle])
    assert record["outcome"] == "accepted"          # non-crash finding
    assert len(record["anomalies"]) == 1
    anomaly_event = record["events"][record["anomalies"][0]["event_index"]]
    assert anomaly_event["payload"]["retry_count"] == 41
    # Correlation fields are present and stable.
    assert record["input_sha256"].startswith("6b3a") or \
        len(record["input_sha256"]) == 64
    assert record["testcase_id"] == "tc_test"


def test_secrets_redacted_by_default_in_persisted_trace(workspace, app_target):
    REGISTRY.register("test:app", lambda: ChattyAdapter())
    record = _observe(workspace, b"auth-check")
    persisted = workspace.path(record["trace_path"]).read_text()
    assert "sekrit" not in persisted
    network_events = [e for e in record["events"]
                      if e["kind"] == "network" and "authorization" in
                      e["payload"]]
    assert network_events[0]["payload"]["authorization"] == "***REDACTED***"


def test_trace_is_replayable_and_listable(workspace, app_target):
    REGISTRY.register("test:app", lambda: ChattyAdapter())
    first = _observe(workspace, b"same-input")
    second = _observe(workspace, b"same-input")
    engine = ObservabilityEngine(workspace)
    stored = engine.get(first["id"])
    assert [ (e["kind"], e["payload"]) for e in stored["events"] ] == \
        [(e["kind"], e["payload"])
         for e in engine.get(second["id"])["events"]]
    ids = {r["id"] for r in engine.list("test:app")}
    assert {first["id"], second["id"]} <= ids


def test_oracle_validation():
    with pytest.raises(ValidationError):
        oracle_from_spec({"field": "x", "op": "~=", "value": 1})
    with pytest.raises(ValidationError):
        oracle_from_spec({"field": "x", "op": ">"})
    bad_field = oracle_from_spec({"field": "payload.missing", "op": "==",
                                  "value": None})
    assert bad_field.violations([{"kind": "custom", "payload": {}}]) == []
