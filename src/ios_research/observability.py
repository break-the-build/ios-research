"""Authorized mobile dynamic-observability adapters (#45).

Stateful/UI/API defects often surface as *behavioral anomalies* — unexpected
lifecycle churn, abnormal request counts, suspicious state flags — long before
anything crashes. This module defines an opt-in telemetry layer:

* adapters are **user-declared and target-scoped**: an adapter names exactly
  one target id and refuses anything else (an unapproved target emits no
  telemetry at all),
* it collects what the *target itself* exposes — app logs, lifecycle events,
  network-request *metadata*, UI state snapshots, researcher-declared custom
  signals — never unrelated apps or system services,
* every event is correlated with its testcase/sequence id and timestamp and
  redacted by default (secret-shaped keys are masked before persistence),
* traces are replayable (stored verbatim next to their input hash), and a
  declarative oracle can flag anomalies as non-crash findings.

Nothing here captures device sensors, injects system-wide hooks, or intercepts
traffic outside the declared target process boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Callable

from .clock import now_iso
from .errors import NotFoundError, SafetyError, ValidationError
from .hashing import sha256_bytes
from .ids import make_id
from .logging_util import _REDACTED, _REDACT_KEYS
from .workspace import Workspace

OBSERVABILITY_SCHEMA_VERSION = 1
MAX_EVENTS_PER_TRACE = 512


def redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Mask secret-shaped values before any persistence."""
    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): (_REDACTED if str(k).lower() in _REDACT_KEYS
                             else walk(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        return value
    return walk(payload)


@dataclass(frozen=True)
class TelemetryEvent:
    """One target-owned observation."""

    kind: str                 # log | lifecycle | network | ui-state | custom
    timestamp: float          # adapter-supplied monotonic clock
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["payload"] = redact_payload(out["payload"])
        return out


class ObservabilityAdapter:
    """Contract implemented by an authorized instrumented target adapter."""

    target_id: str = ""

    def start(self, testcase_id: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def stop(self) -> list[TelemetryEvent]:  # pragma: no cover - interface
        raise NotImplementedError


class ObservabilityRegistry:
    """Explicit registration: unapproved targets have NO adapter."""

    def __init__(self) -> None:
        self._adapters: dict[str, Callable[[], ObservabilityAdapter]] = {}

    def register(self, target_id: str,
                 factory: Callable[[], ObservabilityAdapter]) -> None:
        self._adapters[target_id] = factory

    def adapter_for(self, target_id: str) -> ObservabilityAdapter | None:
        factory = self._adapters.get(target_id)
        return factory() if factory else None


REGISTRY = ObservabilityRegistry()


# --- declarative oracle ---------------------------------------------------------

_OPS = {
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}


@dataclass(frozen=True)
class TraceOracle:
    """A tiny declarative predicate over trace events.

    ``field`` uses dotted paths into an event (``payload.retry_count``);
    ``where_kind`` optionally restricts the rule to one event kind.
    """

    field: str
    op: str
    value: Any
    where_kind: str | None = None
    oracle_version: int = 1

    def violations(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if self.op not in _OPS:
            raise ValidationError(f"unknown oracle op '{self.op}'")
        hits = []
        for event in events:
            if self.where_kind and event.get("kind") != self.where_kind:
                continue
            node: Any = event
            try:
                for part in self.field.split("."):
                    node = node[part]
            except (KeyError, TypeError):
                continue
            if _OPS[self.op](node, self.value):
                hits.append(event)
        return hits


def oracle_from_spec(spec: dict[str, Any]) -> TraceOracle:
    try:
        oracle = TraceOracle(field=spec["field"], op=spec["op"],
                             value=spec["value"],
                             where_kind=spec.get("where_kind"))
    except (KeyError, TypeError) as exc:
        raise ValidationError(
            f"oracle spec needs field/op/value: {exc}") from exc
    if oracle.op not in _OPS:
        raise ValidationError(f"unknown oracle op '{oracle.op}'")
    return oracle


# --- collection engine -------------------------------------------------------------

class ObservabilityEngine:
    def __init__(self, workspace: Workspace, registry: ObservabilityRegistry
                 | None = None):
        self.ws = workspace
        self.registry = registry or REGISTRY

    @staticmethod
    def _require_target_scoped(adapter: ObservabilityAdapter,
                               target_id: str) -> None:
        if getattr(adapter, "target_id", "") != target_id:
            raise SafetyError(
                "observability adapter is scoped to "
                f"'{getattr(adapter, 'target_id', '')}', not '{target_id}'; "
                "unapproved targets emit no telemetry")

    def observe(self, target_id: str, testcase_id: str,
                data: bytes, execute: Callable[[bytes], Any],
                oracles: list[TraceOracle] | None = None
                ) -> dict[str, Any]:
        """Run one testcase while collecting target-owned telemetry."""
        adapter = self.registry.adapter_for(target_id)
        if adapter is None:
            raise SafetyError(
                f"no observability adapter approved for '{target_id}'")
        self._require_target_scoped(adapter, target_id)

        adapter.start(testcase_id)
        result = execute(data)
        events = [event.to_dict() for event in adapter.stop()]
        events = events[:MAX_EVENTS_PER_TRACE]

        anomalies = []
        for oracle in oracles or []:
            for hit in oracle.violations(events):
                anomalies.append({
                    "oracle_version": oracle.oracle_version,
                    "rule": f"{oracle.field} {oracle.op} {oracle.value!r}",
                    "event_index": events.index(hit),
                    "note": "behavioral observation only; not a crash and "
                            "carries no exploitability claim",
                })

        record = {
            "schema_version": OBSERVABILITY_SCHEMA_VERSION,
            "id": make_id("obstrace", target_id, testcase_id),
            "target": target_id,
            "testcase_id": testcase_id,
            "input_sha256": sha256_bytes(data),
            "outcome": result.outcome,
            "collected_at": now_iso(),
            "events": events,
            "anomalies": anomalies,
            "redaction": "secret-shaped keys masked by default",
        }
        rel = f"findings/{record['id']}/trace.json"
        self.ws.write_json(rel, record)
        record["trace_path"] = rel
        return record

    def get(self, trace_id: str) -> dict[str, Any]:
        rel = f"findings/{trace_id}/trace.json"
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"observation trace '{trace_id}' not found")
        return self.ws.read_json(rel)

    def list(self, target_id: str | None = None) -> list[dict[str, Any]]:
        base = self.ws.root / "findings"
        out = []
        if not base.exists():
            return out
        for manifest in sorted(base.glob("*/trace.json")):
            record = self.ws.read_json(str(manifest.relative_to(self.ws.root)))
            if target_id is None or record["target"] == target_id:
                out.append(record)
        return out
