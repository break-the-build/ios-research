"""Stateful workflow fuzzer for authorized app/API sequences (#39).

Byte-input fuzzing cannot reach defects that depend on *history*: stale
sessions, reused handles, order-sensitive caches. This module models an
authorized target as resettable actions with typed parameters and mutates
action **sequences** deterministically:

* adapters are user-declared local modules exposing ``ADAPTER`` (same trust
  level as a researcher's own harness); they own ``reset()`` and
  ``perform(action, params)`` and never touch anything beyond their target,
* every trial starts from an explicit reset so replays are deterministic,
* findings are minimized by greedy step removal while the failure signature
  stays identical,
* lineage persists the exact sequence, adapter version, environment state
  hash, and a replayable JSON script.

No privileged system actions are automated; the adapter boundary is the safety
boundary.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .errors import NotFoundError, ValidationError
from .hashing import sha256_text
from .ids import make_id
from .workspace import Workspace

STATEFUL_SCHEMA_VERSION = 1
MAX_SEQUENCE_LENGTH = 32
MAX_CASES = 100_000

PARAM_TYPES = ("int", "str", "bytes", "bool")


@dataclass(frozen=True)
class ActionSpec:
    """One resettable action exposed by an adapter."""

    action_id: str
    params: tuple[tuple[str, str], ...] = ()   # (name, type)
    description: str = ""


@dataclass
class StepOutcome:
    action_id: str
    params: dict[str, Any]
    status: str            # ok | error | timeout | invalid
    observation: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class WorkflowAdapter:
    """Structural contract; user-declared modules expose ``ADAPTER``."""

    name: str = ""
    version: str = ""
    actions: tuple[ActionSpec, ...] = ()

    def reset(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def perform(self, action_id: str, params: dict[str, Any]) -> StepOutcome:
        raise NotImplementedError  # pragma: no cover - interface


def load_adapter(path: str | Path) -> WorkflowAdapter:
    """Load a user-declared adapter module."""
    path = Path(path)
    if not path.is_file():
        raise NotFoundError(f"adapter not found: {path}")
    try:
        spec = importlib.util.spec_from_file_location(
            f"iosr_adapter_{sha256_text(str(path))[:10]}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)   # user-declared, trusted code
        adapter = getattr(module, "ADAPTER", None)
    except Exception as exc:  # noqa: BLE001 - isolation boundary
        raise ValidationError(f"adapter load failed: {exc}") from exc
    if adapter is None or not isinstance(getattr(adapter, "actions", None),
                                         tuple) or \
            not callable(getattr(adapter, "reset", None)) or \
            not callable(getattr(adapter, "perform", None)):
        raise ValidationError(
            f"module exposes no valid ADAPTER: {path}")
    return adapter


class _Rng:
    """Deterministic RNG (same LCG as oracles)."""

    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFF or 1

    def _next(self) -> int:
        self.state = (1103515245 * self.state + 12345) & 0x7FFFFFFF
        return self.state

    def below(self, n: int) -> int:
        return self._next() % max(1, n)

    def choice(self, items):
        return items[self.below(len(items))]


def _param_value(param_type: str, rng: _Rng) -> Any:
    if param_type == "int":
        return rng.below(1024)
    if param_type == "bool":
        return bool(rng.below(2))
    if param_type == "str":
        return f"p{rng.below(64)}"
    return bytes([rng.below(256)])


def generate_sequence(adapter: WorkflowAdapter, rng: _Rng,
                      length: int) -> list[dict[str, Any]]:
    """A deterministic random action sequence respecting declared types."""
    specs = list(adapter.actions)
    if not specs:
        return []
    seq = []
    for _ in range(max(1, min(length, MAX_SEQUENCE_LENGTH))):
        spec = rng.choice(specs)
        params = {name: _param_value(ptype, rng)
                  for name, ptype in spec.params}
        seq.append({"action": spec.action_id, "params": params})
    return seq


def mutate_sequence(sequence: list[dict[str, Any]], adapter: WorkflowAdapter,
                    rng: _Rng) -> list[dict[str, Any]]:
    """Deterministic structural mutation of a sequence (#39)."""
    if not sequence:
        return generate_sequence(adapter, rng, rng.below(3) + 1)
    out = [dict(step) for step in sequence]
    choice = rng.below(5)
    specs = list(adapter.actions)
    spec = rng.choice(specs) if specs else None
    pos = rng.below(len(out))
    if choice == 0 and len(out) > 1:              # delete a step
        del out[pos]
    elif choice == 1:                             # insert an action
        params = {n: _param_value(t, rng) for n, t in spec.params} \
            if spec else {}
        out.insert(pos, {"action": spec.action_id if spec else "",
                         "params": params})
    elif choice == 2:                             # replace an action
        params = {n: _param_value(t, rng) for n, t in spec.params} \
            if spec else {}
        out[pos] = {"action": spec.action_id if spec else "",
                    "params": params}
    elif choice == 3 and len(out) > 1:            # swap two steps
        other = rng.below(len(out))
        out[pos], out[other] = out[other], out[pos]
    else:                                         # tweak one parameter
        step = out[pos]
        if step["params"]:
            key = rng.choice(sorted(step["params"]))
            value = step["params"][key]
            step["params"][key] = type(value)(
                value if isinstance(value, bool) else
                (value + 1 if isinstance(value, int) else value))
            if isinstance(value, bytes):
                step["params"][key] = bytes([value[0] ^ 0x01]) if value else b"\x00"
    return out[:MAX_SEQUENCE_LENGTH]


class StatefulFuzzer:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    # execution --------------------------------------------------------------
    def run_sequence(self, adapter: WorkflowAdapter,
                     sequence: list[dict[str, Any]]) -> dict[str, Any]:
        """Reset, then execute every step; returns trace + failure signature.

        Adapter errors are captured as ``invalid``/``error`` outcomes instead
        of ending the campaign.
        """
        try:
            adapter.reset()
        except Exception as exc:  # noqa: BLE001
            return {"trace": [], "failure_signature": None,
                    "aborted": f"reset failed: {exc}"}
        trace: list[dict[str, Any]] = []
        failure_signature = None
        for index, step in enumerate(sequence):
            try:
                outcome = adapter.perform(step["action"],
                                          dict(step["params"]))
                status = outcome.status
                observation = dict(outcome.observation)
            except Exception as exc:  # noqa: BLE001 - isolation boundary
                status = "invalid"
                observation = {"adapter_error": str(exc)[:200]}
            entry = {"index": index, **step, "status": status,
                     "observation": observation}
            trace.append(entry)
            if status in ("error", "timeout", "invalid"):
                # Defect identity is deliberately *position-independent*
                # (action + status + adapter-declared reason) so that
                # minimization can drop unrelated prefix/suffix steps while
                # preserving "the same" failure.
                failure_signature = sha256_text(
                    f"{step['action']}|{status}|"
                    f"{observation.get('reason', '')}")
                break   # first failing step defines the signature
        return {"trace": trace, "failure_signature": failure_signature,
                "aborted": ""}

    # campaign -----------------------------------------------------------------
    def fuzz(self, *, adapter_path: str, cases: int, seed: int = 0,
             max_length: int = 8) -> dict[str, Any]:
        adapter = load_adapter(adapter_path)
        cases = max(1, min(cases, MAX_CASES))
        max_length = max(1, min(max_length, MAX_SEQUENCE_LENGTH))
        findings: list[dict[str, Any]] = []
        seen_signatures: set[str] = set()
        executed = 0

        for i in range(cases):
            rng = _Rng((seed << 20) ^ i)
            length = 1 + (i % max_length)      # deterministic growth schedule
            sequence = generate_sequence(adapter, rng, length)
            result = self.run_sequence(adapter, sequence)
            executed += 1
            sig = result["failure_signature"]
            if sig is None or sig in seen_signatures:
                continue
            seen_signatures.add(sig)
            minimized = self.minimize(adapter, sequence, sig)
            findings.append({
                "signature": sig,
                "sequence": sequence,
                "minimized_sequence": minimized,
                "adapter": {"name": adapter.name, "version": adapter.version},
                "env_state_hash": sha256_text(repr(sorted(
                    (s["action"], str(sorted(s["params"].items())))
                    for s in sequence))),
                "replay_script": {
                    "kind": "ios-research-stateful-replay",
                    "schema_version": STATEFUL_SCHEMA_VERSION,
                    "adapter_path": adapter_path,
                    "steps": minimized or sequence,
                },
            })

        record_id = make_id("seqrun", adapter.name, str(cases), str(seed))
        self.ws.write_json(f"findings/{record_id}/sequence.json", {
            "schema_version": STATEFUL_SCHEMA_VERSION,
            "id": record_id,
            "adapter_path": adapter_path,
            "cases": cases,
            "seed": seed,
            "findings": findings,
        })
        return {
            "run_id": record_id,
            "executed": executed,
            "unique_failures": len(findings),
            "findings": findings,
        }

    def minimize(self, adapter: WorkflowAdapter, sequence: list[dict],
                 signature: str, max_rounds: int = 16) -> list[dict[str, Any]]:
        """Greedy step removal that keeps the identical failure signature."""
        current = [dict(step) for step in sequence]

        def fails(seq: list[dict[str, Any]]) -> bool:
            return self.run_sequence(adapter, seq)["failure_signature"] == signature

        changed = True
        rounds = 0
        while changed and len(current) > 1 and rounds < max_rounds:
            changed = False
            rounds += 1
            i = 0
            while i < len(current):
                candidate = current[:i] + current[i + 1:]
                if candidate and fails(candidate):
                    current = candidate
                    changed = True       # keep same index; sequence shrank
                else:
                    i += 1
        return current if fails(current) else current
