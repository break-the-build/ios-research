"""Opt-in Apple Security Research Device backend (#40).

The Security Research Device (SRD) program provides *approved* researchers
with specially configured iPhones. This module adds an SRD target behind the
same :class:`~ios_research.targets.base.Target` interface every other backend
uses, plus a deterministic fake backend so CI can exercise the whole evidence
path without hardware or SRD access.

Strictly opt-in and fail-closed: ``SRDTarget`` refuses to run unless the
researcher explicitly supplies an approval configuration (a dict, or a JSON
file named by ``IOS_RESEARCH_SRD_CONFIG``) containing ``approved: true``, a
non-empty ``device_id``, ``model``, ``build``, and ``authorized_user``. With
any field missing the target reports an actionable blocker and ``execute()``
returns ``ABNORMAL`` — it never fabricates results.

Adapter hooks only: researchers may register *local* command hooks and collect
artifacts they supply themselves. Nothing here executes automatically, and no
exploit, permission-bypass, credential, persistence, or privilege functionality
exists anywhere in this module — it records what the researcher supplies and
observes. See ``SECURITY.md``.

Evidence separation: ``describe()`` and ``provenance()`` always carry
``"evidence_class": "srd"`` so reports can keep SRD evidence apart from
retail-device evidence.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from ..clock import now_iso
from ..hashing import sha256_bytes, canonical_json
from ..logging_util import redact
from .base import ExecResult, Outcome, Target

# Environment variable pointing at a researcher-supplied JSON config file.
SRD_ENV = "IOS_RESEARCH_SRD_CONFIG"

_REQUIRED_FIELDS = ("device_id", "model", "build", "authorized_user")

_MISSING_CONFIG_HINT = (
    "set IOS_RESEARCH_SRD_CONFIG to a JSON file containing "
    '{"approved": true, "device_id": "...", "model": "...", '
    '"build": "...", "authorized_user": "..."} (or pass config=...)')


def missing_config_fields(config: dict[str, Any]) -> list[str]:
    """Return required fields that are absent/empty/False in ``config``."""
    if not isinstance(config, dict):
        return ["<entire config>"] + list(_REQUIRED_FIELDS)
    missing: list[str] = []
    if config.get("approved") is not True:
        missing.append("approved")
    for name in _REQUIRED_FIELDS:
        value = config.get(name)
        if not isinstance(value, str) or not value.strip():
            missing.append(name)
    return missing


def _tool_versions() -> dict[str, str]:
    """Versions of the local tooling that produced the evidence."""
    import platform
    import sys

    from .. import __version__
    return {
        "ios_research": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }


def _evidence_digest(payload: Any) -> str:
    """Deterministic SHA-256 over bytes / str / JSON-able hook output."""
    if isinstance(payload, bytes):
        data = payload
    elif isinstance(payload, str):
        data = payload.encode("utf-8")
    else:
        data = canonical_json(payload).encode("utf-8")
    return sha256_bytes(data)


class _SRDEvidenceMixin:
    """Shared provenance/hook/artifact plumbing for SRD targets.

    Both the real SRD target and the CI fake use this mixin so lifecycle,
    provenance, redaction, and evidence-class behavior are identical by
    construction.
    """

    evidence_class = "srd"

    def _init_evidence(self, workspace=None) -> None:
        self.workspace = workspace
        self._lifecycle: list[dict[str, Any]] = []
        self._hook_records: list[dict[str, Any]] = []
        self._artifact_records: list[dict[str, Any]] = []
        self._command_hooks: dict[str, Callable[[], Any]] = {}
        self._tool_versions = _tool_versions()

    # -- configuration -----------------------------------------------------
    def _resolve_config(self) -> dict[str, Any]:
        """Return the effective config, loading the env file lazily."""
        raise NotImplementedError  # pragma: no cover

    def missing_fields(self) -> list[str]:
        return missing_config_fields(self._resolve_config())

    # -- gating ------------------------------------------------------------
    def available(self) -> bool:
        return not self.missing_fields()

    def blocker(self) -> str:
        """Actionable reason this target cannot run (empty if it can)."""
        missing = self.missing_fields()
        if not missing:
            return ""
        return (f"{self.target_id} is not approved/configured; missing or "
                f"invalid fields: {', '.join(missing)}. {_MISSING_CONFIG_HINT}")

    # -- lifecycle log -------------------------------------------------------
    def _log_event(self, op: str, **fields: Any) -> None:
        self._lifecycle.append({"op": op, "at": now_iso(), **fields})

    def prepare(self) -> None:
        self._log_event("prepare")

    def cleanup(self) -> None:
        self._log_event("cleanup")

    @property
    def lifecycle_log(self) -> list[dict[str, Any]]:
        return list(self._lifecycle)

    # -- adapter hooks (researcher-supplied, never auto-executed) ----------
    def register_command_hook(self, name: str, fn: Callable[[], Any]) -> None:
        """Register a *local* command hook under ``name``.

        The callable is stored only; it is never invoked by the framework. It
        runs solely when the researcher explicitly calls :meth:`run_hook`.
        """
        from ..errors import ValidationError
        if not name or not callable(fn):
            raise ValidationError(
                "register_command_hook requires a non-empty name and a callable")
        self._command_hooks[name] = fn

    def run_hook(self, name: str) -> Any:
        """Explicitly run one registered hook and record its output digest."""
        from ..errors import NotFoundError
        if name not in self._command_hooks:
            raise NotFoundError(
                f"unknown command hook '{name}'; registered: "
                f"{', '.join(sorted(self._command_hooks)) or '(none)'}")
        output = self._command_hooks[name]()
        record = {"hook": name, "at": now_iso(),
                  "output_sha256": _evidence_digest(output)}
        self._hook_records.append(record)
        self._log_event("hook", hook=name,
                        output_sha256=record["output_sha256"])
        return output

    # -- artifact collection -------------------------------------------------
    def collect_artifact(self, name: str, data: bytes) -> dict[str, Any]:
        """Hash researcher-supplied bytes into the workspace artifact store."""
        from ..artifacts import ArtifactStore
        from ..errors import ValidationError
        if self.workspace is None:
            raise ValidationError(
                "artifact collection requires a workspace "
                "(pass workspace= to the target)")
        store = ArtifactStore(self.workspace)
        blob = bytes(data)
        artifact = store.put(blob, kind=f"srd:{name}")
        record = {"name": name, "sha256": artifact.sha256,
                  "size": artifact.size, "path": artifact.path,
                  "artifact_id": artifact.id, "at": now_iso()}
        self._artifact_records.append(record)
        self._log_event("artifact", name=name, sha256=record["sha256"])
        return record

    # -- exported evidence ---------------------------------------------------
    def provenance(self) -> dict[str, Any]:
        """Redacted evidence-provenance dict (always ``evidence_class: srd``)."""
        config = self._resolve_config()
        raw: dict[str, Any] = {
            "evidence_class": self.evidence_class,
            "target_id": self.target_id,
            "kind": self.kind,
            "mock": self.mock,
            "model": config.get("model"),
            "build": config.get("build"),
            "authorized_user": config.get("authorized_user"),
            "device_id": config.get("device_id"),
            "tool_versions": dict(self._tool_versions),
            "config": dict(config),
            "lifecycle": self.lifecycle_log,
            "hooks_run": list(self._hook_records),
            "collected_artifacts": list(self._artifact_records),
            "note": ("records only what the researcher supplies/observes; no "
                     "exploit, bypass, credential, persistence, or privilege "
                     "functionality is included"),
        }
        # Secret-shaped keys never leave the object unredacted.
        return redact(raw)

    def describe(self) -> dict[str, Any]:
        d = super().describe()
        d["evidence_class"] = self.evidence_class
        d["available"] = self.available()
        blocker = self.blocker()
        if blocker:
            d["blocker"] = blocker
        d["note"] = ("opt-in approved-participant backend; records only what "
                     "the researcher supplies/observes")
        return redact(d)


class SRDTarget(_SRDEvidenceMixin, Target):
    """Real Apple Security Research Device target (approved participants only).

    ``mock = False``. Runs **only** against an explicitly configured, approved
    SRD; there is deliberately no code path that requests, assumes, or obtains
    SRD access. With no delivery automation configured, ``_run`` records the
    input as observed evidence (SHA-256 stamped) and returns ``ACCEPTED``;
    crash confirmation comes from the researcher's own authorized tooling via
    command hooks and artifact collection.
    """

    target_id = "srd:device"
    kind = "srd"
    description = "Apple Security Research Device (approved participants only)"
    formats = ("bin",)
    mock = False

    def __init__(self, config: dict[str, Any] | None = None,
                 *, workspace=None) -> None:
        self._explicit_config = config
        self._loaded_config: dict[str, Any] | None = None
        self._env_error: str | None = None
        self._init_evidence(workspace)

    def _resolve_config(self) -> dict[str, Any]:
        if self._explicit_config is not None:
            return dict(self._explicit_config)
        if self._loaded_config is None:
            path = os.environ.get(SRD_ENV, "")
            if not path:
                self._loaded_config = {}
            else:
                try:
                    self._loaded_config = json.loads(
                        Path(path).read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    self._loaded_config = {}
                    self._env_error = f"{SRD_ENV}={path!r} is unreadable: {exc}"
        return self._loaded_config

    def blocker(self) -> str:
        missing = self.missing_fields()
        if not missing:
            return ""
        prefix = f"{self._env_error}; " if self._env_error else ""
        return (f"{prefix}{self.target_id} requires explicit approval; "
                f"missing or invalid fields: {', '.join(missing)}. "
                f"{_MISSING_CONFIG_HINT}")

    def describe(self) -> dict[str, Any]:
        d = super().describe()
        d["config_env_var"] = SRD_ENV
        d["missing_fields"] = self.missing_fields()
        return d

    def execute(self, data: bytes) -> ExecResult:
        # Gate before any lifecycle step: an unapproved target must never even
        # appear to run, and must never fabricate a crash.
        blocker = self.blocker()
        if blocker:
            return ExecResult(outcome=Outcome.ABNORMAL,
                              detail=f"{self.target_id} blocked: {blocker}",
                              duration_ms=0)
        return super().execute(data)

    def _run(self, data: bytes) -> ExecResult:
        input_sha256 = sha256_bytes(data)
        self._log_event("run", mode="observation-only",
                        input_sha256=input_sha256, size=len(data))
        return ExecResult(
            outcome=Outcome.ACCEPTED,
            detail=(f"input recorded on approved SRD ({self._resolve_config().get('build')}); "
                    f"sha256={input_sha256[:16]}… (observation only; no "
                    f"automated delivery/instrumentation is performed)"),
            duration_ms=1)


class FakeSRDBackend(_SRDEvidenceMixin, Target):
    """Deterministic mock SRD backend (CI-safe, ``mock = True``).

    Mirrors :class:`SRDTarget`'s interface so provenance, lifecycle, failure,
    and redaction behavior are covered without hardware or SRD access. Results
    are keyed on the input bytes: identical input always yields an identical
    :class:`ExecResult`. If a config is supplied it is validated exactly like
    the real target's (so failure paths are testable); with none supplied a
    built-in approved demo config is used so the backend runs anywhere.
    """

    target_id = "srd:fake"
    kind = "srd-fake"
    description = "Deterministic fake SRD backend (CI-safe)"
    formats = ("bin",)
    mock = True

    _DEFAULT_CONFIG = {
        "approved": True,
        "device_id": "FAKE-SRD-0001",
        "model": "iPhoneResearchVirtual",
        "build": "00F-FAKE-0001",
        "authorized_user": "ci-researcher",
    }

    def __init__(self, config: dict[str, Any] | None = None,
                 *, workspace=None) -> None:
        self._supplied_config = config
        self._init_evidence(workspace)

    def _resolve_config(self) -> dict[str, Any]:
        if self._supplied_config is not None:
            return dict(self._supplied_config)
        return dict(self._DEFAULT_CONFIG)

    def execute(self, data: bytes) -> ExecResult:
        blocker = self.blocker()
        if blocker:
            return ExecResult(outcome=Outcome.ABNORMAL,
                              detail=f"{self.target_id} blocked: {blocker}",
                              duration_ms=0)
        return super().execute(data)

    def _run(self, data: bytes) -> ExecResult:
        digest = sha256_bytes(data)
        self._log_event("run", mode="fake", input_sha256=digest,
                        size=len(data))
        # Deterministic outcome keyed purely on the input bytes.
        selector = int(digest[:2], 16)
        if selector < 0x20:
            outcome, detail = Outcome.REJECTED, "fake backend rejected input"
        elif selector < 0x30:
            outcome = Outcome.TIMEOUT
            detail = "fake backend timed out deterministically"
        elif selector < 0x50:
            outcome = Outcome.ABNORMAL
            detail = "fake backend abnormal exit"
        else:
            outcome, detail = Outcome.ACCEPTED, "fake backend accepted input"
        duration_ms = int(digest[2:4], 16) // 4 + 1
        return ExecResult(outcome=outcome, detail=detail,
                          duration_ms=duration_ms)
