"""Opt-in Apple Security Research Device (SRD) backend (#40).

Bookkeeping-only support for researchers already accepted into Apple's SRD
Program. The framework never assumes, requests, or obtains SRD access; every
capability here is *recording* user-supplied metadata plus running
researcher-authored local adapter commands.

* **Approval gate**: the backend refuses to construct unless the config carries
  explicit approval data under ``srd.*`` (``approved_user``, ``device_model``,
  ``build``/``preview``, ``approval_reference``/``approval_artifact``).
  Missing or incomplete configuration fails closed with a SAFETY error.
* **Provenance**: device model, software build/preview, approved-user context,
  host tool versions (python/xcodebuild when present), and frozen-clock
  timestamps are stamped into an append-only log per session.
* **Evidence separation**: every evidence entry carries a ``channel`` of
  ``srd`` or ``retail`` and a ``tag`` (``srd:<adapter>`` / ``retail:*``) so
  reports can keep the two clearly apart.
* **Adapter hooks**: researcher-selected LOCAL commands taken verbatim from the
  allowlisted ``srd.adapters`` config object, executed via subprocess with argv
  lists (never a shell). Output is redacted of secret-shaped keys before it is
  persisted; artifacts land inside the workspace and are pinned by SHA-256.

No exploit deployment, protection bypass, credential access, persistence, or
surveillance functionality exists here — this module is provenance and
adapters only.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
import sys
from typing import Any, Callable

from .clock import now_iso
from .config import Config
from .errors import SafetyError, StateError, ValidationError
from .hashing import sha256_bytes
from .ids import make_id
from .logging_util import _REDACTED, _is_sensitive
from .workspace import Workspace

SRD_SCHEMA_VERSION = 1

# Approval-gate keys, all inside the top-level ``srd`` config object.
_REQUIRED_KEYS = ("approved_user", "device_model")
_SOFTWARE_KEYS = ("build", "preview")  # at least one required
_APPROVAL_KEYS = ("approval_reference", "approval_artifact")  # at least one

CHANNELS = ("retail", "srd")
SRD_TAG_PREFIX = "srd:"
RETAIL_TAG_PREFIX = "retail:"

MAX_ADAPTER_TIMEOUT_S = 600.0
_DEFAULT_ADAPTER_TIMEOUT_S = 30.0
_OUTPUT_TAIL_CHARS = 4000

_PLACEHOLDERS = ("out", "python", "session", "workspace")
_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
_KEY_VALUE_RE = re.compile(r"^(\s*)([A-Za-z0-9_.\-]+)(\s*[=:]\s*)(.*)$")


def redact_text(text: str) -> str:
    """Mask secret-shaped ``key=value`` / ``key: value`` lines in free text."""
    masked: list[str] = []
    for line in (text or "").splitlines():
        match = _KEY_VALUE_RE.match(line)
        if match and _is_sensitive(match.group(2)):
            line = "".join(match.group(1, 2, 3)) + _REDACTED
        masked.append(line)
    return "\n".join(masked)


def split_by_channel(items: list[dict[str, Any]]) -> dict[str, list[dict]]:
    """Partition evidence entries into disjoint retail/SRD buckets.

    Every entry must carry a ``channel`` of ``retail`` or ``srd``; anything
    else is a validation error rather than a silent mis-bucket.
    """
    out: dict[str, list[dict]] = {channel: [] for channel in CHANNELS}
    for item in items:
        channel = (item or {}).get("channel", "retail")
        if channel not in CHANNELS:
            raise ValidationError(
                f"unknown evidence channel {channel!r}; known: "
                f"{', '.join(CHANNELS)}")
        out[channel].append(item)
    return out


def host_tool_versions() -> dict[str, str]:
    """Best-effort host tool stamp; empty value means 'not available'."""
    return {
        "python": platform.python_version(),
        "platform": f"{sys.platform}/{platform.machine()}",
        "xcodebuild": _first_version_line("xcodebuild"),
    }


def _first_version_line(tool: str) -> str:
    if shutil.which(tool) is None:
        return ""
    try:
        proc = subprocess.run([tool, "--version"], capture_output=True,
                              timeout=30)
        lines = (proc.stdout or b"").decode("utf-8", "replace").splitlines()
        return lines[0].strip() if lines else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


class SRDGate:
    """Fail-closed approval gate over the ``srd.*`` config keys."""

    def __init__(self, config: Config):
        section = config.get("srd", None)
        self.section: dict[str, Any] = section if isinstance(section, dict) \
            else {}

    def require(self) -> dict[str, str]:
        """Return the normalized approval snapshot or raise.

        A wholly absent/incomplete ``srd`` section is a SAFETY refusal
        (exit code 5); values that are present but malformed are a
        VALIDATION error (exit code 4). Both carry actionable details.
        """
        missing = [key for key in _REQUIRED_KEYS
                   if not self._provided(self.section.get(key))]
        software = [key for key in _SOFTWARE_KEYS
                    if self._provided(self.section.get(key))]
        approval = [key for key in _APPROVAL_KEYS
                    if self._provided(self.section.get(key))]
        if not software:
            missing.append("/".join(_SOFTWARE_KEYS))
        if not approval:
            missing.append("/".join(_APPROVAL_KEYS))
        if missing:
            raise SafetyError(
                "SRD backend is opt-in and refused to start: the config "
                f"is missing required approval data ({', '.join(missing)}). "
                "Set these keys explicitly for an Apple-approved SRD "
                "participant; the framework never obtains SRD access.",
                details={
                    "missing_keys": [f"srd.{k}" for k in missing],
                    "required_keys": [
                        "srd.approved_user", "srd.device_model",
                        "srd.build|srd.preview",
                        "srd.approval_reference|srd.approval_artifact"],
                    "remedy": "add an 'srd' object with your approval data "
                              "to config/config.json",
                })
        bad = [f"srd.{key}" for key in (*_REQUIRED_KEYS, *_SOFTWARE_KEYS,
                                        *_APPROVAL_KEYS)
               if self._provided(self.section.get(key))
               and not isinstance(self.section.get(key), str)]
        if bad:
            raise ValidationError(
                f"SRD config values must be strings: {', '.join(bad)}",
                details={"invalid_keys": bad})
        return {
            "approved_user": self.section["approved_user"],
            "device_model": self.section["device_model"],
            "build": self.section.get("build", ""),
            "preview": self.section.get("preview", ""),
            "approval_reference": (self.section.get("approval_reference", "")
                                   or self.section.get("approval_artifact",
                                                       "")),
        }

    @staticmethod
    def _provided(value: Any) -> bool:
        """Explicitly supplied by the user (type checked separately)."""
        return value is not None and value != ""


class SRDDeviceBackend:
    """Lifecycle + provenance for an approved SRD research session."""

    #: Subclasses driving synthetic execution must mark their records so they
    #: cannot be mistaken for real-device evidence.
    FAKE = False

    def __init__(self, config: Config, workspace: Workspace, *,
                 tools_fn: Callable[[], dict[str, str]] = host_tool_versions):
        self.approval = SRDGate(config).require()
        if workspace is None:
            raise ValidationError("SRD backend requires a workspace")
        self.ws = workspace
        self.tools_fn = tools_fn
        self.adapters = _load_adapters(config.get("srd.adapters", {}))
        self.session = self._load_latest_session()

    # -- provenance ---------------------------------------------------------
    def provenance_summary(self) -> dict[str, Any]:
        """User-supplied SRD context plus host tool versions."""
        return {
            "schema_version": SRD_SCHEMA_VERSION,
            "kind": "srd-provenance",
            "device": {
                "model": self.approval["device_model"],
                "build": self.approval["build"],
                "preview": self.approval["preview"],
            },
            "approved_user_context": {
                "approved_user": self.approval["approved_user"],
                "approval_reference": self.approval["approval_reference"],
            },
            "tools": dict(sorted(self.tools_fn().items())),
            "captured_at": now_iso(),
            "source": "user-supplied config; recorded, never requested",
        }

    # -- lifecycle ----------------------------------------------------------
    def prepare(self) -> dict[str, Any]:
        """Create a session and stamp full provenance (idle -> prepared)."""
        existing = self.session
        if existing and existing["state"] in ("idle", "prepared", "ran"):
            return existing
        provenance = self.provenance_summary()
        count = len([r for r in self.ws.list_json("devices")
                     if r.get("kind") == "srd-session"])
        session = {
            "schema_version": SRD_SCHEMA_VERSION,
            "id": make_id("srd", provenance["approved_user_context"]
                          ["approved_user"],
                          provenance["device"]["model"],
                          provenance["device"]["build"],
                          provenance["device"]["preview"], str(count)),
            "kind": "srd-session",
            "state": "idle",
            "fake": self.FAKE,
            "provenance": provenance,
            "runs": [],
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
        session["provenance_log"] = [{
            "op": "prepare", "at": now_iso(), "state": "idle -> prepared"}]
        session["state"] = "prepared"
        self.session = session
        self._save(session)
        return session

    def run(self, adapter_name: str, *, timeout_s: float | None = None,
            notes: str = "") -> dict[str, Any]:
        """Run one allowlisted local adapter (prepared/ran -> ran)."""
        spec = self._adapter_spec(adapter_name)
        # prepare() is idempotent for an active session and starts a fresh
        # one when the previous session ended (collected/failed).
        self.prepare()
        session = self.session
        if session["state"] not in ("prepared", "ran"):
            raise StateError(
                f"SRD session '{session['id']}' is "
                f"'{session['state']}'; expected 'prepared'")
        effective_timeout = float(timeout_s or spec["timeout_s"])
        try:
            run_entry = self._execute_adapter(session, adapter_name, spec,
                                              timeout_s=effective_timeout,
                                              notes=notes)
        except StateError as exc:
            session["state"] = "failed"
            session.setdefault("provenance_log", []).append({
                "op": "run-failed", "at": now_iso(), "adapter": adapter_name,
                "error": str(exc)})
            self._save(session)
            raise
        session["state"] = "ran"
        session["updated_at"] = now_iso()
        session.setdefault("provenance_log", []).append({
            "op": "run", "at": now_iso(), "adapter": adapter_name,
            "tag": run_entry["tag"], "artifact": run_entry["artifact"]})
        session["runs"].append(run_entry)
        self._save(session)
        return session

    def collect(self) -> dict[str, Any]:
        """Finalize the session, grouping evidence by channel (ran ->
        collected)."""
        session = self.session
        if not session or session["state"] != "ran":
            current = session["state"] if session else "(none)"
            raise StateError(
                f"cannot collect an SRD session in state {current}; "
                "run at least one adapter first")
        channels = split_by_channel(session["runs"])
        session["state"] = "collected"
        session["updated_at"] = now_iso()
        session["evidence_channels"] = {
            channel: len(entries) for channel, entries in channels.items()}
        session.setdefault("provenance_log", []).append({
            "op": "collect", "at": now_iso(), "state": "ran -> collected"})
        self._save(session)
        return session

    # -- execution ------------------------------------------------------------
    def _adapter_spec(self, adapter_name: str) -> dict[str, Any]:
        spec = self.adapters.get(adapter_name)
        if spec is None:
            raise ValidationError(
                f"unknown SRD adapter '{adapter_name}'; known: "
                f"{', '.join(sorted(self.adapters)) or '(none)'}")
        return spec

    def _execute_adapter(self, session: dict[str, Any], name: str,
                         spec: dict[str, Any], *, timeout_s: float,
                         notes: str) -> dict[str, Any]:
        artifact_rel = f"artifacts/srd/{session['id']}/{name}.out"
        uses_out = any("{out}" in part for part in spec["argv"])
        argv = [self._expand(part, session, artifact_rel)
                for part in spec["argv"]]
        if uses_out:
            self.ws.path(artifact_rel).parent.mkdir(parents=True, exist_ok=True)
        started_at = now_iso()
        try:
            proc = subprocess.run(argv, shell=False, cwd=str(self.ws.root),
                                  capture_output=True, timeout=timeout_s)
        except OSError as exc:
            raise StateError(
                f"SRD adapter '{name}' failed to start: {exc}",
                details={"adapter": name, "argv_template": spec["argv"]}) \
                from exc
        except subprocess.TimeoutExpired as exc:
            raise StateError(
                f"SRD adapter '{name}' timed out after {timeout_s:g}s",
                details={"adapter": name, "timeout_s": timeout_s}) from exc
        stdout = _tail(redact_text(proc.stdout.decode("utf-8", "replace")))
        stderr = _tail(redact_text(proc.stderr.decode("utf-8", "replace")))
        if proc.returncode != 0:
            raise StateError(
                f"SRD adapter '{name}' exited {proc.returncode}",
                details={"adapter": name, "exit_code": proc.returncode,
                         "stderr_tail": stderr})
        artifact: dict[str, Any] = {}
        if uses_out:
            blob = self.ws.read_bytes(artifact_rel)
            artifact = {"path": artifact_rel, "sha256": sha256_bytes(blob),
                        "size": len(blob)}
        return {
            "adapter": name,
            "tag": f"{SRD_TAG_PREFIX}{name}",
            "channel": "srd",
            "started_at": started_at,
            "finished_at": now_iso(),
            "exit_code": 0,
            "stdout_tail": stdout,
            "stderr_tail": stderr,
            "timeout_s": timeout_s,
            "argv": argv,
            "artifact": artifact,
            "notes": notes,
        }

    def _expand(self, part: str, session: dict[str, Any],
                artifact_rel: str) -> str:
        def sub(match: re.Match[str]) -> str:
            token = match.group(1)
            if token not in _PLACEHOLDERS:
                raise ValidationError(
                    f"unknown SRD adapter placeholder '{{{token}}}'; "
                    f"known: {', '.join(_PLACEHOLDERS)}")
            return {
                "out": str(self.ws.path(artifact_rel)),
                "python": sys.executable,
                "session": session["id"],
                "workspace": str(self.ws.root),
            }[token]

        expanded = _PLACEHOLDER_RE.sub(sub, part)
        if "{" in expanded or "}" in expanded:
            raise ValidationError(
                f"unbalanced braces in SRD adapter argument: {part!r}")
        return expanded

    # -- persistence ----------------------------------------------------------
    def _load_latest_session(self) -> dict[str, Any] | None:
        sessions = [r for r in self.ws.list_json("devices")
                    if r.get("kind") == "srd-session"]
        if not sessions:
            return None
        return max(sessions, key=lambda r: (r.get("created_at", ""),
                                            r.get("id", "")))

    def _save(self, session: dict[str, Any]) -> None:
        self.ws.write_json(f"devices/{session['id']}.json", session)


class FakeSRDBackend(SRDDeviceBackend):
    """Deterministic in-memory-drive SRD backend for CI and tests.

    Mirrors the real lifecycle and record shapes exactly (including
    provenance, redaction, and failure semantics) but never spawns a
    subprocess and never touches a device. Records are marked ``fake: true``
    so they cannot be mistaken for real-device evidence.
    """

    FAKE = True

    FAKE_TOOLS = {"python": "3.fake.0", "platform": "ci/x86_64",
                  "xcodebuild": "Xcode 99.0 (fake)"}

    def __init__(self, config: Config, workspace: Workspace, *,
                 fail_step: str = "", fail_message: str = ""):
        super().__init__(config, workspace,
                         tools_fn=lambda: dict(self.FAKE_TOOLS))
        self.fail_step = fail_step
        self.fail_message = fail_message or "injected fake failure"
        self.calls: list[tuple[str, ...]] = []

    def prepare(self) -> dict[str, Any]:
        self.calls.append(("prepare",))
        if self.fail_step == "prepare":
            raise StateError(f"fake prepare failure: {self.fail_message}")
        return super().prepare()

    def _adapter_spec(self, adapter_name: str) -> dict[str, Any]:
        # The fake backend accepts any adapter name; nothing is executed.
        return {"argv": ["<fake>"],
                "timeout_s": _DEFAULT_ADAPTER_TIMEOUT_S,
                "description": "synthetic fake adapter"}

    def _execute_adapter(self, session, name, spec, *, timeout_s, notes=""):
        self.calls.append(("run", name))
        if self.fail_step == "run":
            raise StateError(f"fake run failure: {self.fail_message}",
                             details={"adapter": name})
        artifact_rel = f"artifacts/srd/{session['id']}/{name}.out"
        blob = f"fake output for {name}\npassword=hunter2\n".encode()
        self.ws.write_bytes(artifact_rel, blob)
        return {
            "adapter": name,
            "tag": f"{SRD_TAG_PREFIX}{name}",
            "channel": "srd",
            "started_at": now_iso(),
            "finished_at": now_iso(),
            "exit_code": 0,
            "stdout_tail": redact_text(blob.decode()),
            "stderr_tail": "",
            "timeout_s": timeout_s or _DEFAULT_ADAPTER_TIMEOUT_S,
            "argv": ["<fake>"],
            "artifact": {"path": artifact_rel, "sha256": sha256_bytes(blob),
                         "size": len(blob)},
            "notes": notes,
        }

    def collect(self) -> dict[str, Any]:
        self.calls.append(("collect",))
        if self.fail_step == "collect":
            raise StateError(f"fake collect failure: {self.fail_message}")
        return super().collect()


def _load_adapters(raw: Any) -> dict[str, dict[str, Any]]:
    """Validate the researcher-authored ``srd.adapters`` allowlist."""
    if raw in (None, {}):
        return {}
    if not isinstance(raw, dict):
        raise ValidationError("srd.adapters must be a JSON object keyed by "
                              "adapter name")
    adapters: dict[str, dict[str, Any]] = {}
    for name, spec in sorted(raw.items()):
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_-]+", name):
            raise ValidationError(
                f"SRD adapter names must be lowercase identifiers: {name!r}")
        if not isinstance(spec, dict):
            raise ValidationError(
                f"SRD adapter '{name}' must be an object with an 'argv' list")
        argv = spec.get("argv")
        if (not isinstance(argv, list) or not argv
                or not all(isinstance(p, str) and p for p in argv)):
            raise ValidationError(
                f"SRD adapter '{name}' needs a non-empty 'argv' list of "
                "strings (executed without a shell)")
        timeout = spec.get("timeout_s", _DEFAULT_ADAPTER_TIMEOUT_S)
        if not isinstance(timeout, (int, float)) or not (
                0 < float(timeout) <= MAX_ADAPTER_TIMEOUT_S):
            raise ValidationError(
                f"SRD adapter '{name}' timeout_s must be in "
                f"(0, {MAX_ADAPTER_TIMEOUT_S:.0f}]")
        description = spec.get("description", "")
        if not isinstance(description, str):
            raise ValidationError(
                f"SRD adapter '{name}' description must be a string")
        for part in argv:
            for token in _PLACEHOLDER_RE.findall(part):
                if token not in _PLACEHOLDERS:
                    raise ValidationError(
                        f"SRD adapter '{name}' uses unknown placeholder "
                        f"'{{{token}}}'; known: {', '.join(_PLACEHOLDERS)}")
        adapters[name] = {
            "argv": argv,
            "timeout_s": float(timeout),
            "description": description,
        }
    return adapters


def _tail(text: str) -> str:
    return text[-_OUTPUT_TAIL_CHARS:] if len(text) > _OUTPUT_TAIL_CHARS \
        else text
