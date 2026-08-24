"""Xcode test-plan adapter and XCResult diagnostic ingestion (#36).

Lets an authorized, source-available Apple-app target use native Xcode test
plans: import a user-declared ``.xctestplan``, build (optionally run)
``xcodebuild test`` commands with sanitizer options, parse ``xcresulttool``
JSON exports into normalized diagnostics, and map a failure to a focused
reproduction command.

Boundaries (mirroring the issue's acceptance criteria):
- No system-process debugging, entitlement escalation, or privilege bypass:
  this module only *parses declared files* and *constructs commands*; running
  ``xcodebuild`` is an explicit, availability-gated opt-in.
- Unsupported diagnostics are reported as ``unrecognized`` entries with the
  raw issue type, never silently dropped and never interpreted.
- Everything except a real ``xcodebuild`` invocation is deterministic and
  CI-safe (fixtures only; no Xcode required).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .clock import now_iso
from .errors import NotFoundError, StateError, ValidationError
from .hashing import sha256_bytes
from .ids import make_id
from .workspace import Workspace

SCHEMA_VERSION = 1

# Sanitizer/diagnostic options supported by xcodebuild test runs.
SANITIZER_FLAGS = {
    "address": ("-enableAddressSanitizer", "YES"),
    "thread": ("-enableThreadSanitizer", "YES"),
    "undefined-behavior": ("-enableUndefinedBehaviorSanitizer", "YES"),
    "main-thread-checker": ("-enableMainThreadChecker", "YES"),
    "zombies": ("-enableZombieObjects", "YES"),
}

# Issue types this adapter normalizes; anything else is reported unrecognized.
KNOWN_ISSUE_TYPES = {"Test Failure", "Crash", "Sanitizer"}

# Structural container names the walker understands; other container types are
# surfaced as unrecognized so future diagnostics are visible, never dropped.
_PRIMITIVES = {"String", "Boolean", "Integer", "Double", "Array", "Date"}
_KNOWN_CONTAINERS = {
    "ActionsInvocationRecord", "ActionRunSummary", "ActionRecord",
    "Test Failure", "Failure", "Test Case", "TestCase", "Test Name",
    "Message", "Coverage", "Code Coverage", "CodeCoverage",
    "Target Device", "Test Config", "Run Operation",
    "Issue", "Issues", "Warning", "Activity", "OS Version", "Model",
}


# ---------------------------------------------------------------------------
# Test plans (.xctestplan JSON)
# ---------------------------------------------------------------------------

def parse_test_plan(path: str) -> dict[str, Any]:
    """Parse and normalize a user-declared ``.xctestplan`` JSON file."""
    plan_path = Path(path)
    if not plan_path.is_file():
        raise NotFoundError(f"test plan '{path}' not found")
    try:
        raw = json.loads(plan_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from None
    if not isinstance(raw, dict) or not isinstance(raw.get("testTargets"),
                                                   list) \
            or not raw["testTargets"]:
        raise ValidationError(
            f"{path}: a test plan needs a non-empty 'testTargets' array")
    targets = []
    for i, entry in enumerate(raw["testTargets"]):
        if not isinstance(entry, dict):
            raise ValidationError(f"{path}: testTargets[{i}] must be an object")
        target = entry.get("target") or {}
        name = target.get("name") if isinstance(target, dict) else None
        if not isinstance(name, str) or not name.strip():
            raise ValidationError(
                f"{path}: testTargets[{i}].target.name is required")
        targets.append({"name": name,
                        "skipped": bool(entry.get("skipped", False))})
    return {
        "schema_version": SCHEMA_VERSION,
        "name": plan_path.stem,
        "source_path": str(plan_path),
        "targets": targets,
        "default_options": (raw.get("defaultOptions")
                            if isinstance(raw.get("defaultOptions"), dict)
                            else {}),
        "imported_at": now_iso(),
    }


class PlanStore:
    """Workspace-persisted imported test plans."""

    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def _rel(self, plan_id: str) -> str:
        return f"xcode/plans/{plan_id}.json"

    def save(self, plan: dict[str, Any]) -> dict[str, Any]:
        plan_id = make_id("xplan", plan["name"], plan["source_path"],
                          plan["imported_at"])
        plan["id"] = plan_id
        self.ws.write_json(self._rel(plan_id), plan)
        return plan

    def get(self, plan_id: str) -> dict[str, Any]:
        if not self.ws.path(self._rel(plan_id)).exists():
            raise NotFoundError(f"test plan '{plan_id}' not found")
        return self.ws.read_json(self._rel(plan_id))

    def list(self) -> list[dict[str, Any]]:
        base = self.ws.dir("xcode") / "plans"
        if not base.exists():
            return []
        out = []
        for path in sorted(base.glob("*.json")):
            out.append(self.ws.read_json(str(path.relative_to(self.ws.root))))
        return out


# ---------------------------------------------------------------------------
# Command construction (pure; never executes)
# ---------------------------------------------------------------------------

def build_test_command(plan: dict[str, Any], *, project: str | None = None,
                       workspace_swift: str | None = None,
                       only_testing: list[str] | None = None,
                       sanitizers: list[str] | None = None,
                       destination: str | None = None,
                       result_bundle_path: str | None = None
                       ) -> list[str]:
    """Construct an ``xcodebuild test`` argv from a normalized plan.

    Pure function: returns the command without running it. Unknown sanitizer
    names are rejected so a typo cannot silently disable a diagnostic.
    """
    cmd = ["xcodebuild", "test"]
    if project:
        cmd += ["-project", project]
    if workspace_swift:
        cmd += ["-workspace", workspace_swift]
    if not project and not workspace_swift:
        raise ValidationError(
            "an Xcode project (-project) or workspace (-workspace) is "
            "required to build a test command")
    cmd += ["-testPlan", plan["name"]]
    if destination:
        cmd += ["-destination", destination]
    for name in sanitizers or []:
        flag = SANITIZER_FLAGS.get(name)
        if flag is None:
            raise ValidationError(
                f"unsupported sanitizer '{name}'; supported: "
                f"{', '.join(sorted(SANITIZER_FLAGS))}")
        cmd += list(flag)
    for test in only_testing or []:
        cmd += ["-only-testing", test]
    if result_bundle_path:
        cmd += ["-resultBundlePath", result_bundle_path]
    return cmd


def map_repro_command(plan: dict[str, Any], *, failing_test: str,
                      project: str | None = None,
                      workspace_swift: str | None = None,
                      sanitizers: list[str] | None = None) -> list[str]:
    """Focused reproduction command for one failing test identifier."""
    return build_test_command(
        plan, project=project, workspace_swift=workspace_swift,
        only_testing=[failing_test], sanitizers=sanitizers)


# ---------------------------------------------------------------------------
# xcodebuild backend (opt-in execution)
# ---------------------------------------------------------------------------

class XcodebuildBackend:
    """Real backend over the ``xcodebuild`` tool. Never used in CI."""

    def __init__(self) -> None:
        self._tool = shutil.which("xcodebuild")

    def available(self) -> bool:
        return self._tool is not None

    def blocker(self) -> str:
        if self._tool is None:
            return ("xcodebuild not found on PATH; install Xcode command "
                    "line tools (`xcode-select --install`) or run with "
                    "--dry-run to construct the command only")
        return ""

    def run(self, cmd: list[str], *, timeout_s: float = 600.0
            ) -> dict[str, Any]:
        blocker = self.blocker()
        if blocker:
            raise StateError(f"xcodebuild unavailable: {blocker}",
                             details={"command": cmd})
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout_s)
        except subprocess.TimeoutExpired:
            raise StateError(
                f"xcodebuild exceeded {timeout_s:g}s and was terminated")
        return {"exit_code": proc.returncode,
                "stdout_tail": proc.stdout[-4000:],
                "stderr_tail": proc.stderr[-4000:]}


# ---------------------------------------------------------------------------
# XCResult ingestion (xcresulttool JSON export format)
# ---------------------------------------------------------------------------

def _walk_values(node: Any) -> list[dict[str, Any]]:
    """Return the ``_values`` array of an xcresulttool object-graph node."""
    if isinstance(node, dict):
        values = node.get("_values")
        if isinstance(values, list):
            return [v for v in values if isinstance(v, dict)]
    return []


def _node_name(node: dict[str, Any]) -> str:
    t = node.get("_type")
    if isinstance(t, dict):
        return str(t.get("_name", ""))
    return ""


def _classify_sanitizer(message: str) -> dict[str, str]:
    lowered = message.lower()
    if "addresssanitizer" in lowered:
        if "write" in lowered:
            return {"sanitizer": "address",
                    "classification_hint": "OUT_OF_BOUNDS_WRITE"}
        if "read" in lowered:
            return {"sanitizer": "address",
                    "classification_hint": "OUT_OF_BOUNDS_READ"}
        return {"sanitizer": "address", "classification_hint": "UNKNOWN"}
    if "threadsanitizer" in lowered or "data race" in lowered:
        return {"sanitizer": "thread", "classification_hint": "UNKNOWN"}
    if "undefinedbehaviorsanitizer" in lowered or "ubsan" in lowered:
        return {"sanitizer": "undefined-behavior",
                "classification_hint": "UNKNOWN"}
    if "main thread checker" in lowered:
        return {"sanitizer": "main-thread-checker",
                "classification_hint": "UNKNOWN"}
    if "zombie" in lowered or "message sent to deallocated" in lowered:
        return {"sanitizer": "zombies", "classification_hint": "USE_AFTER_FREE"}
    return {"sanitizer": "", "classification_hint": "UNKNOWN"}


def _extract_environment(node: dict[str, Any]) -> dict[str, str]:
    """Pull OS/device provenance from a device/config node (or its parent)."""
    env: dict[str, str] = {}

    def add_key_nodes(key_nodes: list[dict[str, Any]]) -> None:
        for key_node in key_nodes:
            key = _node_name(key_node)
            if not key or key in _PRIMITIVES:
                continue
            for leaf in _walk_values(key_node):
                if _node_name(leaf) == "String":
                    value = leaf.get("_value")
                    if isinstance(value, str):
                        env.setdefault(key.lower().replace(" ", "_"), value)

    name = _node_name(node)
    if name in ("Target Device", "Test Config"):
        add_key_nodes(_walk_values(node))
        return env
    for child in _walk_values(node):
        if _node_name(child) in ("Target Device", "Test Config"):
            add_key_nodes(_walk_values(child))
    return env


def parse_xcresult_export(export: dict[str, Any], *,
                          source: str = "<memory>") -> dict[str, Any]:
    """Normalize an ``xcresulttool get --format json`` export.

    Returns failures (with sanitizer attribution where the message makes it
    unambiguous), coverage summaries, environment provenance, and an
    ``unrecognized`` list for issue types this adapter does not model.
    """
    if not isinstance(export, dict):
        raise ValidationError(f"{source}: xcresult export must be a JSON object")
    failures: list[dict[str, Any]] = []
    unrecognized: list[dict[str, str]] = []
    environment: dict[str, str] = {}
    coverage: dict[str, Any] = {}

    def visit(node: dict[str, Any]) -> None:
        name = _node_name(node)
        if name in ("Test Failure", "Failure"):
            message = ""
            test_name = ""
            for child in _walk_values(node):
                child_name = _node_name(child)
                if child_name in ("String", "Message"):
                    value = child.get("_value")
                    if isinstance(value, str) and not message:
                        message = value
                if child_name in ("Test Case", "TestCase", "Test Name"):
                    for leaf in _walk_values(child):
                        value = leaf.get("_value")
                        if isinstance(value, str) and not test_name:
                            test_name = value
            attribution = _classify_sanitizer(message)
            failures.append({
                "test": test_name,
                "message": message[:500],
                **attribution,
            })
        elif name in ("Coverage", "Code Coverage", "CodeCoverage"):
            for child in _walk_values(node):
                value = child.get("_value")
                if isinstance(value, (int, float)) \
                        and _node_name(child) in ("Line Coverage", "Percentage"):
                    coverage.setdefault("entries", {})[_node_name(child)] = value
        elif name in ("Target Device", "Test Config", "Run Operation"):
            environment.update(_extract_environment(node))
        elif name in ("Issue", "Issues", "Warning", "Activity"):
            for child in _walk_values(node):
                visit(child)
        elif name and name not in _PRIMITIVES:
            if name not in _KNOWN_CONTAINERS:
                unrecognized.append({"issue_type": name, "where": source})
            for child in _walk_values(node):
                visit(child)

    visit(export)
    return {
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "failures": failures,
        "coverage": coverage,
        "environment": environment,
        "unrecognized": unrecognized,
        "parsed_at": now_iso(),
    }


class XCResultStore:
    """Persist normalized xcresult parses in the workspace."""

    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def save(self, normalized: dict[str, Any],
             raw_bytes: bytes | None = None) -> dict[str, Any]:
        record_id = make_id("xcresult", normalized["source"],
                            normalized["parsed_at"])
        normalized["id"] = record_id
        self.ws.write_json(f"xcode/xcresults/{record_id}.json", normalized)
        if raw_bytes is not None:
            self.ws.write_bytes(f"xcode/xcresults/{record_id}.raw.json",
                                raw_bytes)
        return normalized

    def get(self, record_id: str) -> dict[str, Any]:
        rel = f"xcode/xcresults/{record_id}.json"
        if not self.ws.path(rel).exists():
            raise NotFoundError(f"xcresult record '{record_id}' not found")
        return self.ws.read_json(rel)

    def list(self) -> list[dict[str, Any]]:
        base = self.ws.dir("xcode") / "xcresults"
        if not base.exists():
            return []
        out = []
        for path in sorted(base.glob("*.json")):
            if path.name.endswith(".raw.json"):
                continue
            out.append(self.ws.read_json(str(path.relative_to(self.ws.root))))
        return out


def parse_xcresult_path(path: str, *, backend: XcodebuildBackend | None = None
                        ) -> tuple[dict[str, Any], bytes | None]:
    """Parse an ``.xcresult`` bundle or a pre-exported JSON file.

    Bundles require ``xcrun xcresulttool`` (availability-gated); exported
    JSON files parse anywhere and are the CI-safe path.
    """
    bundle = Path(path)
    if not bundle.exists():
        raise NotFoundError(f"xcresult '{path}' not found")
    if bundle.is_dir():
        backend = backend or XcodebuildBackend()
        if not backend.available():
            raise StateError(
                "parsing an .xcresult bundle requires xcrun xcresulttool; "
                f"unavailable: {backend.blocker()} Alternatively export the "
                "bundle to JSON first: `xcrun xcresulttool get --path ... "
                "--format json > export.json` and parse the JSON file.")
        proc = subprocess.run(
            ["xcrun", "xcresulttool", "get", "--path", str(bundle),
             "--format", "json"], capture_output=True, timeout=120)
        if proc.returncode != 0:
            raise StateError(
                "xcresulttool failed",
                details={"stderr": proc.stderr.decode("utf-8", "replace")[-500:]})
        raw = proc.stdout
    else:
        raw = bundle.read_bytes()
    try:
        export = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(
            f"{path}: not a valid xcresult JSON export ({exc})") from None
    return parse_xcresult_export(export, source=path), raw
