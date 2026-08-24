"""Xcode test-plan adapter and XCResult diagnostic ingestion (#36).

Lets an authorized, source-available Apple-app target use native Xcode test
plans: import a user-declared ``.xctestplan``, build (optionally run)
``xcodebuild test`` commands with sanitizer options, parse ``xcresult``
bundle layouts (stdlib-only, tolerant) or ``xcresulttool`` JSON exports
into normalized diagnostics, and map a failure or a minimized fuzz input
to a focused reproduction command.

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
import plistlib
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

# KNOWN-DIAGNOSTICS table: every diagnostic this adapter understands, mapped to
# its ``xcodebuild`` flag. Anything outside the table is rejected with an
# actionable VALIDATION error naming the supported set — a typo must never
# silently disable a diagnostic.
SANITIZER_FLAGS = {
    "address": ("-enableAddressSanitizer", "YES"),
    "thread": ("-enableThreadSanitizer", "YES"),
    "undefined-behavior": ("-enableUndefinedBehaviorSanitizer", "YES"),
    "main-thread-checker": ("-enableMainThreadChecker", "YES"),
    "guard-malloc": ("-enableGuardMalloc", "YES"),
    "zombies": ("-enableZombieObjects", "YES"),
    "code-coverage": ("-enableCodeCoverage", "YES"),
}

KNOWN_DIAGNOSTICS = tuple(sorted(SANITIZER_FLAGS))

# Scheme-editor diagnostic switches found in .xctestplan ``defaultOptions``,
# lowercased, mapped to their canonical name in the table above.
_PLAN_DIAGNOSTIC_KEYS = {
    "addresssanitizer": "address",
    "threadsanitizer": "thread",
    "undefinedbehaviorsanitizer": "undefined-behavior",
    "mainthreadchecker": "main-thread-checker",
    "guardmalloc": "guard-malloc",
    "zombieobjects": "zombies",
    "codecoverage": "code-coverage",
}


def _unsupported_diagnostic_error(source_path: str, name: str) -> ValidationError:
    return ValidationError(
        f"{source_path}: unsupported diagnostic '{name}'; supported "
        f"diagnostics: {', '.join(KNOWN_DIAGNOSTICS)}")


def validate_plan_diagnostics(plan_path: str,
                              default_options: dict[str, Any] | None,
                              declared: list[str] | None = None
                              ) -> list[str]:
    """Validate a plan's declared diagnostics against the known table.

    Returns the canonical names of enabled diagnostics. Unknown *diagnostic-
    looking* options (e.g. ``quantumSanitizer``) are actionable VALIDATION
    errors; unrelated plan metadata (e.g. ``targetForVariableExpansion``) is
    ignored.
    """
    enabled: list[str] = list(declared or [])
    for key, value in (default_options or {}).items():
        lowered = str(key).lower()
        canonical = _PLAN_DIAGNOSTIC_KEYS.get(lowered)
        if canonical is None:
            looks_diagnostic = (lowered.endswith("sanitizer")
                                or "checker" in lowered or "zombie" in lowered
                                or "guard" in lowered or "coverage" in lowered)
            if looks_diagnostic:
                raise _unsupported_diagnostic_error(plan_path, str(key))
            continue
        if str(value).strip().upper() in ("YES", "TRUE", "1") \
                and canonical not in enabled:
            enabled.append(canonical)
    unknown = [n for n in enabled if n not in SANITIZER_FLAGS]
    if unknown:
        raise _unsupported_diagnostic_error(plan_path, unknown[0])
    return sorted(set(enabled))

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
        # Real plans carry the module as ``identifier`` next to a
        # ``containerPath``; accept ``name`` too for hand-written plans.
        name = None
        if isinstance(target, dict):
            name = target.get("name") or target.get("identifier")
        if not isinstance(name, str) or not name.strip():
            raise ValidationError(
                f"{path}: testTargets[{i}].target.name is required")
        targets.append({"name": name,
                        "skipped": bool(entry.get("skipped", False))})
    default_options = (raw.get("defaultOptions")
                       if isinstance(raw.get("defaultOptions"), dict) else {})
    declared = raw.get("ios_research_diagnostics") \
        if isinstance(raw.get("ios_research_diagnostics"), list) else None
    diagnostics = validate_plan_diagnostics(str(path), default_options,
                                            declared)
    return {
        "schema_version": SCHEMA_VERSION,
        "name": plan_path.stem,
        "source_path": str(plan_path),
        "targets": targets,
        "diagnostics": diagnostics,
        "default_options": default_options,
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

    Pure function: returns the command without running it. Unknown diagnostic
    names are rejected so a typo cannot silently disable a diagnostic.
    Diagnostics declared in the imported plan are applied unless an explicit
    ``sanitizers`` selection is given.
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
    selected = sanitizers if sanitizers is not None \
        else list(plan.get("diagnostics") or [])
    for name in selected:
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


def map_repro_from_input(plan: dict[str, Any], *, input_path: str,
                         actions: list[str] | None = None,
                         project: str | None = None,
                         workspace_swift: str | None = None,
                         sanitizers: list[str] | None = None,
                         test: str | None = None) -> dict[str, Any]:
    """Map a minimized fuzz input (+ optional action sequence) to a focused
    ``xcodebuild`` reproduction command.

    Pure function: constructs argv and metadata only; nothing executes. The
    minimized input travels to the test runner via the documented
    ``TEST_RUNNER_*`` environment convention, returned in ``environment`` for
    the caller to apply at invocation time. The focused scope is ``test`` when
    given, otherwise the plan's first active target.
    """
    fuzz_input = Path(input_path)
    if not fuzz_input.is_file():
        raise NotFoundError(f"fuzz input '{input_path}' not found")
    focus = test or next(
        (t["name"] for t in plan.get("targets", [])
         if isinstance(t, dict) and not t.get("skipped")), None)
    if not focus:
        raise ValidationError(
            "plan has no active test target to focus the reproduction on")
    argv = build_test_command(
        plan, project=project, workspace_swift=workspace_swift,
        only_testing=[focus], sanitizers=sanitizers)
    environment = {"TEST_RUNNER_FUZZ_INPUT": str(fuzz_input)}
    if actions:
        environment["TEST_RUNNER_ACTIONS"] = ",".join(actions)
    return {
        "command": argv,
        "only_testing": focus,
        "input_path": str(fuzz_input),
        "input_sha256": sha256_bytes(fuzz_input.read_bytes()),
        "actions": list(actions or []),
        "environment": environment,
    }


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
# XCResult ingestion (bundle layout + xcresulttool JSON export format)
# ---------------------------------------------------------------------------

def tool_provenance() -> dict[str, Any]:
    """Record local toolchain provenance without executing anything.

    Only PATH resolution is performed, so this stays deterministic and safe in
    CI; actual versions are captured when a real run happens.
    """
    return {"xcodebuild_path": shutil.which("xcodebuild"),
            "xcrun_path": shutil.which("xcrun"),
            "recorded_at": now_iso()}


def _load_object_graph(data: bytes) -> tuple[dict[str, Any] | None, str]:
    """Tolerantly decode a SupportFiles payload as plist or JSON."""
    try:
        graph = plistlib.loads(data)
        if isinstance(graph, dict):
            return graph, ""
    except Exception:  # noqa: BLE001 - tolerant by design
        pass
    try:
        graph = json.loads(data.decode("utf-8"))
        if isinstance(graph, dict):
            return graph, ""
        return None, "object graph is not a JSON object"
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"not plist or JSON: {exc}"


def parse_xcresult_bundle(path: str) -> dict[str, Any]:
    """Parse an ``.xcresult`` *bundle directory* using only the stdlib.

    Tolerant walker over the on-disk layout — ``Info.plist`` for provenance,
    ``SupportFiles/*.xcresulttest`` object graphs (plist or JSON; delegated to
    :func:`parse_xcresult_export` when recognizable), and plain log files.
    Normalizes to ``{crashes[], logs[], coverage{}, provenance{}}``. No Xcode
    tooling is required or invoked, which makes this the CI-safe ingestion path.
    """
    root = Path(path)
    info = root / "Info.plist"
    if not root.is_dir():
        raise NotFoundError(f"xcresult bundle '{path}' not found")
    if not info.is_file():
        raise ValidationError(
            f"{path}: not an .xcresult bundle (missing Info.plist); "
            "export it to JSON with `xcrun xcresulttool get --format json` "
            "and parse the JSON instead")
    provenance: dict[str, Any] = {}
    try:
        with open(info, "rb") as fh:
            meta = plistlib.load(fh)
        provenance.update(
            {str(k): v for k, v in meta.items()
             if isinstance(v, (str, int, float, bool))})
    except Exception as exc:  # noqa: BLE001 - actionable, not fatal
        raise ValidationError(f"{info}: unreadable Info.plist ({exc})") from None

    crashes: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    coverage: dict[str, Any] = {}
    unrecognized: dict[str, dict[str, str]] = {}

    def merge_export(parsed: dict[str, Any]) -> None:
        crashes.extend(parsed["failures"])
        for key, value in (parsed.get("coverage") or {}).items():
            if isinstance(value, dict) and isinstance(coverage.get(key), dict):
                coverage[key].update(value)
            else:
                coverage[key] = value
        provenance.update(parsed.get("environment") or {})
        for item in parsed["unrecognized"]:
            unrecognized.setdefault(item["issue_type"], item)

    support = root / "SupportFiles"
    if support.is_dir():
        for entry in sorted(support.iterdir()):
            if not entry.is_file():
                continue
            is_graph = (entry.suffix == ".xcresulttest"
                        or entry.name in ("object_graph.json", "export.json"))
            if is_graph:
                data = entry.read_bytes()
                graph, err = _load_object_graph(data)
                if graph is not None:
                    merge_export(parse_xcresult_export(graph,
                                                       source=str(entry)))
                else:
                    logs.append({"name": entry.name, "bytes": len(data),
                                 "note": err})
            elif entry.suffix in (".log", ".txt"):
                text = entry.read_text(encoding="utf-8", errors="replace")
                logs.append({
                    "name": entry.name,
                    "bytes": len(text.encode("utf-8")),
                    "excerpt": [line for line in text.splitlines()
                                if line.strip()][:5],
                })
    return {
        "schema_version": SCHEMA_VERSION,
        "source": str(root),
        "crashes": crashes,
        "logs": logs,
        "coverage": coverage,
        "provenance": provenance,
        "unrecognized": sorted(unrecognized.values(),
                               key=lambda u: u["issue_type"]),
        "parsed_at": now_iso(),
    }


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

    Bundle directories with the standard layout (``Info.plist``) parse
    hermetically via :func:`parse_xcresult_bundle`; bundles without that
    layout need ``xcrun xcresulttool`` (availability-gated). Exported JSON
    files always parse anywhere.
    """
    bundle = Path(path)
    if not bundle.exists():
        raise NotFoundError(f"xcresult '{path}' not found")
    if bundle.is_dir():
        if (bundle / "Info.plist").is_file():
            return parse_xcresult_bundle(path), None
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
