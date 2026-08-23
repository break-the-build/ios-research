"""Versioned grammar-aware mutator plugins (#41).

A *plugin* teaches the framework one structured format so mutation preserves
validity instead of corrupting inputs before deep parsing. Plugins implement a
small, versioned interface:

    parse(data) -> AST | None     return ``None`` to signal "not my format"
    generate(rng) -> AST          synthesize a fresh AST
    mutate(ast, rng) -> AST | None
    crossover(a, b, rng) -> AST | None   structural recombination
    repair(ast) -> AST            fix self-consistency after mutation
    serialize(ast) -> bytes
    validity_score(data) -> float | None  optional 0..1 validity estimate

Trust boundary: plugins are **user-declared local code** loaded only from
explicitly supplied paths — same trust level as a researcher's own harness.
The host isolates every plugin call: an exception, a timeout budget, or
malformed output falls back to generic mutation and can never corrupt the
corpus or abort a campaign. Output size is bounded. All randomness comes from
an injected seeded RNG, so results are reproducible for a fixed
``(seed, input)`` pair, and lineage records ``grammar:<id>@<version>``.
"""

from __future__ import annotations

import importlib.util
import inspect
import time
from pathlib import Path
from typing import Any, Protocol

from .errors import ValidationError
from .hashing import sha256_text

PLUGIN_INTERFACE_VERSION = 1
MAX_PLUGIN_FILES = 16
MAX_AST_NODES = 4096
MAX_OUTPUT_BYTES = 1024 * 1024
DEFAULT_STAGE_BUDGET_S = 5.0


class MutatorPlugin(Protocol):
    """Structural contract a plugin module must expose as ``PLUGIN``."""

    plugin_id: str
    version: str

    def parse(self, data: bytes) -> Any | None: ...
    def generate(self, rng) -> Any: ...
    def mutate(self, node: Any, rng) -> Any | None: ...
    def crossover(self, a: Any, b: Any, rng) -> Any | None: ...
    def repair(self, node: Any) -> Any: ...
    def serialize(self, node: Any) -> bytes: ...
    def validity_score(self, data: bytes) -> float | None: ...


class _Deadline:
    def __init__(self, budget_s: float):
        self.deadline = time.monotonic() + budget_s

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline


class PluginHost:
    """Loads and drives plugins with bounded resources and total isolation."""

    def __init__(self, *, stage_budget_s: float = DEFAULT_STAGE_BUDGET_S):
        self.plugins: list[MutatorPlugin] = []
        self.stage_budget_s = stage_budget_s
        self.fallbacks = 0          # plugin failed -> generic mutation used
        self.last_error = ""

    # -- discovery ----------------------------------------------------------
    def discover(self, paths: list[str | Path]) -> "PluginHost":
        """Load plugins from user-declared files/directories only."""
        candidates: list[Path] = []
        for raw in paths[:MAX_PLUGIN_FILES]:
            path = Path(raw)
            if path.is_dir():
                candidates.extend(sorted(path.glob("*.py")))
            elif path.is_file():
                candidates.append(path)
        for candidate in candidates[:MAX_PLUGIN_FILES]:
            plugin = self._load_one(candidate)
            if plugin is not None:
                self.plugins.append(plugin)
        return self

    def _load_one(self, path: Path) -> MutatorPlugin | None:
        try:
            spec = importlib.util.spec_from_file_location(
                f"iosr_plugin_{sha256_text(str(path))[:10]}", path)
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)   # user-declared, trusted code
            plugin = getattr(module, "PLUGIN", None)
        except Exception:  # noqa: BLE001 - isolation boundary
            self.fallbacks += 1
            self.last_error = f"plugin load failed: {path}"
            return None
        if plugin is None or not self._implements_interface(plugin):
            self.fallbacks += 1
            self.last_error = f"module exposes no valid PLUGIN: {path}"
            return None
        return plugin

    @staticmethod
    def _implements_interface(plugin: object) -> bool:
        required = ("parse", "generate", "mutate", "crossover",
                    "repair", "serialize")
        return (hasattr(plugin, "plugin_id")
                and hasattr(plugin, "version")
                and all(callable(getattr(plugin, name, None))
                        for name in required))

    # -- guarded calls --------------------------------------------------------
    def _call(self, method_name: str, plugin: MutatorPlugin, *args) -> tuple[bool, Any]:
        deadline = _Deadline(self.stage_budget_s)
        try:
            result = getattr(plugin, method_name)(*args)
            if deadline.expired():
                raise TimeoutError(method_name)
            return True, result
        except Exception as exc:  # noqa: BLE001 - isolation boundary
            self.fallbacks += 1
            self.last_error = (
                f"{getattr(plugin, 'plugin_id', '?')}.{method_name}: {exc}")
            return False, None

    # -- high-level operations --------------------------------------------------
    def plugin_for(self, data: bytes) -> MutatorPlugin | None:
        """First plugin whose ``parse`` accepts the seed (deterministic order)."""
        ok_by_size = len(data) <= MAX_OUTPUT_BYTES * 4
        for plugin in self.plugins:
            if not ok_by_size:
                return None
            parsed_ok, node = self._call("parse", plugin, data)
            if parsed_ok and node is not None and self._bounded(node):
                return plugin
        return None

    @staticmethod
    def _bounded(node: Any, depth: int = 0) -> bool:
        if depth > 32:
            return False
        try:
            if isinstance(node, (list, tuple)):
                return (len(node) <= MAX_AST_NODES
                        and all(PluginHost._bounded(child, depth + 1)
                                for child in node))
            if isinstance(node, dict):
                return (len(node) <= MAX_AST_NODES
                        and all(PluginHost._bounded(value, depth + 1)
                                for value in node.values()))
            return True
        except Exception:  # noqa: BLE001 - defensive
            return False

    def mutate_bytes(self, data: bytes, rng) -> tuple[bytes, str] | None:
        """Grammar-aware mutation; ``None`` = fall back to generic mutation.

        Flow: parse -> mutate -> repair -> serialize, preferring a plugin that
        accepts the seed. Any failure returns ``None`` (never raises).
        """
        plugin = self.plugin_for(data)
        if plugin is None:
            return None
        _ok, node = self._call("parse", plugin, data)
        if not _ok or node is None:
            return None
        mutated_ok, mutated = self._call("mutate", plugin, node, rng)
        if not mutated_ok or mutated is None:
            return None
        repaired_ok, repaired = self._call("repair", plugin, mutated)
        node_out = repaired if (repaired_ok and repaired is not None) else mutated
        serialized_ok, blob = self._call("serialize", plugin, node_out)
        if not serialized_ok or not isinstance(blob, (bytes, bytearray)):
            return None
        blob = bytes(blob)
        if len(blob) > MAX_OUTPUT_BYTES:
            self.fallbacks += 1
            self.last_error = (f"{plugin.plugin_id}: serialize output "
                               f"exceeds {MAX_OUTPUT_BYTES} bytes")
            return None
        return blob, f"grammar:{plugin.plugin_id}@{plugin.version}"

    def crossover_bytes(self, a: bytes, b: bytes,
                        rng) -> tuple[bytes, str] | None:
        """Structured crossover when both parents share a plugin format."""
        plugin = self.plugin_for(a)
        other = plugin if (plugin is not None
                           and self.plugin_for(b) is plugin) else None
        if other is None:
            return None
        _ok_a, node_a = self._call("parse", plugin, a)
        _ok_b, node_b = self._call("parse", plugin, b)
        if not (_ok_a and _ok_b and node_a is not None and node_b is not None):
            return None
        crossed_ok, crossed = self._call("crossover", plugin, node_a, node_b, rng)
        if not crossed_ok or crossed is None:
            return None
        repaired_ok, repaired = self._call("repair", plugin, crossed)
        node_out = repaired if (repaired_ok and repaired is not None) else crossed
        serialized_ok, blob = self._call("serialize", plugin, node_out)
        if not serialized_ok or not isinstance(blob, (bytes, bytearray)):
            return None
        blob = bytes(blob)[:MAX_OUTPUT_BYTES]
        if len(bytes(blob)) > MAX_OUTPUT_BYTES:
            self.fallbacks += 1
            self.last_error = (f"{plugin.plugin_id}: crossover output "
                               f"exceeds {MAX_OUTPUT_BYTES} bytes")
            return None
        return blob, f"crossover:{plugin.plugin_id}@{plugin.version}"


def load_plugin(path: str | Path) -> MutatorPlugin:
    """Load exactly one plugin module; raises ValidationError when invalid."""
    host = PluginHost().discover([path])
    if not host.plugins:
        raise ValidationError(
            f"no valid mutator plugin at '{path}'"
            + (f": {host.last_error}" if host.last_error else ""))
    return host.plugins[0]
