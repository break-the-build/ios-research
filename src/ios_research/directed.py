"""Directed greybox fuzzing primitives (#73): distance computation and power
scheduling toward *targets of interest* — functions flagged by static analysis
(findings) or suspicious points.

This module is pure, offline math over user-supplied data:

* a **call-graph document** (JSON, schema 1) naming functions, their source
  locations and their call edges — typically produced offline from static
  analysis;
* **objectives** derived from confirmed findings (file + line) that resolve to
  call-graph functions by location containment or exact name.

Inter-procedural distances follow AFLGo: multi-source Dijkstra over the call
graph with every edge traversable in both directions (a caller reaches its
callees; a callee is reached through its callers), unit edge weight, target
functions at distance 0. The per-input distance is AFLGo's
``mean(log2(d(f) + 1))`` over the functions an input's coverage features map
to, and the directed energy weight decays as ``2 ** -distance``, so inputs
nearer an objective receive proportionally more energy while no input ever
starves.

Nothing here deploys exploits or touches devices; it only shapes how the
in-process reference engine picks parents and how external engines (e.g.
libFuzzer ``-focus_function``) are instructed.
"""

from __future__ import annotations

import heapq
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ValidationError

CALLGRAPH_SCHEMA = 1

# Distance assigned when a function cannot reach any objective. Large but
# finite so arithmetic stays well-behaved and JSON round-trips exactly.
UNREACHABLE_DISTANCE = 32.0

# Energy weight floor for inputs whose features do not map to any known
# function: they still get scheduled, just at the lowest priority tier.
MIN_ENERGY_WEIGHT = 2.0 ** -UNREACHABLE_DISTANCE


def load_callgraph(path: str | Path) -> dict[str, Any]:
    """Read and validate a call-graph document from disk."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValidationError(f"cannot read call graph: {exc}") from exc
    except ValueError as exc:
        raise ValidationError(f"call graph is not valid JSON: {exc}") from exc
    validate_callgraph(doc)
    return doc


def validate_callgraph(doc: Any) -> None:
    """Validate the schema-1 call-graph document shape."""
    if not isinstance(doc, dict):
        raise ValidationError("call graph must be a JSON object")
    if doc.get("schema") != CALLGRAPH_SCHEMA:
        raise ValidationError(
            f"unsupported call-graph schema {doc.get('schema')!r}; "
            f"expected {CALLGRAPH_SCHEMA}")
    functions = doc.get("functions")
    if not isinstance(functions, list) or not functions:
        raise ValidationError("call graph needs a non-empty 'functions' list")
    for fn in functions:
        if not isinstance(fn, dict) or not isinstance(fn.get("name"), str) \
                or not fn["name"]:
            raise ValidationError(
                "each call-graph function needs a non-empty 'name'")
    calls = doc.get("calls", [])
    if not isinstance(calls, list):
        raise ValidationError("call graph 'calls' must be a list")


@dataclass
class CallGraph:
    """A validated call graph with feature-to-function resolution."""

    functions: dict[str, dict[str, Any]] = field(default_factory=dict)
    callers_of: dict[str, tuple[str, ...]] = field(default_factory=dict)
    callees_of: dict[str, tuple[str, ...]] = field(default_factory=dict)
    feature_functions: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_doc(cls, doc: dict[str, Any]) -> "CallGraph":
        validate_callgraph(doc)
        graph = cls()
        for fn in doc["functions"]:
            graph.functions[fn["name"]] = {
                "file": str(fn.get("file") or ""),
                "line": int(fn.get("line") or 0),
                "end_line": int(fn.get("end_line") or fn.get("line") or 0),
            }
        for edge in doc.get("calls") or []:
            if isinstance(edge, dict):
                caller, callee = edge.get("caller"), edge.get("callee")
            else:
                caller, callee = (list(edge) + ["", ""])[:2]
            if caller in graph.functions and callee in graph.functions \
                    and callee not in graph.callees_of.get(caller, ()):
                graph.callees_of[caller] = \
                    graph.callees_of.get(caller, ()) + (callee,)
                graph.callers_of[callee] = \
                    graph.callers_of.get(callee, ()) + (caller,)
        for feature, fn in (doc.get("feature_functions") or {}).items():
            if fn in graph.functions:
                graph.feature_functions[str(feature)] = fn
        return graph

    @classmethod
    def load(cls, path: str | Path) -> "CallGraph":
        return cls.from_doc(load_callgraph(path))

    # -- objective resolution ------------------------------------------------
    def resolve_location(self, file_path: str, line: int,
                         symbol: str = "") -> str | None:
        """Resolve a source location (or exact symbol) to a function name.

        Exact name wins, then the *narrowest* function whose source extent
        contains the location (basename-insensitive), then unique-name suffix
        match.
        """
        if symbol and symbol in self.functions:
            return symbol
        wanted = Path(file_path).name.lower() if file_path else ""
        best = None
        best_width = -1
        for name in sorted(self.functions):
            info = self.functions[name]
            where = Path(info["file"]).name.lower() if info["file"] else ""
            start, end = info["line"], max(info["end_line"], info["line"])
            if wanted and where == wanted and start <= line <= end:
                width = end - start
                if best is None or width < best_width:
                    best, best_width = name, width
        if best is not None:
            return best
        if symbol:
            hits = [name for name in sorted(self.functions)
                    if name.endswith(symbol)]
            if len(hits) == 1:
                return hits[0]
        return None

    def resolve_objectives(self,
                           objectives: list[dict[str, Any]]
                           ) -> tuple[list[str], list[dict[str, Any]]]:
        """Map objective locators to target function names.

        Returns ``(resolved_names, per_objective_records)``; records carry the
        original locator plus the resolved function (or ``null``).
        """
        targets: list[str] = []
        records: list[dict[str, Any]] = []
        for obj in objectives:
            resolved = self.resolve_location(
                obj.get("file", ""), int(obj.get("line") or 0),
                obj.get("symbol", ""))
            if resolved and resolved not in targets:
                targets.append(resolved)
            records.append(dict(obj, function=resolved))
        return sorted(targets), records

    # -- distances -------------------------------------------------------------
    def function_distances(self,
                           targets: list[str]) -> dict[str, float]:
        """Inter-procedural distance from every function to the objectives.

        Multi-source Dijkstra over call edges walked in both directions
        (unit weight); unknown target names are ignored. Functions with no
        path to any objective receive :data:`UNREACHABLE_DISTANCE`.
        """
        dist = {name: UNREACHABLE_DISTANCE for name in self.functions}
        heap: list[tuple[float, str]] = []
        for name in targets:
            if name in dist and dist[name] != 0.0:
                dist[name] = 0.0
                heapq.heappush(heap, (0.0, name))
        while heap:
            d, node = heapq.heappop(heap)
            if d > dist.get(node, UNREACHABLE_DISTANCE):
                continue
            neighbours = self.callees_of.get(node, ()) + \
                self.callers_of.get(node, ())
            for nxt in neighbours:
                nd = d + 1.0
                if nd < dist.get(nxt, UNREACHABLE_DISTANCE):
                    dist[nxt] = nd
                    heapq.heappush(heap, (nd, nxt))
        return dist

    def feature_function(self, feature: str) -> str | None:
        """Map one coverage feature ID to a function name.

        Exact configured mappings win; otherwise the longest function name
        contained in the feature string matches (symbol-bearing IDs such as
        ``cov:parse_record:12`` resolve without extra configuration).
        """
        mapped = self.feature_functions.get(feature)
        if mapped:
            return mapped
        best = ""
        for name in self.functions:
            if len(name) > len(best) and name in feature:
                best = name
        return best or None


def input_distance(function_distance: dict[str, float],
                   features: list[str] | tuple[str, ...]) -> float | None:
    """Per-input distance over the features an input exercised (AFLGo).

    ``mean(log2(d(f) + 1))`` across features that map to a known function;
    ``None`` when no feature maps, meaning this input carries no signal for
    the directed schedule.
    """
    values = [function_distance[f] for f in features if f in function_distance]
    if not values:
        return None
    return sum(math.log2(d + 1.0) for d in values) / len(values)


def energy_weight(distance: float | None) -> float:
    """Directed energy for one input: exponentially decaying in distance."""
    if distance is None:
        return MIN_ENERGY_WEIGHT
    return 2.0 ** (-max(0.0, min(distance, UNREACHABLE_DISTANCE)))


def focus_arguments(focus_function: str,
                    *, engine: str = "libfuzzer") -> list[str]:
    """Engine command-line hook realizing the directed schedule externally.

    libFuzzer concentrates energy on one function via ``-focus_function``;
    other engines have no equivalent and receive no arguments (the in-process
    schedule stays authoritative).
    """
    if engine == "libfuzzer" and focus_function:
        return [f"-focus_function={focus_function}"]
    return []


def build_plan(graph: CallGraph,
               objectives: list[dict[str, Any]]) -> dict[str, Any]:
    """Resolve objectives against a graph and compute all distances.

    The returned plan is plain JSON-safe data suitable for direct persistence
    on a fuzz session record and on the owning experiment. ``function_distance``
    is keyed by function name; ``feature_distance`` is keyed by coverage
    feature ID so the engine can price an input directly from its recorded
    features without re-reading the call graph.
    """
    target_functions, records = graph.resolve_objectives(objectives)
    distances = graph.function_distances(target_functions)
    feature_distance = {
        feature: distances[fn]
        for feature, fn in sorted(graph.feature_functions.items())
        if fn in distances
    }
    return {
        "objectives": records,
        "target_functions": target_functions,
        "function_distance": dict(sorted(distances.items())),
        "feature_distance": feature_distance,
        "focus_function": target_functions[0] if target_functions else "",
        "reachable_targets": bool(target_functions),
    }


def objectives_from_findings(findings: list[Any]) -> list[dict[str, Any]]:
    """Objective locators from finding records (static-analysis sinks)."""
    return [{
        "kind": "finding",
        "id": getattr(f, "id", ""),
        "file": getattr(f, "file_path", ""),
        "line": int(getattr(f, "start_line", 0) or 0),
        "rule": getattr(f, "rule_id", ""),
    } for f in findings]
