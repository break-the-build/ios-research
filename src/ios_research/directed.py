"""Directed greybox fuzzing: distance-guided base selection (AFLGo lineage).

Given a call graph and a set of *focus symbols* (sinks of interest, e.g.
functions flagged by static analysis), compute a distance from every function
to the nearest target and bias corpus-base selection toward inputs whose
lineage sits near those targets. Scheduling stays deterministic and fully
persisted, preserving the engine's resume guarantees.

The call graph comes from an optional target hook (:meth:`Target.callgraph`)
returning ``{"nodes": [...], "edges": [[caller, callee], ...]}``. Targets
without the hook simply keep the undirected schedule.
"""

from __future__ import annotations

from collections import deque
from pathlib import Path

from .errors import ValidationError

MAX_WEIGHT = 16


def load_callgraph(doc: dict) -> dict:
    """Validate a call-graph document into adjacency + reverse adjacency."""
    if not isinstance(doc, dict):
        raise ValidationError("call graph must be a JSON object")
    nodes = doc.get("nodes")
    edges = doc.get("edges")
    if not isinstance(nodes, list) or not all(isinstance(n, str) for n in nodes):
        raise ValidationError("call graph 'nodes' must be a list of names")
    if not isinstance(edges, list) or \
            not all(isinstance(e, list) and len(e) == 2
                    and all(isinstance(v, str) for v in e) for e in edges):
        raise ValidationError(
            "call graph 'edges' must be a list of [caller, callee] pairs")
    adjacency: dict[str, list[str]] = {n: [] for n in nodes}
    reverse: dict[str, list[str]] = {n: [] for n in nodes}
    for caller, callee in edges:
        adjacency.setdefault(caller, []).append(callee)
        reverse.setdefault(callee, []).append(caller)
        reverse.setdefault(caller, [])
        adjacency.setdefault(callee, [])
    return {"nodes": set(adjacency), "adjacency": adjacency,
            "reverse": reverse}


def target_distances(graph: dict, targets: set[str]) -> dict[str, int]:
    """Min BFS distance from every function to any focus symbol (0 = target).

    Multi-source BFS over reversed edges: a function's distance is the number
    of calls between it and the nearest target it can reach. Functions that
    cannot reach any target (and unknown names) are omitted.
    """
    reverse = graph["reverse"]
    distances = {name: 0 for name in targets if name in reverse}
    queue = deque(distances.keys())
    while queue:
        current = queue.popleft()
        for caller in reverse.get(current, ()):  # who can call `current`?
            if caller not in distances:
                distances[caller] = distances[current] + 1
                queue.append(caller)
    return distances


def selection_weight(distance: int | None, *, max_weight: int = MAX_WEIGHT
                     ) -> int:
    """Selection weight for a distance: 16 at the target, halving per hop."""
    if distance is None:
        return 1
    return max(1, max_weight >> min(distance, 4))


def weighted_selection(entries: list[tuple[str, int | None]],
                       counts: dict[str, int]) -> str:
    """Deterministic fractional-fair pick: lowest count-per-weight first.

    ``entries`` are ``(sha, distance)`` pairs; ``counts`` maps sha to times
    selected so far. Ties break on sha, matching the engine's stable schedule.
    """
    if not entries:
        raise ValidationError("no entries to select from")
    return min(entries, key=lambda e: (
        counts.get(e[0], 0) / selection_weight(e[1]), e[0]))[0]


def objective_symbols_from_findings(objectives: list[dict]) -> set[str]:
    """Map `findings objectives` records to candidate focus symbols.

    Uses the file stem as the symbol guess (``src/app/db.py`` -> ``db``);
    records without a file are ignored.
    """
    symbols: set[str] = set()
    for obj in objectives or []:
        file_path = str(obj.get("file") or "")
        if file_path:
            symbols.add(Path(file_path).stem)
    return symbols


def focus_summary(distances: dict[str, int],
                  chosen_counts: dict[str, int]) -> dict:
    """Persisted focus telemetry for fuzz status/stats output."""
    biased = sum(1 for sha, count in chosen_counts.items()
                 if count and selection_weight(
                     distances.get(sha)) > 1)
    return {"biased": biased,
            "targets_reachable": sum(1 for d in distances.values() if d == 0)}
