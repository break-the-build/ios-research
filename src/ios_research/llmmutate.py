"""LLM-in-the-loop mutation: proposer interface, budgets, redaction (#71).

Complements grammar-mutator plugins (#41) with model-guided mutation: a
*proposer* receives a sanitized round context (corpus stats + recent crash
summaries) and returns candidate inputs, which are validated by format-aware
repair before execution. Crashes found in one round are fed back as truncated,
redacted few-shot examples for the next round — a closed loop.

Trust and hermeticity boundary:

* The model itself is **injected by the caller**: either programmatically (any
  object satisfying :class:`Proposer`) or via a user-declared local command
  template (:class:`CommandProposer`, same trust level as ``--mutator-plugin``).
  Nothing here performs network I/O, needs API keys, or ships an SDK.
* Only deterministic fixtures are bundled: :class:`ScriptedProposer` for tests
  and :class:`EchoProposer` as the smallest reference implementation.
* Budgets are enforced in code (``--llm-rounds N --llm-budget K``), mirroring
  the ``limits.max_workers`` pattern; proposer failures are isolated and
  degrade to generic mutation instead of aborting a campaign.
* Every executed proposal is added to the corpus tagged with the proposer
  identity and round, so campaigns stay reproducible without the model.
"""

from __future__ import annotations

import base64
import copy
import json
import re
import shlex
import subprocess
from typing import Any, Mapping, Protocol, Sequence

from .errors import UsageError
from .hashing import sha256_text

CONTEXT_SCHEMA_VERSION = 1

DEFAULT_LLM_ROUNDS = 3
DEFAULT_LLM_BUDGET = 24
DEFAULT_MAX_LLM_ROUNDS = 8
DEFAULT_MAX_LLM_BUDGET = 128

MAX_PROPOSALS_PER_ROUND = 64
MAX_FEEDBACK_CRASHES = 4
MAX_SAMPLE_HEX = 128
MAX_FEW_SHOT_HEX = 96
MAX_DETAIL_CHARS = 160
HASH_KEEP = 12
MAX_STDOUT_BYTES = 8 * 1024 * 1024
DEFAULT_PROPOSER_TIMEOUT_S = 30.0

_HEX_RUN = re.compile(r"\b[0-9a-f]{32,}\b")
_ABS_PATH = re.compile(r"(?:/[A-Za-z0-9._@+-]+){2,}")


class ProposerError(RuntimeError):
    """Raised by proposers that fail to produce parseable candidates."""


def short_hash(value: Any) -> str:
    """Truncate a hash-like identifier for safe display/feedback."""
    return str(value)[:HASH_KEEP]


def redact_text(text: str, roots: Sequence[str] = ()) -> str:
    """Redact workspace roots, long hashes, and absolute paths from text.

    Order matters: known roots collapse to ``<workspace>`` first, then any
    residual hex-hash run is truncated, then remaining absolute paths shrink
    to their basename so no host layout leaks into proposer contexts.
    """
    out = str(text)
    for root in sorted({str(r) for r in roots if r}, key=len, reverse=True):
        out = out.replace(root, "<workspace>")
    out = _HEX_RUN.sub(lambda m: m.group(0)[:HASH_KEEP], out)
    out = _ABS_PATH.sub(lambda m: m.group(0).rstrip("/").rsplit("/", 1)[-1],
                        out)
    return out


def summarize_crash(*, crash_id: str, signature: str, classification: str,
                    detail: str, count: int, input_sha256: str,
                    example_bytes: bytes | None = None,
                    roots: Sequence[str] = ()) -> dict[str, Any]:
    """Build one sanitized crash summary for a proposer context.

    Hashes and ids are truncated, paths are redacted from the detail text, and
    the few-shot example is capped to a bounded hex prefix of the (preferably
    minimized) triggering input.
    """
    example = bytes(example_bytes or b"")[: MAX_FEW_SHOT_HEX // 2]
    return {
        "id": short_hash(crash_id),
        "signature": short_hash(signature),
        "classification": str(classification),
        "count": int(count),
        "detail": redact_text(detail, roots)[:MAX_DETAIL_CHARS],
        "input_sha256": short_hash(input_sha256),
        "example_hex": example.hex(),
    }


def validate_budget(rounds: int, budget: int, *,
                    max_rounds: int = DEFAULT_MAX_LLM_ROUNDS,
                    max_budget: int = DEFAULT_MAX_LLM_BUDGET) -> None:
    """Enforce server-side caps on rounds/budget, mirroring worker limits."""
    for name, value in (("llm rounds", rounds), ("llm budget", budget)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise UsageError(f"{name} must be an integer")
        if value < 1:
            raise UsageError(f"{name} must be >= 1")
    if rounds > max_rounds:
        raise UsageError(f"llm rounds={rounds} exceeds limit {max_rounds}")
    if budget > max_budget:
        raise UsageError(f"llm budget={budget} exceeds limit {max_budget}")


class Proposer(Protocol):
    """Contract for an injected model-backed proposal source (#71).

    ``propose`` receives a sanitized, JSON-serializable context mapping and
    returns raw candidate inputs as bytes. Implementations must be local and
    offline; the engine isolates every call so failures degrade to generic
    mutation rather than aborting a campaign.
    """

    proposer_id: str

    def propose(self, context: Mapping[str, Any]) -> Sequence[bytes]: ...


class ScriptedProposer:
    """Deterministic fake LLM for tests.

    Returns one pre-scripted batch of candidates per round and records a deep
    copy of every context it receives, so tests can assert exactly what
    sanitized feedback later rounds were shown.
    """

    def __init__(self, batches: Sequence[Sequence[bytes]], *,
                 proposer_id: str = "scripted"):
        self.batches = [list(batch) for batch in batches]
        self.proposer_id = proposer_id
        self.contexts: list[dict[str, Any]] = []
        self.calls = 0

    def propose(self, context: Mapping[str, Any]) -> Sequence[bytes]:
        self.contexts.append(copy.deepcopy(dict(context)))
        index = self.calls
        self.calls += 1
        if index < len(self.batches):
            return list(self.batches[index])
        return []


class EchoProposer:
    """Trivial example proposer: echoes corpus samples back verbatim.

    Useful as the smallest possible :class:`Proposer` reference and for
    plumbing tests. Echoed inputs duplicate existing corpus entries, so the
    engine's dedupe rejects them — demonstrating that provenance-tagged
    ingestion can never silently rewrite a converged corpus.
    """

    proposer_id = "echo"

    def propose(self, context: Mapping[str, Any]) -> Sequence[bytes]:
        corpus = context.get("corpus") or {}
        samples = corpus.get("sample_hex") or []
        return [bytes.fromhex(sample) for sample in samples]


class CommandProposer:
    """Run a user-declared local command template as a proposer.

    The command receives the round context as JSON on stdin and writes one
    base64-encoded candidate per stdout line (``#`` comments and blank lines
    are ignored). It is plain subprocess execution of researcher-supplied
    words — no shell interpolation, no network, same trust level as loading a
    mutator plugin from disk. Malformed lines are skipped and recorded;
    nonzero exits and timeouts raise :class:`ProposerError`, which the engine
    isolates per round.
    """

    def __init__(self, template: str, *,
                 timeout_s: float = DEFAULT_PROPOSER_TIMEOUT_S):
        self.template = template
        self.timeout_s = timeout_s
        self.proposer_id = f"cmd:{sha256_text(template)[:HASH_KEEP]}"
        self.last_error = ""

    def propose(self, context: Mapping[str, Any]) -> Sequence[bytes]:
        argv = shlex.split(self.template)
        if not argv:
            raise ProposerError("empty proposer command template")
        try:
            proc = subprocess.run(
                argv,
                input=json.dumps(dict(context)).encode("utf-8"),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            raise ProposerError(
                f"proposer timed out after {self.timeout_s}s") from None
        except OSError as exc:
            raise ProposerError(f"proposer failed to start: {exc}") from None
        if proc.returncode != 0:
            tail = proc.stderr.decode("utf-8", "replace").strip()[-200:]
            raise ProposerError(
                f"proposer exited {proc.returncode}: {tail}")
        out = proc.stdout.decode("utf-8", "replace")
        if len(proc.stdout) > MAX_STDOUT_BYTES:
            raise ProposerError(
                f"proposer output exceeds {MAX_STDOUT_BYTES} bytes")
        candidates: list[bytes] = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                candidates.append(base64.b64decode(line, validate=True))
            except Exception:  # noqa: BLE001 - skip malformed lines
                self.last_error = f"skipped unparseable line: {line[:40]}"
        return candidates


def resolve_proposer(template: str) -> CommandProposer:
    """Build the CLI-facing proposer from a user-declared command template."""
    return CommandProposer(template)
