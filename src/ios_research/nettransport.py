"""Network-delivered input transport with deterministic capture/replay (#57).

The top Apple bounty categories begin with input arriving over a network
socket. File-based delivery never exercises socket receive loops, framing,
incremental decode, or connection-state handling where network-facing bugs
live. This module adds a **loopback TCP transport adapter** in front of any
registered target:

* the adapter binds ``127.0.0.1`` on an ephemeral port at ``prepare()``;
* each execution accepts one connection, delivers the input according to a
  deterministic chunk schedule, and feeds the reassembled bytes to a wrapped
  receiver (an in-process parse path today; a real harness server tomorrow);
* every execution produces a **capture** — exact byte stream, chunk sizes, and
  schedule name — so any crash replays bit-for-bit via ``net replay``.

Schedules are pure functions of (name, payload) — no timing dependence — so
captures are reproducible and corpus/lineage metadata stays deterministic.

Safety: binding is restricted to loopback by the safety module contract; the
adapter refuses any non-loopback address (fail closed), performs no scanning,
and connects to nothing beyond its own local socket.
"""

from __future__ import annotations

import hashlib
import json
import socket
from dataclasses import dataclass, field
from typing import Any

from .errors import SafetyError, ValidationError
from .hashing import sha256_bytes
from .targets.base import Diagnostics, ExecResult, Outcome, Target

LOOPBACK = "127.0.0.1"
RECV_BUFSIZE = 65536
MAX_CAPTURE_BYTES = 4 * 1024 * 1024


# --- schedules ---------------------------------------------------------------

def _chunk_sizes(schedule: str, payload: bytes) -> list[int]:
    """Deterministic chunk boundaries for a named schedule."""
    n = len(payload)
    if schedule == "single":
        return [n]
    if schedule == "split2":
        half = n // 2 or n
        return [half, n - half] if n > half else [n]
    if schedule == "byte-by-byte":
        return [1] * n
    if schedule == "fragmented-4":
        size = max(1, n // 4)
        sizes = [size] * (n // size)
        if n % size:
            sizes.append(n % size)
        return sizes or [n]
    raise ValidationError(f"unknown schedule '{schedule}'; known: single, "
                          "split2, byte-by-byte, fragmented-4")


SCHEDULES = ("single", "split2", "byte-by-byte", "fragmented-4")


@dataclass
class Capture:
    """Byte-exact record of one network-delivered execution."""

    schedule: str
    host: str
    port: int
    payload_sha256: str
    chunks: list[int] = field(default_factory=list)
    received_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "transport": "tcp-loopback",
            "schedule": self.schedule,
            "host": self.host,
            "port": self.port,
            "payload_sha256": self.payload_sha256,
            "chunks": list(self.chunks),
            "received_sha256": self.received_sha256,
        }

    def verify(self, expected_payload: bytes) -> None:
        """Fail loudly unless the capture matches the payload bit-for-bit."""
        if self.payload_sha256 != self.received_sha256:
            raise ValidationError(
                "capture integrity failure: delivered bytes differ from "
                f"payload ({self.payload_sha256[:12]} != "
                f"{self.received_sha256[:12]})")
        total = sum(self.chunks)
        if total != len(expected_payload):
            raise ValidationError(
                f"capture chunking mismatch: {total} bytes scheduled for a "
                f"{len(expected_payload)}-byte payload")


class LoopbackTcpTarget(Target):
    """Delivers inputs to a wrapped receiver over a real loopback TCP socket.

    ``receiver`` is any callable mapping bytes -> ExecResult; with the default
    it is the wrapped target's in-process execution. The transport exercises
    socket write/read framing around that parse path.
    """

    def __init__(self, inner: Target, *, schedule: str = "single",
                 host: str = LOOPBACK):
        if not host.startswith("127."):
            raise SafetyError(
                "network transport may only bind loopback addresses")
        if schedule not in SCHEDULES:
            raise ValidationError(f"unknown schedule '{schedule}'")
        self.inner = inner
        self.schedule = schedule
        self.host = host
        self._sock: socket.socket | None = None
        self._port: int = 0
        # Inherit mock classification from the wrapped target so opt-in rules
        # for real harnesses keep working through the adapter.
        self.mock = inner.mock
        self.target_id = f"net:{inner.target_id}"

    def describe(self) -> dict[str, Any]:
        out = self.inner.describe()
        out["id"] = self.target_id
        out["kind"] = f"network-transport/{out.get('kind', '')}"
        out["transport"] = {"type": "tcp-loopback", "schedule": self.schedule}
        return out

    # lifecycle ---------------------------------------------------------------
    def prepare(self) -> None:
        self.inner.prepare()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, 0))          # ephemeral port, loopback only
        sock.settimeout(10)
        sock.listen(1)
        self._sock = sock
        self._port = int(sock.getsockname()[1])

    def cleanup(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        self.inner.cleanup()

    def seeds(self) -> list[bytes]:
        return self.inner.seeds()

    def structure_mutate(self, data: bytes, rng):
        return self.inner.structure_mutate(data, rng)

    def coverage_features(self, data: bytes, result: ExecResult):
        return self.inner.coverage_features(data, result)

    # execution ---------------------------------------------------------------
    def _run(self, data: bytes) -> ExecResult:
        if self._sock is None:
            raise ValidationError("transport not prepared")
        payload_sha = sha256_bytes(data)
        chunks = _chunk_sizes(self.schedule, data)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10)
        try:
            client.connect((self.host, self._port))
            sent = 0
            for size in chunks:
                client.sendall(data[sent:sent + size])
                sent += size
            client.shutdown(socket.SHUT_WR)

            conn, _addr = self._sock.accept()
            conn.settimeout(10)
            with conn:
                received = bytearray()
                while len(received) <= MAX_CAPTURE_BYTES:
                    part = conn.recv(RECV_BUFSIZE)
                    if not part:
                        break
                    received.extend(part)
        except OSError as exc:  # pragma: no cover - loopback is reliable
            return ExecResult(outcome=Outcome.ABNORMAL,
                              detail=f"transport I/O error: {exc}",
                              diagnostics=Diagnostics(
                                  exception_type="TRANSPORT_IO",
                                  signature="sig_transport_io"))
        finally:
            client.close()

        capture = Capture(
            schedule=self.schedule, host=self.host, port=self._port,
            payload_sha256=payload_sha, chunks=chunks,
            received_sha256=sha256_bytes(bytes(received)))
        result = self.inner.execute(bytes(received))
        capture.verify(data)
        # Attach capture evidence without altering normalized outcomes.
        result.detail = (result.detail + " | " if result.detail else "") + \
            f"captured:{payload_sha[:12]}"
        result.diagnostics = _with_capture(result.diagnostics, capture)
        _LAST_CAPTURE.set(capture)
        return result


class _LastCapture:
    _current: Capture | None = None

    @classmethod
    def set(cls, capture: Capture | None) -> None:
        cls._current = capture

    @classmethod
    def get(cls) -> Capture | None:
        return cls._current


_LAST_CAPTURE = _LastCapture


def _with_capture(diag: Diagnostics | None,
                  capture: Capture) -> Diagnostics | None:
    if diag is None:
        return None
    payload = json.dumps(capture.to_dict(), sort_keys=True)
    diag.stack_trace = [*diag.stack_trace, f"transport={payload}"]
    return diag


def capture_from_result(result: ExecResult) -> dict[str, Any] | None:
    """Extract the transport capture from an ExecResult's diagnostics."""
    if result.diagnostics is None:
        return _LAST_CAPTURE.get().to_dict() if _LAST_CAPTURE.get() else None
    for frame in reversed(result.diagnostics.stack_trace):
        if frame.startswith("transport="):
            try:
                return json.loads(frame[len("transport="):])
            except ValueError:
                return None
    return None


# --- replay -----------------------------------------------------------------

def replay(target: LoopbackTcpTarget, data: bytes,
           capture: dict[str, Any]) -> dict[str, Any]:
    """Re-drive a captured session against a rebuilt target.

    Returns a verdict describing whether the transport reproduced the same
    delivery pattern and whether the outcome matched the recorded one.
    """
    recorded_schedule = capture.get("schedule")
    if recorded_schedule != target.schedule:
        raise ValidationError(
            f"replay schedule mismatch: capture used "
            f"'{recorded_schedule}', target uses '{target.schedule}'")
    result = target.execute(data)
    now_capture = capture_from_result(result)
    same_chunks = bool(now_capture and
                       now_capture.get("chunks") == capture.get("chunks"))
    return {
        "outcome": result.outcome,
        "detail": result.detail,
        "chunks_match": same_chunks,
        "signature": result.diagnostics.signature
        if result.diagnostics else None,
    }


def capture_digest(capture: dict[str, Any]) -> str:
    canonical = json.dumps(capture, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:16]
