"""Black-box stateful prober for the local usbmuxd daemon (#228 §1).

Speaks the documented plist protocol over the daemon's unix socket and
mutates one dimension per round (versions, message types, field values,
frame boundaries). After every round a *valid* ReadDevices round-trip
verifies daemon liveness; if the daemon stops answering and later returns,
launchd restarted it — that transition is recorded as the crash signal
(launchd makes this tier safe to observe on the researcher's own Mac).

Safety:
  - refuses to run while an iOS device is attached unless --allow-with-device
    (mutation rounds must never touch a real device's service ports)
  - bounded rounds and socket timeouts; never forwards payload data after a
    successful Connect

Usage:
  .venv/bin/python tools/probe/usbmuxd_probe.py [--rounds 64] [--seed N]
      [--socket /var/run/usbmuxd] [--allow-with-device]

Output: framework-style JSON envelope; exit 0 ok, 5 safety refusal.
"""
from __future__ import annotations

import argparse
import json
import plistlib
import socket
import struct
import subprocess
import sys
import time

SOCKET_PATH = "/var/run/usbmuxd"
HEADER = struct.Struct("<IIII")
TYPE_PLIST = 8
PROTO_VERSION = 1

# usbmuxd message-type constants (usbmuxd.h)
MSG_RESULT = 1
MSG_DEVICE_ADD = 2
MSG_DEVICE_REMOVE = 3
MSG_DEVICE_PAIRED = 4
MSG_PLIST = 8


# --- wire helpers ---------------------------------------------------------------

def pack_frame(version: int, msg_type: int, tag: int, payload: bytes = b"") \
        -> bytes:
    return HEADER.pack(HEADER.size + len(payload), version, msg_type,
                       tag) + payload


def pack_plist(obj: dict, *, version: int = PROTO_VERSION, tag: int = 1,
               declared_type: int = TYPE_PLIST) -> bytes:
    return pack_frame(version, declared_type, tag,
                      plistlib.dumps(obj, fmt=plistlib.FMT_BINARY))


def recv_exact(sock: socket.socket, n: int, timeout: float = 3.0):
    sock.settimeout(timeout)
    chunks = b""
    deadline = time.monotonic() + timeout
    while len(chunks) < n:
        remaining = n - len(chunks)
        try:
            chunk = sock.recv(min(4096, remaining))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        chunks += chunk
        if time.monotonic() > deadline:
            return None
    return chunks


def recv_message(sock: socket.socket, timeout: float = 3.0):
    """Read one framed message; returns (version, msg_type, tag, payload)."""
    head = recv_exact(sock, HEADER.size, timeout)
    if head is None or len(head) < HEADER.size:
        return None
    length, version, msg_type, tag = HEADER.unpack(head)
    if length < HEADER.size or length > 16 * 1024 * 1024:
        return None
    payload = b""
    if length > HEADER.size:
        payload = recv_exact(sock, length - HEADER.size, timeout)
        if payload is None:
            return None
    return version, msg_type, tag, payload


def parse_plist(payload: bytes) -> dict | None:
    try:
        obj = plistlib.loads(payload)
        return obj if isinstance(obj, dict) else None
    except (plistlib.InvalidFileException, ValueError):
        return None


# --- safety ----------------------------------------------------------------------

def ios_device_attached() -> bool:
    try:
        out = subprocess.run(["ioreg", "-p", "IOUSB", "-w", "0"],
                             capture_output=True, text=True, timeout=15)
        blob = out.stdout.lower()
        return any(k in blob for k in ("iphone", "ipad", "ipod"))
    except (OSError, subprocess.TimeoutExpired):
        return True  # cannot prove absence -> behave safely


# --- mutation rounds (#228: stateful, one dimension per round) --------------------

def build_rounds(seed: int) -> list[dict]:
    import random
    rng = random.Random(seed)
    prog = "iosr-probe"

    def hello(prog_name=prog, lib_version=3, mt_string="Listen"):
        return {"MessageType": mt_string, "ProgName": prog_name,
                "kLibUSBmuxdVersion": lib_version}

    def read_devices():
        return {"MessageType": "ReadDevices", "ProgName": prog}

    def connect(device_id=0, port=0):
        # PortNumber travels in network byte order per the spec.
        return {"MessageType": "Connect", "ProgName": prog,
                "DeviceID": device_id, "PortNumber": port}

    rounds: list[dict] = [
        {"name": "baseline-hello", "send": [pack_plist(hello())],
         "expect": "listen-ok"},
        {"name": "baseline-readdevices", "send": [pack_plist(read_devices())],
         "expect": "devices"},
        {"name": "unknown-messagetype-string",
         "send": [pack_plist(hello(mt_string="Frobnicate"))]},
        {"name": "empty-progname", "send": [pack_plist(hello(prog_name=""))]},
        {"name": "unicode-progname",
         "send": [pack_plist(hello(prog_name="p" * 10 + "\U0001f4f1"))]},
        {"name": "huge-progname", "send": [pack_plist(hello(prog_name="A" *
                                                            65536))]},
        {"name": "nul-progname", "send": [pack_plist(
            hello(prog_name="a\x00b"))]},
        {"name": "negative-libversion",
         "send": [pack_plist(hello(lib_version=-1))]},
        {"name": "huge-libversion",
         "send": [pack_plist(hello(lib_version=2 ** 31 - 1))]},
        {"name": "zero-header-version", "send": [pack_plist(
            hello(), version=0)]},
        {"name": "future-header-version", "send": [pack_plist(
            hello(), version=2)]},
        {"name": "max-header-version", "send": [pack_plist(
            hello(), version=0xFFFFFFFF)]},
        {"name": "wrong-declared-type-result", "send": [pack_plist(
            hello(), declared_type=MSG_RESULT)]},
        {"name": "wrong-declared-type-deviceadd", "send": [pack_plist(
            hello(), declared_type=MSG_DEVICE_ADD)]},
        {"name": "raw-message-types-sweep",
         "send": [pack_frame(PROTO_VERSION, t, 9) for t in
                  range(0, 16)]},
        {"name": "connect-zero-id-zero-port",
         "send": [pack_plist(connect(device_id=0, port=0))]},
        {"name": "connect-negative-deviceid",
         "send": [pack_plist(connect(device_id=-1))]},
        {"name": "connect-max-deviceid",
         "send": [pack_plist(connect(device_id=2 ** 32 - 1))]},
        {"name": "connect-lockdownd-port-no-device",
         "send": [pack_plist(connect(device_id=0, port=62078 & 0xFFFF))]},
        {"name": "connect-byteswapped-port",
         "send": [pack_plist(connect(device_id=0,
                                     port=struct.unpack("<H", struct.pack(
                                         ">H", 62078))[0]))]},
        {"name": "truncated-header", "send": [b"\x14\x00\x00"]},
        {"name": "empty-payload", "send": []},
        {"name": "declared-length-overrun",
         "send": [HEADER.pack(0xFFFFFF, PROTO_VERSION, TYPE_PLIST, 1)]},
        {"name": "declared-length-shrink",
         "send": [HEADER.pack(8, PROTO_VERSION, TYPE_PLIST, 1)]},
        {"name": "garbage-bytes", "send": [bytes(rng.randrange(256)
                                                 for _ in range(64))]},
        {"name": "tag-reuse", "send": [pack_plist(hello(), tag=7),
                                       pack_plist(read_devices(), tag=7)]},
        {"name": "message-order-inversion", "send": [
            pack_plist({"MessageType": "ReadDevices"}),
            pack_plist({"MessageType": "Listen"})]},
    ]
    return rounds


STATES = ("closed", "connected", "hello-ok", "listening", "verified")


class ProbeSession:
    """Tracks the state machine across rounds; verifies liveness each round."""

    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self.state = "closed"
        self.transitions: list[dict] = []
        self.restarts = 0
        self.anomalies: list[dict] = []

    def _log(self, round_name: str, frm: str, to: str, note: str = ""):
        self.transitions.append({"round": round_name, "from": frm, "to": to,
                                 "note": note})

    def _connect(self) -> socket.socket | None:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(self.socket_path)
            self.state = "connected"
            return s
        except (OSError, PermissionError):
            return None

    def alive(self) -> bool:
        """Valid ReadDevices round-trip within the grace window."""
        s = self._connect()
        if s is None:
            return False
        try:
            s.sendall(pack_plist({"MessageType": "ReadDevices",
                                  "ProgName": "iosr-probe"}, tag=0xFFFF))
            msg = recv_message(s, timeout=3)
            return msg is not None
        finally:
            s.close()

    def await_restart(self, budget_s: float = 45.0) -> bool:
        """launchd should relaunch usbmuxd; poll for its return."""
        deadline = time.monotonic() + budget_s
        while time.monotonic() < deadline:
            if self.alive():
                return True
            time.sleep(1.0)
        return False

    def run_round(self, rnd: dict) -> dict:
        before = self.state
        name = rnd["name"]
        s = self._connect()
        if s is None:
            self._log(name, before, "closed", "connect failed")
            recovered = self.await_restart()
            if recovered:
                self.restarts += 1
                self._log(name, "closed", "verified", "daemon returned")
            return {"round": name, "outcome": "daemon-unavailable"
                    if not recovered else "restarted"}

        responses = []
        try:
            try:
                for blob in rnd.get("send", []):
                    s.sendall(blob)
            except (OSError, BrokenPipeError) as exc:
                responses.append({"error": f"send failed: {exc}"})
            # drain up to three replies
            for _ in range(3):
                msg = recv_message(s, timeout=2)
                if msg is None:
                    break
                version, msg_type, tag, payload = msg
                entry = {"version": version, "type": msg_type, "tag": tag}
                parsed = parse_plist(payload)
                if parsed is not None:
                    entry["plist"] = {k: parsed[k] for k in parsed
                                      if k in ("MessageType", "Number",
                                               "DeviceID")}
                responses.append(entry)
        finally:
            s.close()
            self.state = "closed"

        anomaly = None
        if any("error" in r for r in responses):
            anomaly = "transport-error"
        elif any(r.get("plist", {}).get("MessageType") == "Result"
                 and r.get("plist", {}).get("Number", 0) != 0
                 for r in responses):
            pass  # non-zero Result is a normal rejection
        if anomaly:
            self.anomalies.append({"round": name, "responses": responses[:3],
                                   "kind": anomaly})

        # liveness gate
        if self.alive():
            self.state = "verified"
            self._log(name, before, "verified")
            outcome = "anomalous" if anomaly else "ok"
        else:
            self.state = "down"
            self._log(name, before, "down", "liveness gate failed")
            recovered = self.await_restart()
            if recovered:
                self.restarts += 1
                self.state = "verified"
                self._log(name, "down", "verified",
                          "launchd restart observed (crash signal)")
                outcome = "restart-observed"
            else:
                outcome = "daemon-down-unrecovered"
        return {"round": name, "outcome": outcome,
                "responses": responses[:3]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=None,
                    help="cap on mutation rounds (default: all built)")
    ap.add_argument("--seed", type=int, default=20260825)
    ap.add_argument("--socket", default=SOCKET_PATH)
    ap.add_argument("--allow-with-device", action="store_true",
                    help="override the attached-iOS-device refusal")
    args = ap.parse_args()

    attached = ios_device_attached()
    if attached and not args.allow_with_device:
        print(json.dumps({
            "ok": False, "command": "usbmuxd_probe", "exit_code": 5,
            "error": "an iOS device appears to be attached; mutation rounds "
                     "must not run against live hardware "
                     "(pass --allow-with-device to override)",
        }))
        return 5

    session = ProbeSession(args.socket)
    if not session.alive():
        print(json.dumps({
            "ok": False, "command": "usbmuxd_probe", "exit_code": 3,
            "error": f"no responsive usbmuxd at {args.socket}",
        }))
        return 3
    session._log("preflight", "closed", "verified")

    rounds = build_rounds(args.seed)
    if args.rounds:
        rounds = rounds[:max(1, args.rounds)]
    results = [session.run_round(rnd) for rnd in rounds]

    ok = all(r["outcome"] in ("ok", "anomalous") for r in results)
    print(json.dumps({
        "ok": ok,
        "command": "usbmuxd_probe",
        "data": {
            "socket": args.socket,
            "rounds_executed": len(results),
            "outcomes": {k: sum(1 for r in results if r["outcome"] == k)
                         for k in sorted({r["outcome"] for r in results})},
            "transitions": session.transitions,
            "restarts_observed": session.restarts,
            "anomalies": session.anomalies,
            "results": results,
        },
        "messages": [],
        "error": None if ok else "daemon did not recover from every round; "
                                 "inspect results",
        "exit_code": 0 if ok else 1,
    }, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
