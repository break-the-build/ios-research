"""Confirm a finding on real iPhone hardware via the AudioProbe app (#217).

Pipeline: input file (or crash ID from the workspace store) -> push into the
probe app's container -> launch with console capture -> parse PROBE lines ->
verdict. This is the confirmation oracle that turns Mac-discovered crashes
into hardware-confirmed evidence (FINDING-04 workflow, productized).

Usage:
  .venv/bin/python tools/campaign/confirm_on_device.py --input FILE
  .venv/bin/python tools/campaign/confirm_on_device.py --crash crash_XYZ
      [--device UDID] [--timeout 20] [--app research.iosprobe.AudioProbe]

Verdicts:
  OPEN_OK    framework opened the input cleanly
  OPEN_FAIL  framework rejected it (status in console)
  HANG       app alive past --timeout with no DONE (the FINDING-04 signature)
  ERROR      unreadable input / probe infrastructure failure

Exit codes follow the framework contract: 0 ok, 1 error, 3 not found,
4 validation. JSON envelope on stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

# xcrun defaults to the Command Line Tools dir, which has no devicectl.
_XCODE = "/Applications/Xcode.app/Contents/Developer"
if "DEVELOPER_DIR" not in os.environ and Path(_XCODE).exists():
    os.environ["DEVELOPER_DIR"] = _XCODE

DEFAULT_APP = "research.iosprobe.AudioProbe"


def run(cmd: list[str], timeout: float = 60) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        blob = (proc.stdout + proc.stderr).decode("utf-8", "replace")
        return proc.returncode, blob
    except subprocess.TimeoutExpired as exc:
        blob = b""
        if exc.stdout:
            blob += exc.stdout
        if exc.stderr:
            blob += exc.stderr
        return 124, blob.decode("utf-8", "replace")
    except OSError as exc:
        return 1, str(exc)


def list_devices() -> list[dict]:
    """Paired iOS devices visible to devicectl."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out_path = fh.name
    code, blob = run(["xcrun", "devicectl", "list", "devices",
                      "--json-output", out_path])
    try:
        data = json.loads(Path(out_path).read_text())
    except (OSError, ValueError):
        return []
    finally:
        try:
            Path(out_path).unlink()
        except OSError:
            pass
    return data.get("result", {}).get("devices", [])


def resolve_device(device_ref: str | None) -> dict | None:
    devices = [d for d in list_devices()
               if d.get("connectionProperties", {}).get("pairingState")
               == "paired"]
    if device_ref:
        for d in devices:
            if device_ref in (d.get("identifier"), device_name(d)):
                return d
        return None
    return devices[0] if devices else None


def device_name(d: dict) -> str:
    return (d.get("deviceProperties", {}).get("name")
            or d.get("hostname", "?"))


def device_os(d: dict) -> str:
    return str(d.get("deviceProperties", {}).get("osVersionNumber", "?"))


def classify_family(data: bytes) -> str:
    """Magic-byte family dispatch; must mirror device_probe main.m."""
    if len(data) >= 8 and data[:1] == b"\x89" and data[1:4] == b"PNG":
        return "imageio"
    if len(data) >= 6 and data[:6] in (b"GIF87a", b"GIF89a"):
        return "imageio"
    if len(data) >= 12 and data[:3] == b"\xff\xd8\xff":
        return "imageio"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "imageio"
    if len(data) >= 5 and data[:5] == b"%PDF-":
        return "coregraphics"
    if len(data) >= 4 and data[:4] in (b"\x00\x01\x00\x00", b"OTTO",
                                       b"true", b"ttcf"):
        return "coretext"
    if len(data) >= 4 and data[:4] in (b"RIFF", b"FORM", b"caff"):
        return "audio"
    if len(data) >= 3 and data[:3] == b"ID3":
        return "audio"
    if len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
        return "audio"
    return "unknown"


def parse_verdict(console: str, timed_out: bool) -> str:
    """Map captured console output to a verdict."""
    if re.search(r"PROBE ERROR", console):
        return "ERROR"
    if re.search(r"PROBE DONE no-hang", console):
        return "OPEN_OK"
    if re.search(r"PROBE OPEN_FAIL", console):
        return "OPEN_FAIL"
    if re.search(r"PROBE OPEN_OK", console):
        # opened one family but never reached DONE -> later stage hung
        return "HANG" if timed_out else "OPEN_OK"
    return "HANG" if timed_out else "ERROR"


#: devicectl can tear its console channel down before the app's final PROBE
#: lines are relayed when the app exits within milliseconds of launch; the
#: lines show up fine on a manual run but the captured stream is empty, which
#: parse_verdict maps to a false ERROR. A probe-side PROBE ERROR line is
#: definitive and must NOT be retried; an empty/marker-less capture is treated
#: as a suspected capture race and retried with backoff (RESEARCH-LOG 2026-08-25).
CONSOLE_RACE_ATTEMPTS = 3


def launch_with_retry(launch_fn, timeout: float,
                      attempts: int = CONSOLE_RACE_ATTEMPTS):
    """Run the launch/capture step, retrying suspected console races.

    ``launch_fn`` is called as ``launch_fn(timeout)`` and returns
    ``(code, console)``. Returns ``(code, console, attempts_meta)`` where the
    meta list records every attempt for the JSON envelope.
    """
    tried = []
    code, console = 0, ""
    for attempt in range(1, attempts + 1):
        if attempt > 1:
            time.sleep(1.5 * (attempt - 1))
        code, console = launch_fn(timeout)
        timed_out = code == 124
        verdict = parse_verdict(console, timed_out)
        has_markers = "PROBE" in console
        tried.append({"attempt": attempt, "verdict": verdict,
                      "probe_lines": sum(1 for ln in console.splitlines()
                                         if "PROBE" in ln),
                      "timed_out": timed_out})
        if verdict != "ERROR":
            return code, console, tried
        if has_markers:
            # The app itself reported PROBE ERROR: definitive, no retry.
            return code, console, tried
        # Marker-less ERROR: suspected console-capture race -> retry.
    return code, console, tried


def load_input(args) -> bytes:
    if args.input:
        return Path(args.input).read_bytes()
    from ios_research.workspace import Workspace
    from ios_research.crashes import CrashStore
    ws = Workspace(REPO / ".ios-research")
    store = CrashStore(ws)
    rec = store.get(args.crash)
    if rec is None:
        raise KeyError(args.crash)
    return store.input_bytes(rec)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", help="path to the input file to confirm")
    ap.add_argument("--crash", help="crash id in the workspace store")
    ap.add_argument("--device", default=None,
                    help="device UDID or name (default: first paired)")
    ap.add_argument("--timeout", type=float, default=20.0,
                    help="seconds to wait for the app to finish")
    ap.add_argument("--app", default=DEFAULT_APP)
    args = ap.parse_args()

    if bool(args.input) == bool(args.crash):
        print(json.dumps({"ok": False, "error": "pass exactly one of "
                          "--input or --crash", "exit_code": 4}))
        return 4

    try:
        data = load_input(args)
    except (OSError, KeyError) as exc:
        print(json.dumps({"ok": False, "error": f"cannot load input: {exc}",
                          "exit_code": 3}))
        return 3

    dev = resolve_device(args.device)
    if dev is None:
        print(json.dumps({"ok": False, "error": "no paired iOS device found "
                          "(plug in, trust, enable Developer Mode)",
                          "exit_code": 3}))
        return 3
    dev_id = dev["identifier"]

    # Push the input into the probe app's Documents container.
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(data)
        src = fh.name
    code, blob = run(["xcrun", "devicectl", "device", "copy", "to",
                      "--device", dev_id,
                      "--domain-type", "appDataContainer",
                      "--domain-identifier", args.app,
                      "--source", src,
                      "--destination", "Documents/input.bin"])
    if code != 0:
        print(json.dumps({"ok": False, "error":
                          "copy to device container failed (app installed?)",
                          "detail": blob[-400:], "exit_code": 3}))
        return 3

    # Launch with console capture; a hang shows up as launch-process timeout.
    launch = ["xcrun", "devicectl", "device", "process", "launch",
              "--device", dev_id, "--terminate-existing",
              "--console", args.app]
    started = time.monotonic()

    def _launch(timeout: float) -> tuple[int, str]:
        return run(launch, timeout=timeout)

    code, console, attempts_meta = launch_with_retry(_launch, args.timeout)
    timed_out = code == 124
    verdict = parse_verdict(console, timed_out)
    probes = [ln.strip() for ln in console.splitlines()
              if "PROBE" in ln]

    ok = verdict in ("OPEN_OK", "OPEN_FAIL")
    print(json.dumps({
        "ok": ok,
        "command": "confirm_on_device",
        "data": {
            "verdict": verdict,
            "device": device_name(dev),
            "device_id": dev_id,
            "os_version": device_os(dev),
            "input_sha256": __import__("hashlib").sha256(data).hexdigest(),
            "input_bytes": len(data),
            "family": classify_family(data),
            "elapsed_s": round(time.monotonic() - started, 1),
            "probe_lines": probes,
            "launch_attempts": attempts_meta,
        },
        "messages": [],
        "error": None if ok else f"device verdict: {verdict}",
        "exit_code": 0 if ok else 1,
    }, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
