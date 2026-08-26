#!/usr/bin/env python3
"""ble_window.py — bounded on-device Bluetooth-stack testing window (#228-adjacent).

Orchestrates one authorized research window against YOUR paired iPhone:
  1. Start the Mac-side BLEPeer (CoreBluetooth peripheral; mutated Apple-TLV
     advertisement data + fuzzed GATT tree).
  2. Launch the AudioProbe probe app over USB (devicectl console capture);
     its `bluetooth` family scans, connects ONLY to the "IOSR-BT" name
     prefix, and reads every characteristic/descriptor the peer serves.
  3. Harvest new crash reports (idevicecrashreport) and attribute them by
     process name + timestamp.
  4. Emit a JSON envelope {ok, verdicts, crashes, ...}.

Safety: authorized/own devices only. The probe never connects to third-party
Bluetooth devices; the peer never connects out. No persistence, no covert
access — parser-path exercise plus crash-reporter observation only.

Usage:
  python3 tools/campaign/ble_window.py --duration 600 --interval 5 \
      --out-dir /tmp/ble-window [--device NAME-OR-UDID] [--relaunch-every 60]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PEER_APP = (REPO / "tools" / "campaign" / "device_probe" / "BLEPeer"
            / "BLEPeer.app")
BUNDLE_ID = "research.iosprobe.AudioProbe"
PEER_NAME = "IOSR-BT"
CRASH_PROCS = ("bluetoothd", "blued", "CoreBluetooth", "AudioProbe")


def run(cmd: list[str], timeout: float = 120) -> tuple[int, str]:
    env = dict(os.environ)
    env.setdefault("DEVELOPER_DIR", "/Applications/Xcode.app/Contents/Developer")
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              env=env)
        return (proc.returncode,
                (proc.stdout or b"").decode("utf-8", "replace")
                + (proc.stderr or b"").decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def resolve_device(ref: str | None) -> dict | None:
    # devicectl writes JSON via --json-output <path> (no stdout JSON mode).
    tmp = "/tmp/ble-window-devices.json"
    code, _ = run(["xcrun", "devicectl", "list", "devices",
                   "--json-output", tmp])
    if code != 0:
        return None
    try:
        data = json.loads(Path(tmp).read_text())
    except (ValueError, OSError):
        return None
    devices = (data.get("result") or {}).get("devices", [])
    for d in devices:
        ident = str(d.get("identifier", ""))
        name = str(d.get("deviceProperties", {}).get("name", ""))
        state = str(d.get("connectionProperties", {}).get(
            "pairingState", d.get("state", "")))
        if ref and ref not in (ident, name):
            continue
        return {"udid": ident, "name": name, "state": state}
    return None


def harvest_crashes(out_dir: Path) -> list[Path]:
    """Pull device crash logs and keep only new BT/probe-relevant ones."""
    pulled = out_dir / "crash-reports"
    pulled.mkdir(parents=True, exist_ok=True)
    before = {p.name for p in pulled.glob("*")}
    run(["idevicecrashreport", "-e", "-k", str(pulled)], timeout=180)
    fresh = [p for p in pulled.glob("*") if p.name not in before and p.is_file()]
    return [p for p in fresh
            if any(k.lower() in p.name.lower() for k in CRASH_PROCS)]


def stage_input(udid: str, scan_window: int) -> bool:
    """Push a bluetooth-family input.bin (magic IOSRBT + scan window)."""
    blob = b"IOSRBT" + int(scan_window).to_bytes(4, "big") + b"\x00\x00"
    with open("/tmp/iosr-bt-input.bin", "wb") as fh:
        fh.write(blob)
    code, blob_out = run(["xcrun", "devicectl", "device", "copy", "to",
                          "--device", udid,
                          "--domain-type", "appDataContainer",
                          "--domain-identifier", BUNDLE_ID,
                          "--source", "/tmp/iosr-bt-input.bin",
                          "--destination", "Documents/input.bin"])
    return code == 0


def launch_probe(udid: str, timeout: float) -> tuple[int, str]:
    """Launch the probe app with console capture (blocking until exit)."""
    code, blob = run(["xcrun", "devicectl", "device", "process", "launch",
                      "--console", "--terminate-existing",
                      "--device", udid,
                      BUNDLE_ID],
                     timeout=timeout)
    return code, blob


def parse_verdict(console: str) -> str:
    if re.search(r"PROBE ERROR", console):
        return "error"
    if re.search(r"PROBE DONE no-hang", console):
        return "no-hang"
    if re.search(r"PROBE OPEN_FAIL", console):
        return "open-fail"
    if re.search(r"PROBE OPEN_OK|PROBE connected|PROBE adv-hit", console):
        return "exercised"
    return "no-markers"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=300,
                    help="window length in seconds (peer lifetime)")
    ap.add_argument("--interval", type=float, default=5.0,
                    help="seconds between peer payload rotations")
    ap.add_argument("--corpus", default=None,
                    help="payload corpus dir for the peer (optional)")
    ap.add_argument("--seed", type=int, default=82501)
    ap.add_argument("--scan-window", type=int, default=20,
                    help="per-launch scan window on the phone (seconds)")
    ap.add_argument("--relaunch-every", type=int, default=45,
                    help="relaunch the probe app every N seconds")
    ap.add_argument("--device", default=None)
    ap.add_argument("--out-dir", default="/tmp/ble-window")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    dev = resolve_device(args.device)
    if dev is None:
        print(json.dumps({"ok": False,
                          "error": "no paired device visible to devicectl"}))
        return 3

    env = dict(os.environ)
    peer_log = out / "peer.log"
    # Launch detached via `open`: TCC attributes Bluetooth access to the app
    # bundle itself (a child of this shell would inherit a non-Bluetooth host
    # and abort with __TCC_CRASHING_DUE_TO_PRIVACY_VIOLATION).
    # Keep the Mac awake for the whole window — system sleep reports
    # poweredOff to CoreBluetooth sessions and masquerades as a radio failure.
    caffeinate = subprocess.Popen(
        ["caffeinate", "-dims", "-w", str(os.getpid())])
    run(["open", "-a", str(PEER_APP), "--stdout", str(peer_log),
         "--stderr", str(out / "peer.err"), "--args",
         "--duration", str(args.duration + 15),
         "--interval", str(args.interval),
         "--seed", str(args.seed)]
        + (["--corpus", args.corpus] if args.corpus else []),
        timeout=30)
    time.sleep(6)  # CoreBluetooth power-up + first advertisement

    def stop_peer():
        subprocess.run(["pkill", "-f", "BLEPeer.app/Contents/MacOS"],
                       capture_output=True)
        caffeinate.terminate()
    deadline = time.time() + max(30, args.duration - 10)
    launches: list[dict] = []
    crashes: list[dict] = []
    next_launch = time.time()
    while time.time() < deadline:
        if time.time() >= next_launch:
            if not stage_input(dev["udid"], args.scan_window):
                launches.append({"at": time.strftime("%H:%M:%S"),
                                 "error": "stage input failed"})
            else:
                code, console = launch_probe(dev["udid"],
                                             timeout=args.scan_window + 25)
                launches.append({
                    "at": time.strftime("%H:%M:%S"),
                    "code": code,
                    "verdict": parse_verdict(console),
                    "adv_hits": len(re.findall(r"PROBE adv-hit", console)),
                    "reads": len(re.findall(r"PROBE char ", console)),
                    "connected": bool(re.search(r"PROBE connected", console)),
                })
            for p in harvest_crashes(out):
                crashes.append({"file": p.name})
            next_launch = time.time() + max(15, args.relaunch_every)
            # stream per-launch progress so long windows are observable
            with open(out / "progress.jsonl", "a") as pf:
                pf.write(json.dumps(launches[-1]) + "\n")
        time.sleep(2)

    stop_peer()
    peer_out = peer_log.read_text(errors="replace") if peer_log.exists() else ""

    envelope = {
        "command": "ble-window",
        "ok": True,
        "data": {
            "device": dev,
            "peer_cases": len(re.findall(r"case=\d+ adv=", peer_out)),
            "peer_powered_on": "powered-on" in peer_out,
            "launches": launches,
            "launch_count": len(launches),
            "total_adv_hits": sum(l["adv_hits"] for l in launches),
            "total_char_reads": sum(l["reads"] for l in launches),
            "verdicts": [l["verdict"] for l in launches],
            "new_crash_reports": crashes,
        },
    }
    print(json.dumps(envelope, indent=1))
    (out / "window.json").write_text(json.dumps(envelope, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
