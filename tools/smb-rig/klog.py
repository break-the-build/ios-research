"""Kernel-log tap: smbfs log messages as a coverage proxy.

macOS offers no kernel coverage to a fuzzer, but smbfs logs a distinct
message on most parser error paths ("parse_create_contexts: Illegal context
name length", "rq_next_command: md_get_mem failed", ...). Each message is
normalised to a template; a template never seen before means a reply reached
a new branch. The tap writes every message to klog.tsv against the newest
case and calls on_new(template) for first sightings, which the rig uses to
promote the responsible mutated reply (favored.py).

Templates seen in earlier runs are remembered in a shared file so "new" means
new across campaigns, not just since the rig started.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from typing import TYPE_CHECKING, Callable, TextIO

if TYPE_CHECKING:                                       # typing.Self is 3.11+; CI also runs 3.10
    from typing import Self

from cases import utc_stamp

LOG_COMMAND = ("/usr/bin/log", "stream", "--style", "ndjson", "--level", "debug",
               "--predicate", 'process == "kernel" AND sender == "smbfs"')
MAX_RAW = 300

_SUBS = (
    (re.compile(r"<[^<>]*>"), "<S>"),                 # vnode / share names
    (re.compile(r"0x[0-9a-fA-F]+"), "X"),
    # bare hex printed without 0x ("fid 4f2a3f1a..."): any hex run containing a
    # digit. Without this every FileId looked like a new code path.
    (re.compile(r"\b(?=[0-9a-fA-F]*[a-fA-F])(?=[0-9a-fA-F]*\d)[0-9a-fA-F]+\b"), "X"),
    (re.compile(r"\d+"), "N"),
)


# Messages hinting at memory-safety trouble short of a panic: flagged ALERT in
# klog.tsv and reported loudly, since a silent heap problem may only panic later.
ALERT_RX = re.compile(r"panic|corrupt|overflow|underflow|assert|double.free|use.after.free|"
                      r"\bzone\b|kalloc|out of bounds|refcount|retain ?count|over-?release",
                      re.IGNORECASE)


def normalize(message: str) -> str:
    """Strip per-instance values so one code path maps to one template."""
    out = message.strip()
    for rx, rep in _SUBS:
        out = rx.sub(rep, out)
    return out


def load_seen(path: str) -> set[str]:
    try:
        with open(path) as f:
            return {line.rstrip("\n") for line in f if line.strip()}
    except OSError:
        return set()


class KernelLogTap:
    def __init__(self, run_dir: str, seen_path: str, current_case: Callable[[], int],
                 on_new: Callable[[str, int], None] | None = None,
                 command: tuple[str, ...] = LOG_COMMAND,
                 on_alert: Callable[[str, int], None] | None = None) -> None:
        self.on_alert = on_alert
        self.alerts = 0
        self.out_path = os.path.join(run_dir, "klog.tsv")
        self.seen_path = seen_path
        self.seen = load_seen(seen_path)
        self.baseline = len(self.seen)
        self.current_case = current_case
        self.on_new = on_new
        self.command = command
        self.lines = 0
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._out: TextIO | None = None                 # klog.tsv, line-buffered, opened lazily

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
        self.close()

    @property
    def new_templates(self) -> int:
        return len(self.seen) - self.baseline

    def start(self) -> None:
        self._proc = subprocess.Popen(self.command, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True)
        threading.Thread(target=self._pump, daemon=True).start()

    def stop(self) -> None:
        """Terminate `log stream`; the pump thread then drains and closes the file."""
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()

    def close(self) -> None:
        with self._lock:
            if self._out is not None:
                self._out.close()
                self._out = None

    def _pump(self) -> None:
        assert self._proc and self._proc.stdout
        try:
            with self._proc.stdout:                     # close the pipe when the stream ends
                for line in self._proc.stdout:
                    self.handle_line(line)
        finally:
            self.close()

    def handle_line(self, line: str) -> str | None:
        """Process one ndjson line; returns the template (or None if skipped)."""
        try:
            event = json.loads(line)
        except ValueError:
            return None                                 # the "Filtering the log..." banner
        message = event.get("eventMessage") if isinstance(event, dict) else None
        if not message:
            return None
        template = normalize(message)
        case = self.current_case()
        alert = bool(ALERT_RX.search(message))
        with self._lock:
            self.lines += 1
            self.alerts += alert
            is_new = template not in self.seen
            if is_new:
                self.seen.add(template)
                with open(self.seen_path, "a") as f:
                    f.write(template + "\n")
            flags = ",".join(f for f, on in (("NEW", is_new), ("ALERT", alert)) if on)
            if self._out is None:
                self._out = open(self.out_path, "a", buffering=1)   # noqa: SIM115 -- closed in close()
            self._out.write("\t".join((utc_stamp(), str(case), flags, template.replace("\t", " "),
                                       message[:MAX_RAW].replace("\t", " ").replace("\n", " "))) + "\n")
            if alert:
                os.fsync(self._out.fileno())            # an alert may precede a panic
        if is_new and self.on_new:
            self.on_new(template, case)
        if alert and self.on_alert:
            self.on_alert(message, case)
        return template
