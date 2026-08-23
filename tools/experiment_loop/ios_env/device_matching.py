"""ios_research_device_matching environment (on-device target, issue #11).

The black-box on-device target (:mod:`ios_research.targets.device`) stages one
input to an authorized iPhone and then must attribute a freshly harvested
``.ips`` crash report to *that* input. On a busy device this is a best-effort
heuristic (baseline snapshot + timestamp/process match), so its accuracy is a
real, tunable property worth measuring.

This environment drives the **real** :class:`IosDeviceTarget` and the **real**
:mod:`ios_research.targets.ips` parser against a *seeded simulation* of a busy
device: pre-existing crash reports, an optional crash caused by our input, and
background crashes from unrelated processes appearing in the poll window. It
measures how well the target attributes crashes under two knobs that genuinely
affect correctness:

* ``use_baseline`` — snapshot pre-existing reports and exclude them (else old
  reports masquerade as newly produced).
* ``require_process`` — pin the expected faulting process (else an unrelated
  background crash is mis-attributed to our input).

The simulation is fully in-process (no hardware); it exercises the same matching
and normalization code the real backend uses. ``simulated = True``: seeded and
repeatable, so paired arms see identical device populations.
"""

from __future__ import annotations

import json
import random
import time
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_BOOL, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research.targets import ips
from ios_research.targets.device import IosDeviceTarget

# The process our input is meant to crash, plus unrelated processes that also
# crash on a busy device (SpringBoard, daemons, other apps).
_TARGET_PROCESS = "MediaPlaybackd"
_NOISE_PROCESSES = ("SpringBoard", "dasd", "backboardd", "PhotoAnalysis",
                    "SafariViewService")


def _make_ips(proc: str, seq: int) -> tuple[str, str]:
    """Return ``(identifier, ips_text)`` for a crash in ``proc``.

    The identifier embeds a zero-padded sequence so lexical sort == time order
    (matching how the real backend sorts report filenames).
    """
    header = {"bug_type": "309", "name": proc,
              "os_version": "iPhone OS 17.0 (21A329)",
              "timestamp": f"2026-08-23 10:{seq:02d}:00.00 -0700"}
    body = {
        "procName": proc,
        "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV",
                      "subtype": "KERN_INVALID_ADDRESS at 0x0000000123456780"},
        "faultingThread": 0,
        "threads": [{"triggered": True,
                     "threadState": {"pc": {"value": 0x1a2b3c00 + seq}},
                     "frames": [{"imageIndex": 0, "symbol": f"decode_{proc}",
                                 "imageOffset": 0x100 + seq}]}],
        "usedImages": [{"name": proc}],
    }
    ident = f"{proc}-2026-08-23-1000{seq:02d}.ips"
    return ident, json.dumps(header) + "\n" + json.dumps(body)


class _SimBackend:
    """In-memory DeviceBackend simulating a busy device for one trial.

    Uses the real :mod:`ios_research.targets.ips` parser for process matching, so
    ``collect_new_reports`` reproduces the real backend's filtering semantics
    exactly — only the transport (disk/USB) is replaced by an in-memory list.
    """

    def __init__(self, *, baseline: list[tuple[str, str]],
                 new_reports: list[tuple[str, str]], use_baseline: bool) -> None:
        self._baseline = baseline
        self._all = baseline + new_reports  # what the device holds after delivery
        self._use_baseline = use_baseline

    def available(self) -> bool:
        return True

    def blocker(self) -> str:
        return ""

    def udid(self) -> str:
        return "SIMULATEDUDID0001"

    def device_info(self, udid: str) -> dict[str, str]:
        return {"model": "iPhone14,2", "os_name": "iOS",
                "os_version": "17.0", "os_build": "21A329"}

    def snapshot_reports(self, udid: str) -> set[str]:
        # An operator can disable the baseline snapshot; then old reports are
        # indistinguishable from new ones (the failure mode we measure).
        if not self._use_baseline:
            return set()
        return {ident for ident, _ in self._baseline}

    def deliver(self, surface: str, input_path: str, udid: str) -> None:
        return None

    def collect_new_reports(self, udid: str, since: set[str],
                            process: str | None) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for ident, text in sorted(self._all, key=lambda r: r[0]):
            if ident in since:
                continue
            if not ips.is_crash_report(text):
                continue
            if process:
                meta = ips.parse_metadata(text)
                if meta.get("process") and process not in meta["process"]:
                    continue
            out.append((ident, text))
        return out


@register
class IosResearchDeviceMatchingEnvironment(BaseEnvironment):
    name = "ios_research_device_matching"
    cost_per_sample = 0.0
    simulated = True

    knob_list = (
        Knob(name="use_baseline", kind=KNOB_BOOL, default=True,
             description="snapshot pre-existing reports and exclude them"),
        Knob(name="require_process", kind=KNOB_BOOL, default=False,
             description="pin the expected faulting process when matching"),
    )

    metric_list = (
        MetricSpec("attribution_accuracy", MAXIMIZE, "ratio"),
        MetricSpec("false_attribution_rate", MINIMIZE, "ratio"),
        MetricSpec("miss_rate", MINIMIZE, "ratio"),
        MetricSpec("match_latency_ms", MINIMIZE, "ms"),
    )

    _TRIALS = 60  # device scenarios per sample

    def _trial(self, rng: random.Random) -> tuple[
            bool, bool, list[tuple[str, str]], list[tuple[str, str]]]:
        """Simulate one device scenario.

        Returns ``(caused_crash, background_noise, baseline_reports,
        new_reports)`` — the pre-existing and post-delivery report sets a real
        device would present to the target.
        """
        seq = 1
        baseline: list[tuple[str, str]] = []
        # Pre-existing reports already on the device (incl. some from the target
        # process — these must NOT be attributed to our input).
        for _ in range(rng.randint(0, 3)):
            proc = _TARGET_PROCESS if rng.random() < 0.5 else rng.choice(_NOISE_PROCESSES)
            baseline.append(_make_ips(proc, seq))
            seq += 1

        caused_crash = rng.random() < 0.5
        new_reports: list[tuple[str, str]] = []
        # Background crashes on a busy device (unrelated processes).
        background = rng.random() < 0.5
        if background:
            for _ in range(rng.randint(1, 2)):
                new_reports.append((_make_ips(rng.choice(_NOISE_PROCESSES), seq)))
                seq += 1
        # Our input's crash, if any — may or may not be the newest report.
        if caused_crash:
            new_reports.append(_make_ips(_TARGET_PROCESS, seq))
            seq += 1
        return caused_crash, background, baseline, new_reports

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        use_baseline = bool(config.get("use_baseline", True))
        require_process = bool(config.get("require_process", False))
        process = _TARGET_PROCESS if require_process else None

        vals: dict[str, list[float]] = {m.name: [] for m in self.metric_list}

        for s in range(samples):
            rng = random.Random(seed * 100003 + s)
            correct = 0
            false_attrib = 0
            noncrash_trials = 0
            misses = 0
            crash_trials = 0
            latencies: list[float] = []

            for _ in range(self._TRIALS):
                caused, background, baseline, new_reports = self._trial(rng)
                backend = _SimBackend(baseline=baseline, new_reports=new_reports,
                                      use_baseline=use_baseline)
                target = IosDeviceTarget("imageio", backend=backend,
                                         timeout_s=0.05, poll_s=0.0,
                                         process=process)
                t0 = time.perf_counter()
                res = target.execute(b"input-under-test")
                latencies.append((time.perf_counter() - t0) * 1000.0)

                reported_crash = res.outcome == "crash"
                # Correct iff: we caused a crash AND it was attributed to the
                # target process; or we caused none AND none was reported.
                attributed_to_target = False
                if reported_crash and res.diagnostics:
                    proc = (res.diagnostics.thread or {}).get("name", "")
                    attributed_to_target = proc == _TARGET_PROCESS

                if caused:
                    crash_trials += 1
                    if attributed_to_target:
                        correct += 1
                    else:
                        misses += 1
                else:
                    noncrash_trials += 1
                    if reported_crash:
                        false_attrib += 1
                    else:
                        correct += 1

            vals["attribution_accuracy"].append(correct / self._TRIALS)
            vals["false_attribution_rate"].append(
                false_attrib / noncrash_trials if noncrash_trials else 0.0)
            vals["miss_rate"].append(
                misses / crash_trials if crash_trials else 0.0)
            vals["match_latency_ms"].append(sum(latencies) / len(latencies))

        return self.summarize(Trace(values=vals), samples)
