"""ios_research_detection environment (goal 22).

Measures the built-in detection signatures against a seeded, labeled sample
set: spyware/persistence capability-indicator samples (assembled from the
same public technique strings the rules encode) versus benign iOS/macOS
application strings. Metrics follow standard detection-engineering practice:
recall, false-positive rate, F1, and scan throughput.

This is a *self-consistency* benchmark of the rule engine and shipped rules
against their own documented indicators. It is not a malware zoo evaluation;
production rulesets should be validated against vetted IOC feeds.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from experiment_loop.environments.base import (
    KNOB_BOOL, KNOB_CHOICE, BaseEnvironment, Knob, Trace, register,
)
from experiment_loop.models import MAXIMIZE, MINIMIZE, MetricSpec, Observation

from ios_research import detection
from .common import temp_workspace  # noqa: F401  (keeps parity with siblings)

_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

# Labeled positives: each triggers >=1 built-in rule at default thresholds.
_POSITIVES = {
    "spyware": (b"AVAudioRecorder AVCaptureDevice CLLocationManager "
                b"SecItemCopyMatching POST /"),
    "persistence": (b"<?xml plist /Library/LaunchDaemons/com.evil.p "
                    b"RunAtLoad KeepAlive"),
    "keychain": (b"SecItemCopyMatching kSecClassGenericPassword "
                 b"kSecReturnAttributes"),
    "tcc": b"TCC.db kTCCService client_reference",
}

# Labeled negatives: ordinary application/framework strings.
_NEGATIVES = [
    b"UICollectionView didSelectRowAt indexPath",
    b"NSFileManager contentsOfDirectoryAtPath error",
    b"GET /index.html HTTP/1.1 Host: example.test",
    b"com.example.app didFinishLaunchingWithOptions",
    b"CFBundleIdentifier com.apple.dt.Xcode",
    b"TODO: refactor settings screen layout",
]


def _labeled_samples() -> list[tuple[bytes, int]]:
    """(payload, is_positive) pairs; positives repeat per family."""
    samples: list[tuple[bytes, int]] = []
    for payload in _POSITIVES.values():
        samples.append((payload, 1))
    for payload in _NEGATIVES:
        samples.append((payload, 0))
    return samples


@register
class IosResearchDetectionEnvironment(BaseEnvironment):
    name = "ios_research_detection"
    cost_per_sample = 0.0

    knob_list = (
        Knob(name="min_severity", kind=KNOB_CHOICE,
             values=_SEVERITY_ORDER, default="info",
             description="count only matches at or above this severity"),
        Knob(name="dedupe_by_family", kind=KNOB_BOOL, default=False,
             description="collapse multiple rule matches per sample to one "
                         "family-level detection before scoring"),
    )

    metric_list = (
        MetricSpec("detection_recall", MAXIMIZE, "ratio"),
        MetricSpec("false_positive_rate", MINIMIZE, "ratio"),
        MetricSpec("detection_f1", MAXIMIZE, "score"),
        MetricSpec("rules_loaded", MAXIMIZE, "count"),
        MetricSpec("scans_per_second", MAXIMIZE, "scans/s"),
    )

    def _fires(self, data: bytes, rules, min_severity: str,
               dedupe_by_family: bool) -> bool:
        result = detection.scan_bytes(data, rules)
        threshold = _SEVERITY_ORDER.index(min_severity)
        matched = [m for m in result["matches"]
                   if _SEVERITY_ORDER.index(m["severity"]) >= threshold]
        if dedupe_by_family:
            return bool({m["family"] for m in matched})
        return bool(matched)

    def run(self, config: Mapping[str, Any], *, samples: int,
            seed: int) -> Observation:
        min_severity = str(config.get("min_severity", "info"))
        dedupe = bool(config.get("dedupe_by_family", False))
        rules = detection.load_rules(detection.builtin_rules_path())

        labeled = _labeled_samples()
        # Deterministic rotation so larger sample counts revisit the set.
        ordered = [labeled[(seed + i) % len(labeled)]
                   for i in range(max(samples, len(labeled)))]

        tp = fp = tn = fn = 0
        t0 = time.perf_counter()
        for data, label in ordered:
            detected = self._fires(data, rules, min_severity, dedupe)
            if label and detected:
                tp += 1
            elif label and not detected:
                fn += 1
            elif not label and detected:
                fp += 1
            else:
                tn += 1
        elapsed = max(time.perf_counter() - t0, 1e-9)

        recall = tp / (tp + fn) if (tp + fn) else 1.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) else 0.0)

        vals = {
            "detection_recall": [recall],
            "false_positive_rate": [fpr],
            "detection_f1": [f1],
            "rules_loaded": [float(len(rules))],
            "scans_per_second": [len(ordered) / elapsed],
        }
        return self.summarize(Trace(values=vals), samples)
