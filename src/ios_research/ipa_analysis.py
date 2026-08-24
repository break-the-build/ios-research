"""Authorized IPA static and configuration analysis (#44).

Complements dynamic fuzzing with high-signal configuration findings for
*user-provided* app bundles:

* entitlements and provisioning metadata,
* Info.plist privacy / ATS / security-relevant keys,
* signing artifacts, linked frameworks, declared network endpoints.

Every finding carries a stable rule id, location, evidence, severity
rationale, and remediation guidance. Built-in rules are versioned data;
researchers may supply additional **declarative** local rule packs (with their
own provenance) and explicit suppressions — suppressed findings stay visible,
marked ``suppressed`` so review is never silent. Bundles are read locally and
never uploaded; evidence values are redacted of secret-shaped keys.
"""

from __future__ import annotations

import json
import plistlib
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ValidationError
from .hashing import sha256_bytes
from .logging_util import _REDACTED, _REDACT_KEYS

ANALYSIS_SCHEMA_VERSION = 1
BUILTIN_RULES_VERSION = 1

_HTTP_RE = re.compile(rb"https?://[A-Za-z0-9.\-_]+(?::\d+)?")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str            # info | low | medium | high
    location: str
    evidence: str
    remediation: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "location": self.location,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "rationale": self.rationale,
        }


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): (_REDACTED if str(k).lower() in _REDACT_KEYS
                         else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _load_bundle(path: Path) -> dict[str, bytes]:
    """Return ``{relative_name: bytes}`` for an .app dir or .ipa/.zip."""
    entries: dict[str, bytes] = {}
    if path.is_dir():
        prefix = f"{path.name.rstrip('.app')}.app/" if path.name.endswith(
            ".app") else ""
        for file in sorted(path.rglob("*")):
            if file.is_file():
                rel = str(file.relative_to(path))
                entries[prefix + rel] = file.read_bytes()
        return entries
    if path.suffix.lower() in (".ipa", ".zip"):
        try:
            with zipfile.ZipFile(path) as bundle:
                for info in bundle.infolist():
                    if not info.is_dir():
                        entries[info.filename] = bundle.read(info.filename)
        except zipfile.BadZipFile as exc:
            raise ValidationError(f"malformed archive: {exc}") from exc
        return entries
    raise ValidationError(
        f"unsupported bundle: {path} (.app directory or .ipa/.zip expected)")


def _find_one(entries: dict[str, bytes], suffix: str) -> tuple[str, bytes]:
    for name, blob in sorted(entries.items()):
        if name.endswith(suffix):
            return name, blob
    raise KeyError(suffix)


def _parse_plist(blob: bytes) -> dict[str, Any]:
    try:
        parsed = plistlib.loads(blob)
    except Exception as exc:  # noqa: BLE001 - malformed input is expected
        raise ValidationError(f"unparseable plist: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValidationError("plist root must be a dictionary")
    return parsed


def builtin_rules_version() -> int:
    return BUILTIN_RULES_VERSION


def analyze_bundle(path: str | Path, *,
                   extra_rules: list[dict[str, Any]] | None = None,
                   suppressions: list[dict[str, str]] | None = None
                   ) -> dict[str, Any]:
    """Produce deterministic, redacted findings for one bundle."""
    bundle_path = Path(path)
    if not bundle_path.exists():
        raise ValidationError(f"bundle not found: {bundle_path}")
    entries = _load_bundle(bundle_path)

    findings: list[Finding] = []
    findings.extend(_check_signature(entries))
    findings.extend(_check_ats(entries))
    findings.extend(_check_entitlements(entries))
    findings.extend(_check_endpoints(entries))
    findings.extend(_check_frameworks(entries))
    findings.extend(_evaluate_extra_rules(entries, extra_rules or []))

    suppressed_keys = {(s.get("rule_id"), s.get("path"))
                       for s in suppressions or []}
    records = []
    for finding in sorted(findings, key=lambda f: f.rule_id):
        entry = finding.to_dict()
        pair = (finding.rule_id, None)
        pair_with_loc = (finding.rule_id, finding.location)
        entry["suppressed"] = pair in suppressed_keys or \
            pair_with_loc in suppressed_keys
        records.append(_redact(entry))

    return {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "kind": "ipa-static-analysis",
        "bundle": bundle_path.name,
        "bundle_sha256": sha256_bytes(
            b"".join(blob for _name, blob in sorted(entries.items()))),
        "builtin_rules_version": BUILTIN_RULES_VERSION,
        "extra_rules": len(extra_rules or []),
        "findings": records,
        "counts": _counts(records),
        "note": ("configuration observations from a locally supplied "
                 "bundle; no exploitability or store-compliance claim"),
    }


def _counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        counts[record["severity"]] = counts.get(record["severity"], 0) + 1
    return dict(sorted(counts.items()))


# --- built-in rules ----------------------------------------------------------

def _check_signature(entries: dict[str, bytes]) -> list[Finding]:
    has_sig = any("_CodeSignature/CodeResources" in name
                  for name in entries)
    if has_sig:
        return []
    return [Finding(
        rule_id="IPA-SIGN-001",
        severity="high",
        location="bundle",
        evidence="no _CodeSignature/CodeResources found",
        remediation="re-sign the bundle and verify with codesign",
        rationale="unsigned code cannot be attributed to a developer and "
                  "fails platform integrity guarantees",
    )]


def _check_ats(entries: dict[str, bytes]) -> list[Finding]:
    try:
        _name, blob = _find_one(entries, "Info.plist")
        info = _parse_plist(blob)
    except KeyError:
        return [Finding("IPA-INFO-002", "medium", "Info.plist",
                        "Info.plist missing",
                        "ship a valid Info.plist",
                        "the property list drives platform security policy")]
    ats = info.get("NSAppTransportSecurity") or {}
    if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
        return [Finding(
            rule_id="IPA-ATS-003",
            severity="high",
            location="Info.plist:NSAppTransportSecurity",
            evidence="NSAllowsArbitraryLoads=true",
            remediation="remove the global ATS exception; allow specific "
                        "domains instead",
            rationale="disables App Transport Security for every connection "
                      "the app makes",
        )]
    return []


def _check_entitlements(entries: dict[str, bytes]) -> list[Finding]:
    out: list[Finding] = []
    for name, blob in sorted(entries.items()):
        if not name.endswith(".mobileprovision"):
            continue
        # Provisioning profiles embed a plist after the CMS blob; find it.
        start = blob.find(b"<?xml")
        if start < 0:
            continue
        try:
            profile = _parse_plist(blob[start:])
        except ValidationError:
            continue
        ent = profile.get("Entitlements") or {}
        if isinstance(ent, dict) and ent.get("get-task-allow") is True:
            out.append(Finding(
                rule_id="IPA-ENT-004",
                severity="medium",
                location=name,
                evidence="get-task-allow=true",
                remediation="distribute with a release provisioning profile",
                rationale="debuggable entitlement permits debugger attach",
            ))
    return out


def _check_endpoints(entries: dict[str, bytes]) -> list[Finding]:
    hosts: set[str] = set()
    for name, blob in entries.items():
        if name.endswith((".nib", ".car", ".png", ".jpg")):
            continue
        # Skip plist DTD boilerplate ("http://www.apple.com/DTDs/...")
        lines = [line for line in blob.splitlines()
                 if b"DTD" not in line and b"DOCTYPE" not in line]
        for match in _HTTP_RE.findall(b"\n".join(lines))[:64]:
            host = match.decode("ascii", "replace")
            if host.startswith("http://"):
                hosts.add(host)
    if not hosts:
        return []
    return [Finding(
        rule_id="IPA-NET-005",
        severity="low",
        location=", ".join(sorted(hosts))[:200],
        evidence=f"{len(hosts)} cleartext http:// endpoint(s)",
        remediation="use https:// everywhere",
        rationale="cleartext transport exposes traffic to interception",
    )]


_STANDARD_PREFIXES = ("/System/Library/", "/usr/lib/")


def _check_frameworks(entries: dict[str, bytes]) -> list[Finding]:
    unusual = []
    for name in entries:
        if name.endswith(".dylib") and "/Frameworks/" not in name:
            unusual.append(name)
    if not unusual:
        return []
    return [Finding(
        rule_id="IPA-FWK-006",
        severity="info",
        location=", ".join(sorted(unusual))[:200],
        evidence="dylibs embedded outside Frameworks/",
        remediation="embed dynamic libraries under <Bundle>/Frameworks/",
        rationale="non-standard layout complicates code-signing validation",
    )]


def _evaluate_extra_rules(entries: dict[str, bytes],
                          extra_rules: list[dict[str, Any]]
                          ) -> list[Finding]:
    """Declarative local rules: match on plist keys inside named files."""
    findings: list[Finding] = []
    for rule in extra_rules:
        try:
            rule_id = rule["rule_id"]
            match = rule["match"]
            severity = rule.get("severity", "info")
            remediation = rule.get("remediation", "")
            rationale = rule.get("rationale", "declared local rule matched")
            suffix = match["plist_suffix"]
            key_path = match["key"].split(".")
            equals = match.get("equals")
        except (KeyError, TypeError) as exc:
            raise ValidationError(
                f"invalid extra rule: missing {exc}") from exc
        for name, blob in sorted(entries.items()):
            if not name.endswith(suffix):
                continue
            try:
                doc = _parse_plist(blob)
            except ValidationError:
                continue
            node: Any = doc
            for part in key_path:
                if not isinstance(node, dict) or part not in node:
                    break
                node = node[part]
            else:
                if equals is None or node == equals:
                    findings.append(Finding(
                        rule_id=rule_id, severity=severity, location=name,
                        evidence=f"{match['key']}={node!r}",
                        remediation=remediation, rationale=rationale))
    return findings


def load_rule_pack(path: str | Path) -> tuple[list[dict[str, Any]],
                                              list[dict[str, str]], dict]:
    """Load a local rule pack with provenance: rules + suppressions."""
    pack_path = Path(path)
    try:
        pack = json.loads(pack_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"cannot read rule pack: {exc}") from exc
    if not isinstance(pack, dict):
        raise ValidationError("rule pack must be a JSON object")
    rules = pack.get("rules", [])
    suppressions = pack.get("suppressions", [])
    if not isinstance(rules, list) or not isinstance(suppressions, list):
        raise ValidationError("rule pack rules/suppressions must be lists")
    provenance = {
        "name": pack.get("name", ""),
        "version": pack.get("version", ""),
        "sha256": sha256_bytes(pack_path.read_bytes()),
    }
    return rules, suppressions, provenance
