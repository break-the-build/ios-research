"""macOS reward-category verification oracle tests (#62)."""

from __future__ import annotations

import json

import pytest

from ios_research.errors import ValidationError
from ios_research.macoracles import (
    MacOracleEngine, gatekeeper_oracle, sandbox_escape_oracle, tcc_oracle,
)


# --- TCC ----------------------------------------------------------------------

def test_tcc_capture_without_consent_is_capture_evidence():
    verdict = tcc_oracle({"resource": "Photos",
                          "access_event": {"consent": "none"}})
    assert verdict.classification == "capture-evidence"
    assert "consent=none" in verdict.observed
    assert verdict.missing_for_claim


def test_tcc_sandboxed_capture_gets_stronger_classification():
    verdict = tcc_oracle({"resource": "contacts", "sandboxed_app": True,
                          "access_event": {"consent": "none"}})
    assert verdict.classification == "capture-evidence-sandboxed"
    assert any("app-sandbox" in item for item in verdict.missing_for_claim)


def test_tcc_denied_and_consented_are_not_captures():
    denied = tcc_oracle({"resource": "photos",
                         "access_event": {"consent": "denied"}})
    consented = tcc_oracle({"resource": "camera",
                            "access_event": {"consent": "granted"}})
    assert denied.classification == "no-capture-denied-path"
    assert consented.classification == "no-capture-consented"


def test_tcc_validates_inputs():
    with pytest.raises(ValidationError, match="unknown TCC resource"):
        tcc_oracle({"resource": "toaster",
                    "access_event": {"consent": "none"}})
    with pytest.raises(ValidationError, match="consent"):
        tcc_oracle({"resource": "photos",
                    "access_event": {"consent": "maybe"}})
    with pytest.raises(ValidationError, match="access_event"):
        tcc_oracle({"resource": "photos"})


# --- Gatekeeper ------------------------------------------------------------------

def test_gatekeeper_full_bypass_requires_quarantine_and_safari():
    verdict = gatekeeper_oracle({
        "download_source": "safari", "quarantine_bit": True,
        "assessment": {"result": "opened",
                       "checks_encountered": ["XProtect"]}})
    assert verdict.classification == "full-bypass-evidence"
    assert any("Safari download provenance" in m
               for m in verdict.missing_for_claim)


def test_gatekeeper_limited_interaction_and_compliant():
    limited = gatekeeper_oracle({
        "download_source": "airdrop", "quarantine_bit": True,
        "assessment": {"result": "opened"}})
    compliant = gatekeeper_oracle({
        "download_source": "safari", "quarantine_bit": False,
        "assessment": {"result": "blocked"}})
    assert limited.classification == "limited-interaction-evidence"
    assert compliant.classification == "compliant-behavior"


def test_gatekeeper_validates_assessment():
    with pytest.raises(ValidationError, match="assessment"):
        gatekeeper_oracle({"download_source": "safari",
                           "quarantine_bit": True})
    with pytest.raises(ValidationError, match="result"):
        gatekeeper_oracle({"download_source": "safari",
                           "quarantine_bit": True,
                           "assessment": {"result": "exploded"}})


# --- Sandbox escape ---------------------------------------------------------------

def test_sandbox_outside_container_observations_indicate_escape():
    verdict = sandbox_escape_oracle({
        "process_entitlements": [],
        "observations": [{"type": "file-handle-outside-container"},
                         {"type": "xpc-outside-entitlements"}]})
    assert verdict.classification == "escape-evidence-indicator"
    assert len(verdict.observed) == 3


def test_sandbox_contained_when_only_inside_observations():
    verdict = sandbox_escape_oracle({
        "process_entitlements": ["com.example.sandbox"],
        "observations": [{"type": "file-handle-inside-container"},
                         {"type": "xpc-within-entitlements"}]})
    assert verdict.classification == "contained"
    assert verdict.missing_for_claim == []


def test_sandbox_validates_observations():
    with pytest.raises(ValidationError, match="observations"):
        sandbox_escape_oracle({"process_entitlements": []})
    with pytest.raises(ValidationError, match="unknown type"):
        sandbox_escape_oracle({"process_entitlements": [],
                               "observations": [{"type": "teleport"}]})


# --- engine persistence -------------------------------------------------------------

def _evidence_file(tmp_path, payload):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_engine_persists_deterministic_verdicts(workspace, tmp_path):
    engine = MacOracleEngine(workspace)
    evidence = _evidence_file(tmp_path, {
        "resource": "photos", "access_event": {"consent": "none"}})
    first = engine.run(name="tcc", evidence_path=evidence)
    second = engine.run(name="tcc", evidence_path=evidence)
    assert first["id"] == second["id"]
    stored = workspace.read_json(f"analysis/{first['id']}.json")
    assert stored["kind"] == "oracle-verdict"
    assert stored["claim_separation"]
    with pytest.raises(ValidationError, match="unknown oracle"):
        engine.run(name="voodoo", evidence_path=evidence)


def test_engine_rejects_malformed_evidence(workspace, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    with pytest.raises(ValidationError, match="JSON object"):
        MacOracleEngine(workspace).run(name="tcc", evidence_path=str(bad))
