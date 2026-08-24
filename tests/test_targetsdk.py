"""Custom authorized-target SDK: manifest, templates, build, register (#33).

The manifest/template/registry paths run everywhere. The compiled end-to-end
path (init -> build -> register -> real ASan crashes) is skipped unless a C
compiler is on PATH — mirroring the opt-in native tests in
tests/test_mac_target.py.
"""

from __future__ import annotations

import json
import shutil

import pytest

from ios_research import targets as target_registry
from ios_research.errors import StateError, ValidationError
from ios_research.sanitizers import PROFILES
from ios_research.targetsdk import (
    ManifestTarget, TargetManifest, build, init_template, load_manifest,
    register_manifest, validate_manifest, validate_target,
)
from ios_research.targets.base import Outcome


def _has_cc() -> bool:
    return shutil.which("cc") is not None


def _valid_manifest(**overrides):
    raw = {
        "schema_version": 1,
        "name": "sample",
        "language": "c",
        "source": "harness.c",
        "build_cmd": ["cc", "-g", "harness.c", "-o", "{out}"],
        "output_path": "build/harness",
        "seeds": ["seeds"],
        "dictionary": None,
        "sanitizer_profile": "asan-ubsan",
        "timeout_s": 10.0,
        "authorization": {"ack": True},
    }
    raw.update(overrides)
    return raw


def _flip_ack(manifest_path, ack=True):
    """Flip authorization.ack in a freshly written template manifest."""
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["authorization"]["ack"] = ack
    manifest_path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")


# --- manifest validation -------------------------------------------------------

def test_manifest_missing_ack_fails():
    problems = validate_manifest(_valid_manifest(
        authorization={"ack": False}))
    assert any("authorization.ack" in p for p in problems)
    assert any("authorization.ack" in p for p in validate_manifest(
        _valid_manifest(authorization={})))
    # Missing authorization section entirely.
    raw = _valid_manifest()
    del raw["authorization"]
    assert any("authorization.ack" in p for p in validate_manifest(raw))


def test_manifest_bad_language_fails():
    problems = validate_manifest(_valid_manifest(language="rust"))
    assert any("language" in p for p in problems)


def test_manifest_unknown_sanitizer_profile_fails():
    problems = validate_manifest(_valid_manifest(sanitizer_profile="bogus"))
    assert any("sanitizer profile invalid" in p for p in problems)
    # A known-but-unsupported profile for the host platform also fails closed.
    unsupported = [pid for pid, prof in PROFILES.items()
                   if "darwin" not in prof.platforms]
    if unsupported:
        problems = validate_manifest(
            _valid_manifest(sanitizer_profile=unsupported[0]),
            platform="darwin")
        assert any("unsupported" in p for p in problems)


def test_manifest_valid_passes_with_no_problems():
    assert validate_manifest(_valid_manifest()) == []


def test_load_manifest_raises_with_stable_message(tmp_path):
    path = tmp_path / "target-manifest.json"
    path.write_text(json.dumps(_valid_manifest(authorization={"ack": False})),
                    encoding="utf-8")
    with pytest.raises(ValidationError) as exc:
        load_manifest(path)
    assert "authorization.ack" in str(exc.value)

    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_manifest(path)


def test_validate_manifest_problem_order_is_stable():
    a = validate_manifest(_valid_manifest(language="x", name="BAD NAME"))
    b = validate_manifest(_valid_manifest(language="x", name="BAD NAME"))
    assert a == b and len(a) >= 2


# --- templates -------------------------------------------------------------------

@pytest.mark.parametrize("language,source", [
    ("c", "harness.c"),
    ("cpp", "harness.cpp"),
    ("swift", "harness.swift"),
    ("objc", "harness.m"),
])
def test_init_writes_all_language_templates(tmp_path, language, source):
    dest = tmp_path / language
    manifest_path = init_template(language, dest, f"t{language}")
    assert manifest_path.is_file()
    assert (dest / source).is_file()
    assert (dest / "seeds" / "seed_0.bin").is_file()

    from ios_research.targetsdk import CLEAN_SEED
    assert (dest / "seeds" / "seed_0.bin").read_bytes() == CLEAN_SEED

    # Templates ship structurally valid but *unacknowledged*: parse the raw
    # JSON (load_manifest would fail closed on the missing authorization).
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest = TargetManifest.from_dict(raw)
    problems = validate_manifest(raw)
    assert [p for p in problems if "authorization.ack" not in p] == []
    assert manifest.name == f"t{language}"
    assert manifest.language == language
    assert manifest.authorization_ack is False
    assert "{out}" in manifest.build_cmd


def test_c_template_has_libfuzzer_entry(tmp_path):
    dest = tmp_path / "proj"
    init_template("c", dest, "entrycheck")
    text = (dest / "harness.c").read_text(encoding="utf-8")
    assert "LLVMFuzzerTestOneInput" in text
    # ...and marker-keyed deliberate bugs so validation can prove crash parsing.
    for marker in ("OOB", "WRT", "UAF"):
        assert marker in text


def test_init_refuses_occupied_destination(tmp_path):
    dest = tmp_path / "proj"
    init_template("c", dest, "one")
    with pytest.raises(ValidationError):
        init_template("c", dest, "two")


def test_init_rejects_bad_name_and_language(tmp_path):
    with pytest.raises(ValidationError):
        init_template("c", tmp_path / "a", "Bad Name!")
    with pytest.raises(ValidationError):
        init_template("rust", tmp_path / "b", "fine")


# --- build -------------------------------------------------------------------------

def test_build_unavailable_toolchain_is_state_error(tmp_path, monkeypatch):
    manifest_path = init_template("c", tmp_path / "proj", "nobuild")
    _flip_ack(manifest_path)
    monkeypatch.setenv("CC", "/nonexistent/cc")
    with pytest.raises(StateError) as exc:
        build(manifest_path)
    assert "/nonexistent/cc" in str(exc.value)
    assert "PATH" in str(exc.value)


def test_build_requires_source_present(tmp_path):
    manifest_path = init_template("c", tmp_path / "proj", "nosrc")
    _flip_ack(manifest_path)
    (manifest_path.parent / "harness.c").unlink()
    with pytest.raises(StateError):
        build(manifest_path)


# --- end-to-end (compiled C target; needs `cc` on PATH) -----------------------------

@pytest.mark.skipif(not _has_cc(), reason="requires a C compiler ('cc') on PATH")
def test_c_target_end_to_end_crash_pipeline(workspace, tmp_path):
    """init -> build -> register -> execute: real ASan classifications."""
    dest = tmp_path / "sample-target"
    manifest_path = init_template("c", dest, "sample")
    _flip_ack(manifest_path)

    result = build(manifest_path)
    binary = result["output_path"]
    import os
    assert os.access(binary, os.X_OK)
    prov = result["provenance"]
    assert prov["command"][0] == "cc"   # CC env unset here -> plain launcher
    assert "-fsanitize=address,undefined" in prov["flags"]
    assert prov["environment"]["platform"]

    target_id = register_manifest(workspace, manifest_path)
    assert target_id == "custom:sample"
    try:
        assert target_registry.is_registered(target_id)
        target = target_registry.create(target_id)
        assert isinstance(target, ManifestTarget)
        assert target.mock is False
        assert target.available()

        expect = {
            b"OOB" + b"." * 20: "OUT_OF_BOUNDS_READ",
            b"WRT" + b"." * 20: "OUT_OF_BOUNDS_WRITE",
            b"UAF" + b"." * 20: "USE_AFTER_FREE",
        }
        sigs = set()
        for payload, cls in expect.items():
            res = target.execute(payload)
            assert res.outcome == Outcome.CRASH, res.detail
            assert res.diagnostics.classification_hint == cls
            assert res.diagnostics.faulting_address
            sigs.add(res.diagnostics.signature)
        assert len(sigs) == 3   # distinct signatures -> dedup works

        # Clean seed accepted; manifest seeds are actually read from disk.
        clean = target.execute(b"clean-input-no-marker")
        assert clean.outcome == Outcome.ACCEPTED
        seeds = target.seeds()
        assert seeds and all(
            target.execute(s).outcome == Outcome.ACCEPTED for s in seeds)
    finally:
        target_registry._REGISTRY.pop(target_id, None)


@pytest.mark.skipif(not _has_cc(), reason="requires a C compiler ('cc') on PATH")
def test_c_target_reproducible_twice(workspace, tmp_path):
    """The same crashing input yields the same signature on repeated runs."""
    dest = tmp_path / "repro"
    manifest_path = init_template("c", dest, "repro")
    _flip_ack(manifest_path)
    build(manifest_path)
    target = ManifestTarget(load_manifest(manifest_path)[0],
                            base_dir=dest)
    payload = b"UAF" + b"x" * 24
    first = target.execute(payload)
    second = target.execute(payload)
    third = target.execute(payload)
    assert first.outcome == Outcome.CRASH
    assert first.diagnostics.signature == second.diagnostics.signature \
        == third.diagnostics.signature


@pytest.mark.skipif(not _has_cc(), reason="requires a C compiler ('cc') on PATH")
def test_validate_target_full_pipeline(workspace, tmp_path):
    """validate proves seed health, crash parsing, and reproducibility."""
    dest = tmp_path / "validated"
    manifest_path = init_template("c", dest, "validated")
    _flip_ack(manifest_path)

    result = validate_target(manifest_path)
    assert result["ok"] is True
    assert result["built_now"] is True
    assert result["seeds_accepted"] == result["seeds_total"] == 1
    assert all(m["classification_ok"] and m["reproducible"]
               for m in result["crash_markers"])

    # Provenance sidecar captured and picked up by describe().
    target = ManifestTarget(load_manifest(manifest_path)[0], base_dir=dest)
    d = target.describe()
    assert d["available"] is True
    assert d["build_provenance"]["compiler"]


@pytest.mark.skipif(not _has_cc(), reason="requires a C compiler ('cc') on PATH")
def test_validate_target_unacked_manifest_fails_stable(tmp_path):
    manifest_path = init_template("c", tmp_path / "unacked", "unacked")
    with pytest.raises(ValidationError) as exc:
        validate_target(manifest_path)
    assert "authorization.ack" in str(exc.value)


# --- registration -------------------------------------------------------------------

def test_register_manifest_records_provenance_in_workspace(workspace, tmp_path):
    dest = tmp_path / "reg"
    manifest_path = init_template("c", dest, "regsdk")
    # Registration requires a fully valid (acked) manifest.
    _flip_ack(manifest_path)
    target_id = register_manifest(workspace, manifest_path)
    try:
        assert target_id == "custom:regsdk"
        assert target_registry.is_registered(target_id)
        record = workspace.read_json("targets/custom-regsdk.json")
        assert record["target_id"] == target_id
        assert record["manifest"]["language"] == "c"
        assert record["manifest_sha256"]
        assert record["environment"]["platform"]
        d = target_registry.create(target_id).describe()
        assert d["id"] == target_id
        assert "authorized" in d["note"]
    finally:
        target_registry._REGISTRY.pop(target_id, None)


def test_register_manifest_rejects_invalid(workspace, tmp_path):
    dest = tmp_path / "bad"
    manifest_path = init_template("c", dest, "badman")   # ack stays false
    with pytest.raises(ValidationError):
        register_manifest(workspace, manifest_path)
    assert not target_registry.is_registered("custom:badman")


def test_hydration_restores_registration_from_workspace(workspace, tmp_path):
    """A registered custom target resolves again in a 'fresh' process."""
    from ios_research.targetsdk import hydrate_manifests
    dest = tmp_path / "hyd"
    manifest_path = init_template("c", dest, "hydrate", acknowledge=False)
    _flip_ack(manifest_path)
    build(manifest_path)
    target_id = register_manifest(workspace, manifest_path)
    try:
        assert target_registry.is_registered(target_id)
        # Simulate a new process: registry forgets, workspace record restores.
        target_registry._REGISTRY.pop(target_id, None)
        assert not target_registry.is_registered(target_id)
        assert hydrate_manifests(workspace) >= 1
        target = target_registry.create(target_id)
        assert target.available()
        res = target.execute(b"OOB" + b"." * 20)
        assert res.outcome == Outcome.CRASH
    finally:
        target_registry._REGISTRY.pop(target_id, None)


def test_hydration_skips_broken_records(workspace, tmp_path):
    from ios_research.targetsdk import hydrate_manifests
    broken = {"schema_version": 1, "name": "broken", "manifest": "not-a-dict"}
    workspace.write_json("targets/custom-broken.json", broken)
    # Must not raise; bad records are skipped silently.
    hydrate_manifests(workspace)
    assert not target_registry.is_registered("custom:broken")


# --- target behavior without a build --------------------------------------------------

def test_unbuilt_target_reports_blocker(tmp_path):
    dest = tmp_path / "unbuilt"
    manifest_path = init_template("c", dest, "unbuilt", acknowledge=True)
    manifest, _raw = load_manifest(manifest_path)
    target = ManifestTarget(manifest, base_dir=dest)
    assert not target.available()
    assert "not built" in target.blocker()
    res = target.execute(b"data")
    assert res.outcome == Outcome.ABNORMAL
    assert "target build" in res.detail
