"""Custom authorized-target SDK (#33): manifest, templates, build, register.

Researchers already hold harnesses for their *own* parsing code. This module
lets them wrap such a harness as a first-class ios-research target without
touching framework code:

    target init     -> write a language template (C / C++ / Swift / Obj-C)
    target build    -> run the manifest's argv (no shell), record provenance
    target validate -> prove seed health, crash parsing and reproducibility
    target register -> expose it as ``custom:<name>`` at runtime

The versioned manifest (``schema_version`` 1) pins the entry point, build
command/profile, seed & dictionary locations, sanitizer profile, timeout and —
required — an explicit authorization acknowledgement. Validation fails closed
unless ``authorization.ack`` is true: the SDK only ever builds and runs local,
user-declared targets on the researcher's own machine (see ``SECURITY.md``);
there is no device bypass, persistence or exploit capability here.

Templates carry deliberately triggerable ASan-detectable bugs keyed on byte
markers ("OOB"/"WRT"/"UAF", modeled on ``tools/harness/mac_fuzz_harness.c``
HARNESS_TARGET_SELFTEST) so ``target validate`` can prove that real crash
reports flow through the standard pipeline. C/C++ templates also expose a
libFuzzer-compatible ``LLVMFuzzerTestOneInput``; Swift/Obj-C fall back to a
simple argv-based driver because Apple clang ships no libFuzzer runtime.
"""

from __future__ import annotations

import json
import os
import platform as _platform
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import targets as _targets
from .clock import now_iso
from .errors import StateError, ValidationError
from .hashing import sha256_bytes
from .ids import make_id
from .sanitizers import get_profile, validate_profile
from .targets.base import ExecResult, Outcome, Target
from .workspace import Workspace

MANIFEST_SCHEMA_VERSION = 1
LANGUAGES = ("c", "cpp", "swift", "objc")
DEFAULT_TIMEOUT_S = 10.0
MAX_BUILD_TIMEOUT_S = 3600.0
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
BUILD_SIDECAR = "target-build.json"
LOG_TAIL_CHARS = 2000


# --- manifest model -----------------------------------------------------------

@dataclass
class TargetManifest:
    """Versioned description of one custom authorized target."""

    name: str
    language: str                      # c | cpp | swift | objc
    source: str                        # entry-point source, relative to base_dir
    build_cmd: list[str]               # argv with a literal "{out}" placeholder
    output_path: str                   # built binary, relative to base_dir
    seeds: list[str] = field(default_factory=list)
    dictionary: str | None = None
    sanitizer_profile: str = "asan-ubsan"
    timeout_s: float = DEFAULT_TIMEOUT_S
    schema_version: int = MANIFEST_SCHEMA_VERSION
    authorization_ack: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "language": self.language,
            "source": self.source,
            "build_cmd": list(self.build_cmd),
            "output_path": self.output_path,
            "seeds": list(self.seeds),
            "dictionary": self.dictionary,
            "sanitizer_profile": self.sanitizer_profile,
            "timeout_s": self.timeout_s,
            "authorization": {"ack": bool(self.authorization_ack)},
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "TargetManifest":
        auth = raw.get("authorization")
        return cls(
            name=raw.get("name"),
            language=raw.get("language"),
            source=raw.get("source"),
            build_cmd=raw.get("build_cmd"),
            output_path=raw.get("output_path"),
            seeds=raw.get("seeds") or [],
            dictionary=raw.get("dictionary"),
            sanitizer_profile=raw.get("sanitizer_profile", ""),
            timeout_s=raw.get("timeout_s", DEFAULT_TIMEOUT_S),
            schema_version=raw.get("schema_version"),
            authorization_ack=bool(isinstance(auth, dict) and auth.get("ack")),
        )


def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(x, str) for x in value)


def validate_manifest(manifest: TargetManifest | dict[str, Any],
                      *, platform: str | None = None) -> list[str]:
    """Return all problems with ``manifest`` in a stable order (empty = valid).

    Pure function: no filesystem access, no toolchain probes.
    """
    if isinstance(manifest, dict):
        manifest = TargetManifest.from_dict(manifest)
    problems: list[str] = []

    if manifest.schema_version != MANIFEST_SCHEMA_VERSION:
        problems.append(
            f"unsupported schema_version {manifest.schema_version!r}; "
            f"expected {MANIFEST_SCHEMA_VERSION}")
    if not isinstance(manifest.name, str) or not NAME_RE.match(manifest.name or ""):
        problems.append(
            "name must match [a-z0-9][a-z0-9_-]{0,31}")
    if manifest.language not in LANGUAGES:
        problems.append(
            f"language must be one of {', '.join(LANGUAGES)}")
    if not isinstance(manifest.source, str) or not manifest.source:
        problems.append("source must be a non-empty relative path")
    elif os.path.isabs(manifest.source) or ".." in Path(manifest.source).parts:
        problems.append("source must be relative to the manifest directory")
    if not _is_str_list(manifest.build_cmd) or not manifest.build_cmd:
        problems.append("build_cmd must be a non-empty list of strings (no shell)")
    elif "{out}" not in manifest.build_cmd:
        problems.append('build_cmd must contain an "{out}" output placeholder')
    if not isinstance(manifest.output_path, str) or not manifest.output_path:
        problems.append("output_path must be a non-empty relative path")
    elif (os.path.isabs(manifest.output_path)
          or ".." in Path(manifest.output_path).parts):
        problems.append("output_path must be relative to the manifest directory")
    if not _is_str_list(manifest.seeds):
        problems.append("seeds must be a list of relative paths")
    if manifest.dictionary is not None and (
            not isinstance(manifest.dictionary, str)
            or not manifest.dictionary):
        problems.append("dictionary must be null or a non-empty relative path")

    timeout = manifest.timeout_s
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) \
            or timeout <= 0 or timeout > MAX_BUILD_TIMEOUT_S:
        problems.append(
            f"timeout_s must be a number in (0, {MAX_BUILD_TIMEOUT_S:.0f}]")

    profile = manifest.sanitizer_profile
    try:
        result = validate_profile(profile,
                                  platform=platform or _platform.system().lower())
        if not result["supported"]:
            problems.append(f"sanitizer profile unsupported: {result['reason']}")
    except ValidationError as exc:
        problems.append(f"sanitizer profile invalid: {exc.message}")

    if not manifest.authorization_ack:
        problems.append(
            "authorization.ack must be true: building and running this target "
            "executes local user-declared code and requires explicit "
            "authorization acknowledgement")
    return problems


def load_manifest(path: str | Path) -> tuple[TargetManifest, dict[str, Any]]:
    """Load and fully validate a ``target-manifest.json`` file.

    Returns ``(manifest, raw_dict)``; raises :class:`ValidationError` with a
    stable message listing every problem when invalid.
    """
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValidationError(f"cannot read manifest '{path}': {exc}") from exc
    except ValueError as exc:
        raise ValidationError(f"manifest '{path}' is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValidationError(f"manifest '{path}' must be a JSON object")
    if raw.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValidationError(
            f"unsupported manifest schema_version "
            f"{raw.get('schema_version')!r}; expected "
            f"{MANIFEST_SCHEMA_VERSION}")
    manifest = TargetManifest.from_dict(raw)
    problems = validate_manifest(manifest)
    if problems:
        raise ValidationError(
            f"invalid target manifest '{path}': " + "; ".join(problems),
            details={"problems": problems})
    return manifest, raw


def manifest_sha256(path: str | Path) -> str:
    """Content hash of a manifest file (provenance anchor)."""
    return sha256_bytes(Path(path).read_bytes())


# --- templates -----------------------------------------------------------------

_C_HARNESS = r"""/*
 * Custom ios-research target harness ({name}) — C, byte input.
 *
 * Deliberately triggerable ASan findings keyed on byte markers (modeled on
 * tools/harness/mac_fuzz_harness.c HARNESS_TARGET_SELFTEST) so
 * `ios-research target validate` can prove real crash parsing end to end:
 *   input contains "OOB" -> heap-buffer-overflow READ
 *   input contains "WRT" -> heap-buffer-overflow WRITE
 *   input contains "UAF" -> heap-use-after-free READ
 * Anything else is parsed cleanly. Authorized/own-machine research only.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int contains(const uint8_t *d, size_t n, const char *s) {
    size_t len = strlen(s);
    if (n < len) return 0;
    for (size_t i = 0; i + len <= n; i++) {
        if (memcmp(d + i, s, len) == 0) return 1;
    }
    return 0;
}

static int parse_record(const uint8_t *data, size_t size) {
    uint8_t *buf = (uint8_t *)malloc(16);
    if (!buf) return 0;
    memset(buf, 0, 16);
    if (contains(data, size, "OOB")) {
        volatile uint8_t x = buf[16 + (size & 0x3F)];  /* heap OOB read  */
        (void)x;
    } else if (contains(data, size, "WRT")) {
        buf[64] = 0x41;                                /* heap OOB write */
    } else if (contains(data, size, "UAF")) {
        free(buf);
        volatile uint8_t y = buf[0];                   /* use-after-free */
        (void)y;
        buf = NULL;
    }
    if (buf) free(buf);
    return 1;
}

/* libFuzzer-compatible entry point (used when built with -fsanitize=fuzzer;
 * see docs/TARGET-SDK.md for the two build modes). */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return parse_record(data, size) ? 0 : 0;
}

#ifndef HARNESS_SDK_NO_MAIN
/* Standalone driver: Apple clang ships no libFuzzer runtime, so the default
 * build links this main instead. Runs each argv file through the entry point;
 * ASan reports go to stderr and exit non-zero (exitcode=99). */
int main(int argc, char **argv) {
    static uint8_t blob[1 << 20];
    for (int i = 1; i < argc; i++) {
        FILE *fh = fopen(argv[i], "rb");
        if (!fh) { perror(argv[i]); return 2; }
        size_t n = fread(blob, 1, sizeof(blob), fh);
        fclose(fh);
        (void)LLVMFuzzerTestOneInput(blob, n);
    }
    return 0;
}
#endif /* HARNESS_SDK_NO_MAIN */
"""

_CPP_HARNESS = r"""/*
 * Custom ios-research target harness ({name}) — C++, byte input.
 *
 * Same marker scheme as the C template (OOB/WRT/UAF -> distinct ASan
 * classifications) so `target validate` can prove real crash parsing.
 * Authorized/own-machine research only.
 */
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>

static bool contains(const uint8_t *d, size_t n, const char *s) {
    size_t len = std::strlen(s);
    if (n < len) return false;
    for (size_t i = 0; i + len <= n; i++) {
        if (std::memcmp(d + i, s, len) == 0) return true;
    }
    return false;
}

static int parse_record(const uint8_t *data, size_t size) {
    auto *buf = static_cast<uint8_t *>(std::malloc(16));
    if (!buf) return 0;
    std::memset(buf, 0, 16);
    if (contains(data, size, "OOB")) {
        volatile uint8_t x = buf[16 + (size & 0x3F)];  /* heap OOB read  */
        static_cast<void>(x);
    } else if (contains(data, size, "WRT")) {
        buf[64] = 0x41;                                /* heap OOB write */
    } else if (contains(data, size, "UAF")) {
        std::free(buf);
        volatile uint8_t y = buf[0];                   /* use-after-free */
        static_cast<void>(y);
        buf = nullptr;
    }
    if (buf) std::free(buf);
    return 1;
}

/* libFuzzer-compatible entry point (see docs/TARGET-SDK.md). */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return parse_record(data, size) ? 0 : 0;
}

#ifndef HARNESS_SDK_NO_MAIN
/* Standalone driver (Apple clang ships no libFuzzer runtime). */
int main(int argc, char **argv) {
    static uint8_t blob[1 << 20];
    for (int i = 1; i < argc; i++) {
        std::FILE *fh = std::fopen(argv[i], "rb");
        if (!fh) { std::perror(argv[i]); return 2; }
        size_t n = std::fread(blob, 1, sizeof(blob), fh);
        std::fclose(fh);
        (void)LLVMFuzzerTestOneInput(blob, n);
    }
    return 0;
}
#endif /* HARNESS_SDK_NO_MAIN */
"""

_SWIFT_HARNESS = r"""/*
 * Custom ios-research target harness ({name}) — Swift, byte input.
 *
 * Platform fallback driver: Apple's toolchain ships no libFuzzer runtime, so
 * this template uses a simple argv-based `run_one_input` main instead of a
 * libFuzzer entry point (docs/TARGET-SDK.md). Same OOB/WRT/UAF marker scheme
 * as the C template; build with -sanitize=address (the declared sanitizer
 * profile) so the findings are caught and reported. Authorized research only.
 */
import Foundation

func contains(_ data: [UInt8], _ marker: [UInt8]) -> Bool {
    guard marker.count <= data.count else { return false }
    return data.contains(marker)
}

func parseRecord(_ data: [UInt8]) -> Int32 {
    guard let raw = malloc(16) else { return 1 }
    memset(raw, 0, 16)
    let buf = raw.assumingMemoryBound(to: UInt8.self)
    let oob = Array("OOB".utf8), wrt = Array("WRT".utf8), uaf = Array("UAF".utf8)
    if contains(data, oob) {
        let v = buf[16 + (data.count & 0x3F)]      // heap OOB read (ASan)
        _ = v
    } else if contains(data, wrt) {
        buf[64] = 0x41                             // heap OOB write (ASan)
    } else if contains(data, uaf) {
        free(raw)
        let v = buf[0]                             // use-after-free (ASan)
        _ = v
        return 0
    }
    free(raw)
    return 0
}

func runOneInput(_ path: String) -> Int32 {
    guard let data = FileManager.default.contents(atPath: path) else {
        FileHandle.standardError.write(Data("cannot read \(path)\n".utf8))
        return 2
    }
    return parseRecord([UInt8](data))
}

// Driver: `harness <file>` — one input per process, like the libFuzzer mode.
let args = CommandLine.arguments
if args.count < 2 {
    FileHandle.standardError.write(Data("usage: harness <input-file>\n".utf8))
    exit(2)
}
exit(runOneInput(args[1]))
"""

_OBJC_HARNESS = r"""/*
 * Custom ios-research target harness ({name}) — Objective-C, byte input.
 *
 * Platform fallback: plain Objective-C (no Foundation dependency) with an
 * argv-based driver because Apple clang ships no libFuzzer runtime. Same
 * OOB/WRT/UAF marker scheme as the C template. Authorized research only.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int contains(const uint8_t *d, size_t n, const char *s) {
    size_t len = strlen(s);
    if (n < len) return 0;
    for (size_t i = 0; i + len <= n; i++) {
        if (memcmp(d + i, s, len) == 0) return 1;
    }
    return 0;
}

static int parse_record(const uint8_t *data, size_t size) {
    uint8_t *buf = (uint8_t *)malloc(16);
    if (!buf) return 0;
    memset(buf, 0, 16);
    if (contains(data, size, "OOB")) {
        volatile uint8_t x = buf[16 + (size & 0x3F)];  /* heap OOB read  */
        (void)x;
    } else if (contains(data, size, "WRT")) {
        buf[64] = 0x41;                                /* heap OOB write */
    } else if (contains(data, size, "UAF")) {
        free(buf);
        volatile uint8_t y = buf[0];                   /* use-after-free */
        (void)y;
        buf = NULL;
    }
    if (buf) free(buf);
    return 1;
}

/* Standalone driver (Apple clang ships no libFuzzer runtime). */
int main(int argc, char **argv) {
    static uint8_t blob[1 << 20];
    for (int i = 1; i < argc; i++) {
        FILE *fh = fopen(argv[i], "rb");
        if (!fh) { perror(argv[i]); return 2; }
        size_t n = fread(blob, 1, sizeof(blob), fh);
        fclose(fh);
        (void)parse_record(blob, n);
    }
    return 0;
}
"""

# Per-language template assets: source file name, source text, build command
# (argv, "{out}" placeholder; sanitizer flags come from the declared profile).
_TEMPLATES = {
    "c": {
        "source": "harness.c",
        "body": _C_HARNESS,
        "build_cmd": ["cc", "-g", "-O1", "-fno-omit-frame-pointer",
                      "-DHARNESS_SDK_STANDALONE", "harness.c", "-o", "{out}"],
    },
    "cpp": {
        "source": "harness.cpp",
        "body": _CPP_HARNESS,
        "build_cmd": ["c++", "-g", "-O1", "-fno-omit-frame-pointer",
                      "-DHARNESS_SDK_STANDALONE", "harness.cpp", "-o", "{out}"],
    },
    # Swift/Obj-C document the supported-platform fallback: Apple ships no
    # libFuzzer runtime, so they use the argv driver; the sanitizer flags are
    # supplied by the declared profile at build time.
    "swift": {
        "source": "harness.swift",
        "body": _SWIFT_HARNESS,
        "build_cmd": ["swiftc", "-g", "-Onone", "harness.swift",
                      "-o", "{out}"],
    },
    "objc": {
        "source": "harness.m",
        "body": _OBJC_HARNESS,
        "build_cmd": ["cc", "-g", "-O1", "-fno-omit-frame-pointer",
                      "-x", "objective-c", "harness.m", "-o", "{out}"],
    },
}

CLEAN_SEED = b"clean-seed-no-marker\n"


def default_manifest(name: str, language: str, *,
                     acknowledge: bool = False) -> TargetManifest:
    """The manifest a fresh template gets for ``name``/``language``."""
    tpl = _TEMPLATES[language]
    return TargetManifest(
        name=name,
        language=language,
        source=tpl["source"],
        build_cmd=list(tpl["build_cmd"]),
        output_path="build/harness",
        seeds=["seeds"],
        dictionary=None,
        sanitizer_profile="asan-ubsan",
        timeout_s=DEFAULT_TIMEOUT_S,
        schema_version=MANIFEST_SCHEMA_VERSION,
        authorization_ack=bool(acknowledge),
    )


def init_template(language: str, dest_dir: str | Path, name: str, *,
                  acknowledge: bool = False) -> Path:
    """Write one language template project; returns the manifest path.

    Layout: ``<dest>/target-manifest.json``, the harness source, and a
    ``seeds/`` directory holding one clean seed. Refuses to overwrite an
    existing non-empty destination (deterministic, no clobbering).
    """
    if language not in LANGUAGES:
        raise ValidationError(
            f"unknown language '{language}'; expected one of "
            f"{', '.join(LANGUAGES)}")
    if not NAME_RE.match(name or ""):
        raise ValidationError(
            f"invalid target name '{name}': must match "
            f"[a-z0-9][a-z0-9_-]{{0,31}}")
    dest = Path(dest_dir)
    if dest.exists() and any(dest.iterdir()):
        raise ValidationError(
            f"destination '{dest}' exists and is not empty; "
            f"choose a fresh --dest directory")
    tpl = _TEMPLATES[language]
    manifest = default_manifest(name, language, acknowledge=acknowledge)

    dest.mkdir(parents=True, exist_ok=True)
    (dest / tpl["source"]).write_text(tpl["body"].replace("{name}", name),
                                      encoding="utf-8")
    seeds_dir = dest / "seeds"
    seeds_dir.mkdir(exist_ok=True)
    (seeds_dir / "seed_0.bin").write_bytes(CLEAN_SEED)
    manifest_path = dest / "target-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return manifest_path


# --- environment / build provenance ---------------------------------------------

def environment_provenance() -> dict[str, str]:
    """Stable host/environment stamp captured with every build and registration."""
    return {
        "platform": _platform.system().lower(),
        "machine": _platform.machine(),
        "python": _platform.python_version(),
    }


def _resolve_tool(argv0: str) -> str:
    """Resolve the build launcher; ``CC`` overrides a bare 'cc' (make convention)."""
    override = os.environ.get("CC")
    if argv0 == "cc" and override:
        return override
    return argv0


def _tool_version(tool: str) -> str:
    """First line of ``<tool> --version`` ("" when unavailable); best effort."""
    try:
        proc = subprocess.run([tool, "--version"], capture_output=True,
                              timeout=30)
        line = (proc.stdout or b"").decode("utf-8", "replace").splitlines()
        return line[0].strip() if line else ""
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover - probe
        return ""


def _profile_compile_flags(manifest: TargetManifest) -> list[str]:
    return list(get_profile(manifest.sanitizer_profile).compile_flags)


def build(manifest_path: str | Path, *, timeout_s: float = 300.0
          ) -> dict[str, Any]:
    """Build a target from its manifest.

    Runs the manifest argv via subprocess (never a shell) inside the manifest
    directory, prepending the sanitizer profile's compile flags. Returns
    ``{"output_path", "duration_ms", "log_tail", "provenance"}`` and persists
    provenance to a ``target-build.json`` sidecar next to the manifest so
    later registrations capture build/environment provenance.

    Raises :class:`StateError` (stable JSON error via the CLI) when the
    toolchain is unavailable or the compiler fails.
    """
    path = Path(manifest_path)
    manifest, _raw = load_manifest(path)
    if not isinstance(timeout_s, (int, float)) or timeout_s <= 0 \
            or timeout_s > MAX_BUILD_TIMEOUT_S:
        raise ValidationError(
            f"timeout_s must be a number in (0, {MAX_BUILD_TIMEOUT_S:.0f}]")

    base = path.resolve().parent
    source = base / manifest.source
    if not source.is_file():
        raise StateError(
            f"harness source '{manifest.source}' not found in '{base}'; "
            f"re-run 'target init' or fix manifest.source")
    out = (base / manifest.output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    argv = [str(tok) for tok in manifest.build_cmd]
    launcher = _resolve_tool(argv[0])
    flags = _profile_compile_flags(manifest)
    full_argv = [launcher, *flags, *argv[1:]]
    full_argv = [tok.replace("{out}", str(out)) for tok in full_argv]

    start = time.monotonic()
    try:
        proc = subprocess.run(full_argv, cwd=str(base), capture_output=True,
                              timeout=float(timeout_s))
    except FileNotFoundError:
        raise StateError(
            f"build tool '{launcher}' not found on PATH; install a toolchain "
            f"(e.g. 'xcode-select --install' on macOS) or fix "
            f"manifest.build_cmd[0]") from None
    except subprocess.TimeoutExpired:
        raise StateError(
            f"build exceeded {timeout_s}s budget; increase --timeout-s or "
            f"simplify manifest.build_cmd") from None
    duration_ms = int((time.monotonic() - start) * 1000)

    log = ((proc.stderr or b"") + (proc.stdout or b"")).decode(
        "utf-8", "replace")
    if proc.returncode != 0:
        tail = log.strip()[-LOG_TAIL_CHARS:]
        raise StateError(
            f"build failed with exit code {proc.returncode}: {tail}",
            details={"command": full_argv})

    log_tail = log.strip()[-LOG_TAIL_CHARS:]
    provenance = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "manifest_sha256": manifest_sha256(path),
        "command": full_argv,
        "compiler": _tool_version(launcher),
        "flags": flags,
        "output_path": str(out),
        "duration_ms": duration_ms,
        "environment": environment_provenance(),
        "built_at": now_iso(),
    }
    sidecar = base / BUILD_SIDECAR
    sidecar.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n",
                       encoding="utf-8")
    return {
        "output_path": str(out),
        "duration_ms": duration_ms,
        "log_tail": log_tail,
        "provenance": provenance,
    }


def load_build_provenance(base_dir: str | Path) -> dict[str, Any] | None:
    """Load the ``target-build.json`` sidecar written by :func:`build`."""
    sidecar = Path(base_dir) / BUILD_SIDECAR
    if not sidecar.is_file():
        return None
    try:
        blob = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return blob if isinstance(blob, dict) else None


# --- target adapter ---------------------------------------------------------------

class ManifestTarget(Target):
    """Execute a manifest-built binary over single inputs (mock = False).

    Outcome mapping mirrors :class:`~ios_research.targets.mac.MacFuzzTarget`:
    exit 0 → ACCEPTED; non-zero with a recognizable sanitizer report → CRASH
    (normalized via :mod:`ios_research.targets.asan`); non-zero otherwise →
    ABNORMAL; budget exceeded → TIMEOUT.
    """

    kind = "custom-native"
    mock = False

    def __init__(self, manifest: TargetManifest, *, base_dir: str | Path) -> None:
        self.manifest = manifest
        self.base_dir = Path(base_dir).resolve()
        self.target_id = f"custom:{manifest.name}"
        self.description = (
            f"user-declared {manifest.language} target '{manifest.name}' "
            f"(authorized local harness)")
        self.formats = ("raw",)
        self.timeout_s = float(manifest.timeout_s)
        self._profile = get_profile(manifest.sanitizer_profile)

    # -- discovery ----------------------------------------------------------
    @property
    def binary(self) -> Path:
        return (self.base_dir / self.manifest.output_path).resolve()

    def available(self) -> bool:
        """True when the built binary exists and is executable."""
        return self.binary.is_file() and os.access(self.binary, os.X_OK)

    def blocker(self) -> str:
        if self.available():
            return ""
        return (f"binary not built at {self.binary}; run "
                f"'ios-research target build <target-manifest.json>'")

    def describe(self) -> dict[str, Any]:
        d = super().describe()
        d.update({
            "language": self.manifest.language,
            "source": self.manifest.source,
            "sanitizer_profile": self.manifest.sanitizer_profile,
            "entry_point": ("LLVMFuzzerTestOneInput"
                            if self.manifest.language in ("c", "cpp")
                            else "argv file driver"),
            "available": self.available(),
            "blocker": self.blocker(),
            "manifest_sha256": self.manifest_sha256(),
            "note": ("real native harness from a user-declared manifest; "
                     "authorized/own-machine research only"),
        })
        prov = load_build_provenance(self.base_dir)
        if prov is not None:
            d["build_provenance"] = prov
        return d

    def manifest_sha256(self) -> str:
        path = self.base_dir / "target-manifest.json"
        try:
            return manifest_sha256(path)
        except OSError:
            return ""

    # -- format hooks -------------------------------------------------------
    def seeds(self) -> list[bytes]:
        """Read the manifest's seed files/directories (deterministic order)."""
        blobs: list[bytes] = []
        for entry in self.manifest.seeds:
            path = (self.base_dir / entry).resolve()
            if path.is_file():
                blobs.append(path.read_bytes())
            elif path.is_dir():
                for child in sorted(path.iterdir()):
                    if child.is_file():
                        blobs.append(child.read_bytes())
        return blobs[:64]

    # -- lifecycle ------------------------------------------------------------
    def prepare(self) -> None:   # nothing persistent to set up
        pass

    def cleanup(self) -> None:
        pass

    def _run(self, data: bytes) -> ExecResult:
        import time as _time

        if not self.available():
            return ExecResult(outcome=Outcome.ABNORMAL,
                              detail=self.blocker(), duration_ms=0)
        start = _time.monotonic()
        tmp = tempfile.NamedTemporaryFile(
            prefix="ios-research-custom-", suffix=".input", delete=False)
        try:
            tmp.write(data)
            tmp.flush()
            tmp.close()
            env = dict(os.environ)
            for key, value in self._profile.runtime_env.items():
                env.setdefault(key, value)
            try:
                proc = subprocess.run([str(self.binary), tmp.name],
                                      capture_output=True, env=env,
                                      timeout=self.timeout_s)
            except subprocess.TimeoutExpired:
                dur = int((_time.monotonic() - start) * 1000)
                return ExecResult(outcome=Outcome.TIMEOUT,
                                  detail=(f"harness exceeded "
                                          f"{self.timeout_s}s budget"),
                                  duration_ms=dur)
            except OSError as exc:  # pragma: no cover - defensive
                return ExecResult(outcome=Outcome.ABNORMAL,
                                  detail=f"failed to execute harness: {exc}",
                                  duration_ms=0)

            dur = int((_time.monotonic() - start) * 1000)
            report = (proc.stderr or b"").decode("utf-8", "replace")
            if proc.returncode == 0:
                return ExecResult(outcome=Outcome.ACCEPTED,
                                  detail="input handled without a finding",
                                  duration_ms=max(dur, 1))
            if _asan_is_crash_report(report):
                diag = _asan_parse(report, module=self.manifest.name)
                first = report.splitlines()[0].strip() if report else ""
                return ExecResult(outcome=Outcome.CRASH,
                                  detail=first[:500]
                                  or "sanitizer reported a crash",
                                  duration_ms=max(dur, 1), diagnostics=diag)
            detail = (report.strip().splitlines()[-1][:500]
                      if report.strip()
                      else f"harness exited with code {proc.returncode}")
            return ExecResult(outcome=Outcome.ABNORMAL, detail=detail,
                              duration_ms=max(dur, 1))
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass


def _asan_is_crash_report(text: str) -> bool:
    from .targets import asan
    return asan.is_crash_report(text)


def _asan_parse(text: str, *, module: str):
    from .targets import asan
    return asan.parse(text, module=module)


# --- validation pipeline -----------------------------------------------------------

_CRASH_MARKERS = (("OOB", "OUT_OF_BOUNDS_READ"),
                  ("WRT", "OUT_OF_BOUNDS_WRITE"),
                  ("UAF", "USE_AFTER_FREE"))


def validate_target(manifest_path: str | Path, *,
                    build_timeout_s: float = 300.0) -> dict[str, Any]:
    """End-to-end validation of a custom target.

    Checks, in order: manifest validity, availability/build, seed health,
    crash parsing (each known marker must produce its expected ASan
    classification) and reproducibility (same signature on a second run).
    Returns a structured summary; raises :class:`ValidationError` when the
    overall check fails so the CLI surfaces a stable JSON error.
    """
    from .targets.base import Outcome as _Outcome

    path = Path(manifest_path)
    manifest, _raw = load_manifest(path)   # raises with stable messages
    base = path.resolve().parent
    target = ManifestTarget(manifest, base_dir=base)

    built_here = False
    if not target.available():
        build(path, timeout_s=build_timeout_s)
        built_here = True
    if not target.available():  # pragma: no cover - defensive
        raise StateError(f"target '{target.target_id}' still unavailable after "
                         f"build: {target.blocker()}")

    seed_outcomes = [_Outcome.ACCEPTED if target.execute(s).outcome
                     in (_Outcome.ACCEPTED, _Outcome.REJECTED)
                     else _Outcome.ABNORMAL for s in target.seeds()]
    seeds_accepted = sum(1 for o in seed_outcomes
                         if o in (_Outcome.ACCEPTED, _Outcome.REJECTED))

    markers: list[dict[str, Any]] = []
    reproducible = True
    for marker, expected_class in _CRASH_MARKERS:
        payload = marker.encode("ascii") + b"." * 20
        first = target.execute(payload)
        second = target.execute(payload)
        cls = (first.diagnostics.classification_hint
               if first.diagnostics else "")
        same = (first.outcome == _Outcome.CRASH
                and second.outcome == _Outcome.CRASH
                and first.diagnostics is not None
                and second.diagnostics is not None
                and first.diagnostics.signature == second.diagnostics.signature)
        reproducible = reproducible and same
        markers.append({
            "marker": marker,
            "outcome": first.outcome,
            "classification": cls,
            "expected_classification": expected_class,
            "classification_ok": cls == expected_class,
            "signature": (first.diagnostics.signature
                          if first.diagnostics else ""),
            "reproducible": same,
        })

    crash_pipeline_ok = any(m["classification_ok"] and m["reproducible"]
                            for m in markers)
    ok = (seeds_accepted == len(seed_outcomes) and seed_outcomes
          and crash_pipeline_ok and reproducible)
    result = {
        "ok": ok,
        "target_id": target.target_id,
        "built_now": built_here,
        "seeds_total": len(seed_outcomes),
        "seeds_accepted": seeds_accepted,
        "crash_markers": markers,
        "reproducible": reproducible,
        "manifest_sha256": manifest_sha256(path),
    }
    if not ok:
        failed = []
        if seed_outcomes and seeds_accepted != len(seed_outcomes):
            failed.append("seed health")
        if not crash_pipeline_ok:
            failed.append("crash parsing")
        if not reproducible:
            failed.append("reproducibility")
        raise ValidationError(
            f"target validation failed for '{target.target_id}': "
            f"{', '.join(failed)}", details=result)
    return result


# --- registration -------------------------------------------------------------------

def register_manifest(workspace: Workspace | None, manifest_path: str | Path,
                      ) -> str:
    """Register a validated manifest as ``custom:<name>`` — no code changes.

    Persists a registration record (manifest, content hash, environment and
    any recorded build provenance) under ``targets/`` in the workspace so
    experiments can cite exactly what was built and run.
    """
    path = Path(manifest_path)
    manifest, raw = load_manifest(path)
    base = path.resolve().parent
    target_id = f"custom:{manifest.name}"

    def _factory() -> ManifestTarget:
        return ManifestTarget(manifest, base_dir=base)

    _targets.register(target_id, _factory)

    if workspace is not None:
        record = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "id": make_id("custom", manifest.name),
            "target_id": target_id,
            "registered_at": now_iso(),
            # Absolute project directory so later processes can rehydrate the
            # registration without re-supplying the path.
            "base_dir": str(base),
            "manifest": raw,
            "manifest_sha256": manifest_sha256(path),
            "environment": environment_provenance(),
        }
        provenance = load_build_provenance(base)
        if provenance is not None:
            record["build_provenance"] = provenance
        workspace.write_json(f"targets/custom-{manifest.name}.json", record)
    return target_id


def hydrate_manifests(workspace: Workspace | None = None) -> int:
    """Re-register every recorded custom target from a workspace.

    Called lazily by the target registry so ``custom:<name>`` targets survive
    across CLI invocations (register once, then fuzz/minimize/report in any
    later process). Prefers the live manifest on disk (re-validated); falls
    back to the stored copy when the project has moved. Skips broken records
    silently — hydration must never break the registry.
    """
    ws = workspace or Workspace.locate()
    if ws is None or not ws.initialized:
        return 0
    base_dir = ws.dir("targets")
    count = 0
    for record_path in sorted(base_dir.glob("custom-*.json")):
        try:
            record = ws.read_json(f"targets/{record_path.name}")
            manifest, _raw = _hydrate_one(record)
            base = Path(record.get("base_dir") or record_path.parent)
            _targets.register(
                f"custom:{manifest.name}",
                (lambda m, b: (lambda: ManifestTarget(m, base_dir=b)))(
                    manifest, base))
            count += 1
        except Exception:  # noqa: BLE001 - skip broken/stale records
            continue
    return count


def _hydrate_one(record: dict[str, Any]) -> tuple[TargetManifest, dict]:
    """Resolve one registration record into a validated manifest."""
    base = Path(record.get("base_dir", "."))
    live = base / "target-manifest.json"
    source = live if live.is_file() else None
    if source is not None:
        try:
            return load_manifest(source)
        except ValidationError:
            pass   # changed since registration; fall back to stored copy
    raw = record.get("manifest")
    if not isinstance(raw, dict):
        raise ValidationError("registration record has no manifest")
    problems = validate_manifest(raw)
    if problems:
        raise ValidationError("; ".join(problems[:1]))
    return TargetManifest.from_dict(raw), raw
