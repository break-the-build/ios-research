"""Guard the CLI lazy-import behavior (goal 04 cli-performance).

Lightweight commands must not import the heavy engine modules; each engine loads
only when a command that needs it runs. Runs in subprocesses so module state is
isolated from the rest of the suite.
"""

from __future__ import annotations

import subprocess
import sys

_HEAVY = [
    "ios_research.fuzz", "ios_research.research", "ios_research.agent",
    "ios_research.differential", "ios_research.analysis", "ios_research.report",
    "ios_research.triage", "ios_research.corpus", "ios_research.targets",
    "ios_research.experiment",
]


def _loaded_after(argv):
    """Return which heavy modules are loaded after running the CLI with argv."""
    code = (
        "import sys, io, contextlib\n"
        "from ios_research.cli import main\n"
        "buf = io.StringIO()\n"
        "with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):\n"
        "    try: main(%r)\n"
        "    except SystemExit: pass\n"
        "heavy = %r\n"
        "print(','.join(h for h in heavy if h in sys.modules))\n"
    ) % (argv, _HEAVY)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True)
    return set(filter(None, out.stdout.strip().split(",")))


def test_version_loads_no_heavy_engines():
    assert _loaded_after(["version"]) == set()


def test_help_loads_no_heavy_engines():
    assert _loaded_after(["--help"]) == set()


def test_doctor_loads_no_heavy_engines():
    assert _loaded_after(["doctor"]) == set()


def test_build_parser_loads_no_heavy_engines():
    code = (
        "import sys\n"
        "from ios_research.cli import build_parser\n"
        "build_parser()\n"
        "heavy = %r\n"
        "print(','.join(h for h in heavy if h in sys.modules))\n"
    ) % (_HEAVY,)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True)
    assert out.stdout.strip() == ""


def test_fuzz_command_does_load_its_engine(tmp_path):
    # Sanity: a command that needs an engine still imports it (deferred, not
    # broken).
    ws = tmp_path / ".ios-research"
    subprocess.run([sys.executable, "-c",
                    "from ios_research.cli import main; main(['init','--workspace',%r])" % str(ws)],
                   capture_output=True)
    loaded = _loaded_after(["fuzz", "start", "--target", "mock:parser",
                            "--max-cases", "50", "--workspace", str(ws)])
    assert "ios_research.fuzz" in loaded
