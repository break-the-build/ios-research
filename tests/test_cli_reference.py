import subprocess
import sys
from pathlib import Path


def test_committed_cli_reference_is_current():
    repo = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, str(repo / "tools" / "gen_cli_reference.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=repo,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
