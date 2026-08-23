"""Security tests: generated-harness smoke runs execute isolated (#124)."""

from __future__ import annotations

from ios_research.harness import smoke_run


GOOD_DRIVER = (
    "def fuzz(data: bytes) -> str:\n"
    "    from ios_research import targets\n"
    "    return targets.create('mock:parser').execute(data).outcome\n"
)


class TestIsolation:
    def test_good_driver_reports_outcome(self):
        result = smoke_run(GOOD_DRIVER, "mock:parser")
        assert result["ok"] is True
        assert result["outcome"] == "accepted"

    def test_os_exit_candidate_cannot_kill_caller(self):
        # A candidate that hard-exits must not take this process down.
        hostile = ("import os\n"
                   "def fuzz(data):\n"
                   "    os._exit(9)\n")
        result = smoke_run(hostile, "mock:parser", timeout_s=15)
        assert result["ok"] is False
        assert "exit code 9" in result["error"]

    def test_infinite_loop_is_bounded_by_timeout(self):
        loop = ("def fuzz(data):\n"
                "    while True:\n"
                "        pass\n")
        result = smoke_run(loop, "mock:parser", timeout_s=3)
        assert result["ok"] is False
        assert "exceeded" in result["error"]

    def test_raising_candidate_returns_clean_error(self):
        boom = ("def fuzz(data):\n"
                "    raise RuntimeError('boom')\n")
        result = smoke_run(boom, "mock:parser")
        assert result == {"ok": False,
                          "error": "RuntimeError: boom"}

    def test_missing_entry_point_detected(self):
        result = smoke_run("x = 1\n", "mock:parser")
        assert result == {"ok": False,
                          "error": "no callable 'fuzz' after execution"}

    def test_stdout_noise_does_not_break_verdict_parsing(self):
        noisy = ("import sys\n"
                 "sys.stdout.write('JUNK' * 100)\n"
                 "def fuzz(data):\n"
                 "    return 'accepted'\n")
        result = smoke_run(noisy, "mock:parser")
        assert result["ok"] is True
        assert result["outcome"] == "accepted"

    def test_unknown_target_surfaces_as_failure(self):
        result = smoke_run(GOOD_DRIVER, "no:such-target")
        assert result["ok"] is False
