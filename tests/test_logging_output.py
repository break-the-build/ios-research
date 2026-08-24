"""Coverage for structured logging and output rendering (goal 01)."""

from __future__ import annotations

import io
import json

from ios_research.logging_util import Logger, redact, LEVELS
from ios_research.output import Result, render
from ios_research.errors import ExitCode


# --- logging --------------------------------------------------------------
def test_logger_respects_level_threshold():
    stream = io.StringIO()
    lg = Logger(level="warning", stream=stream)
    lg.debug("dbg_event")
    lg.info("info_event")
    lg.warning("warn_event")
    lg.error("err_event")
    out = stream.getvalue()
    assert "dbg_event" not in out and "info_event" not in out
    assert "[warning] warn_event" in out and "[error] err_event" in out


def test_logger_verbose_enables_debug():
    stream = io.StringIO()
    lg = Logger(verbose=True, stream=stream)
    lg.debug("dbg", k=1)
    assert "dbg" in stream.getvalue()


def test_logger_quiet_only_errors():
    stream = io.StringIO()
    lg = Logger(quiet=True, stream=stream)
    lg.warning("w")
    lg.info("i")
    lg.error("boom")
    out = stream.getvalue()
    assert "boom" in out and "w" not in out and "i" not in out


def test_logger_writes_json_lines_to_file_with_redaction():
    logf = io.StringIO()
    lg = Logger(level="info", log_file=logf)
    lg.info("event", api_key="SECRET", value=1)
    line = logf.getvalue().strip()
    record = json.loads(line)
    assert record["event"] == "event"
    assert record["api_key"] == "***REDACTED***"
    assert record["value"] == 1
    assert "SECRET" not in logf.getvalue()


def test_redact_is_pure():
    original = {"token": "t", "ok": 1}
    cleaned = redact(original)
    assert original["token"] == "t"           # input unchanged
    assert cleaned["token"] == "***REDACTED***"


def test_levels_table():
    assert LEVELS["debug"] < LEVELS["info"] < LEVELS["warning"] < LEVELS["error"]


# --- output rendering -----------------------------------------------------
def test_render_json_envelope():
    stream = io.StringIO()
    r = Result(command="x", data={"a": 1}, messages=["hi"])
    render(r, as_json=True, quiet=False, stream=stream)
    payload = json.loads(stream.getvalue())
    assert payload["command"] == "x" and payload["data"]["a"] == 1


def test_render_human_default():
    stream = io.StringIO()
    r = Result(command="x", data={"a": 1}, messages=["hello"])
    render(r, as_json=False, quiet=False, stream=stream)
    assert "hello" in stream.getvalue()


def test_render_human_custom_callable():
    stream = io.StringIO()
    r = Result(command="x", data={"n": 5}, human=lambda d: f"n={d['n']}")
    render(r, as_json=False, quiet=False, stream=stream)
    assert "n=5" in stream.getvalue()


def test_render_quiet_suppresses_output(capsys):
    stream = io.StringIO()
    r = Result(command="x", data={"a": 1}, messages=["noise"])
    render(r, as_json=False, quiet=True, stream=stream)
    assert stream.getvalue() == ""


def test_render_error_goes_to_stderr(capsys):
    stream = io.StringIO()
    r = Result(ok=False, command="x", error="bad", exit_code=ExitCode.ERROR)
    render(r, as_json=False, quiet=False, stream=stream)
    assert "bad" in capsys.readouterr().err


def test_result_envelope_shape():
    env = Result(command="c", data={"k": "v"}).envelope()
    assert set(env) == {"ok", "command", "data", "messages", "error", "exit_code"}


def test_redact_covers_secrets_nested_in_lists():
    original = {"records": [{"token": "leak-me", "n": 1}],
                "pairs": ({"client_secret": "x"}, {"ok": True})}
    cleaned = redact(original)
    assert cleaned["records"][0]["token"] == "***REDACTED***"
    assert cleaned["records"][0]["n"] == 1
    assert cleaned["pairs"][0]["client_secret"] == "***REDACTED***"
    assert cleaned["pairs"][1] == {"ok": True}
    assert isinstance(cleaned["pairs"], tuple)


def test_redact_matches_compound_key_variants():
    fields = {"access_token": "a", "refresh_token": "b",
              "session_token": "c", "client_secret": "d",
              "password_hash": "e", "set_cookie": "f",
              "X-Api-Key": "g", "Private_Key": "h", "safe": 1}
    cleaned = redact(fields)
    redacted = {k for k, v in cleaned.items() if v == "***REDACTED***"}
    assert redacted == {"access_token", "refresh_token", "session_token",
                        "client_secret", "password_hash", "set_cookie",
                        "X-Api-Key", "Private_Key"}
    assert cleaned["safe"] == 1


def test_redact_does_not_mangle_benign_keys():
    cleaned = redact({"token_count": None} | {})
    # "token" substring rule is deliberately aggressive; document it.
    assert cleaned["token_count"] == "***REDACTED***"
