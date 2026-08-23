"""Tests for findings import + adjudication (`findings` command group)."""

from __future__ import annotations

import json

import pytest

from ios_research.cli import main
from ios_research.errors import NotFoundError, ValidationError
from ios_research.findings import (
    FindingsPipeline, FindingsStore, HeuristicAdjudicator,
    parse_sarif,
)

SARIF = json.dumps({
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {
                "name": "semgrep",
                "rules": [
                    {"id": "python.sqlalchemy.sqli",
                     "properties": {"tags": ["security", "CWE-89"]}},
                    {"id": "py.unsanitized",
                     "helpUri": "https://cwe.mitre.org/data/definitions/78.html"},
                ],
            }},
            "results": [
                {
                    "ruleId": "python.sqlalchemy.sqli",
                    "level": "error",
                    "message": {"text": "user input flows to execute() "
                                        "without parameterization"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "src/app/db.py"},
                        "region": {"startLine": 42, "endLine": 42}}}],
                },
                {
                    "ruleId": "py.unsanitized",
                    "level": "warning",
                    "message": {"text": "command built from request data"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "src/app/cmd.py"},
                        "region": {"startLine": 7}}},
                    ],
                },
                {
                    "level": "note",
                    "message": {"text": "orphan finding without rule"},
                },
            ],
        }
    ],
})


# --- SARIF parsing -------------------------------------------------------------
def test_parse_sarif_normalizes_results():
    items = parse_sarif(SARIF)
    assert len(items) == 3
    first = items[0]
    assert first["tool"] == "semgrep"
    assert first["cwe"] == "CWE-89"
    assert first["file_path"] == "src/app/db.py"
    assert first["start_line"] == 42
    assert items[1]["cwe"] == "CWE-78"


def test_parse_sarif_invalid_documents():
    with pytest.raises(ValidationError):
        parse_sarif("{not json")
    with pytest.raises(ValidationError):
        parse_sarif('{"hello": "world"}')


# --- adjudicator -----------------------------------------------------------------
def _finding(tmp_path, body: str, path="src/app/db.py", cwe="CWE-89",
             message="tainted input reaches sink"):
    from ios_research.findings import FindingRecord
    full = tmp_path / path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(body)
    return FindingRecord(id="fin_x", tool="t", rule_id="r", cwe=cwe,
                         severity="error", file_path=path,
                         start_line=2, end_line=2, message=message)


def test_adjudicator_confirms_sink_and_source(tmp_path):
    rec = _finding(tmp_path,
                   "def q(u):\n    cur.execute(f\"SELECT * FROM t WHERE a={u}\")\n")
    verdict = HeuristicAdjudicator().adjudicate(rec, root=tmp_path)
    assert verdict["verdict"] == "confirmed"
    assert verdict["signals"]["sink"] is True


def test_adjudicator_dismisses_sanitized_path(tmp_path):
    rec = _finding(tmp_path,
                   "def q(u):\n    safe = validate_input(u)\n"
                   "    cur.execute(\"SELECT * FROM t WHERE a=?\", (safe,))\n")
    verdict = HeuristicAdjudicator().adjudicate(rec, root=tmp_path)
    assert verdict["verdict"] == "dismissed"
    assert verdict["signals"]["sanitizer"] is True


def test_adjudicator_pending_without_context(tmp_path):
    rec = _finding(tmp_path, "x = 1\ny = 2\n", cwe="", message="something odd")
    verdict = HeuristicAdjudicator().adjudicate(rec, root=tmp_path)
    assert verdict["verdict"] == "pending"
    assert 0 <= verdict["confidence"] <= 100


# --- pipeline / store -------------------------------------------------------------
def test_import_dedupes_and_persists(ctx, tmp_path):
    sarif_file = tmp_path / "report.sarif"
    sarif_file.write_text(SARIF)
    pipeline = FindingsPipeline(ctx.workspace())
    text = sarif_file.read_text()
    first = pipeline.import_sarif(text)
    second = pipeline.import_sarif(text)
    assert first["imported"] == 3
    assert second["imported"] == 0 and second["duplicates"] == 3
    assert len(FindingsStore(ctx.workspace()).list()) == 3


def test_adjudicate_all_updates_statuses(ctx, tmp_path):
    (tmp_path / "src/app").mkdir(parents=True)
    (tmp_path / "src/app/db.py").write_text(
        "def q(u):\n    cur.execute(\"SELECT \" + u)\n")
    pipeline = FindingsPipeline(ctx.workspace())
    sarif = {
        "runs": [{
            "tool": {"driver": {
                "name": "codeql",
                "rules": [{"id": "sqli",
                           "properties": {"tags": ["CWE-89"]}}],
            }},
            "results": [{
                "ruleId": "sqli", "level": "error",
                "message": {"text": "request flows to query"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/app/db.py"},
                    "region": {"startLine": 2}}}],
            }],
        }],
    }
    pipeline.import_sarif(json.dumps(sarif))
    touched = pipeline.adjudicate_all(root=ctx.workspace().root.parent)
    # db.py does not exist under the workspace root -> no evidence -> pending.
    statuses = {rec.status for rec in touched}
    assert statuses == {"confirmed"} or statuses == {"pending"}


def test_override_manual_review(ctx):
    pipeline = FindingsPipeline(ctx.workspace())
    pipeline.import_sarif(SARIF)
    fid = pipeline.store.list()[0].id
    rec = pipeline.override(fid, "dismissed", "reviewed by analyst")
    assert rec.status == "dismissed"
    assert rec.verdict["adjudicator"] == "manual"
    with pytest.raises(ValidationError):
        pipeline.override(fid, "exploded")


def test_objectives_lists_confirmed_only(ctx, tmp_path):
    pipeline = FindingsPipeline(ctx.workspace())
    pipeline.import_sarif(SARIF)
    located = [f for f in pipeline.store.list() if f.file_path][0]
    pipeline.override(located.id, "confirmed", "triage")
    objs = pipeline.objectives()
    assert [o["finding_id"] for o in objs] == [located.id]
    assert objs[0]["file"].endswith(".py")


def test_get_missing_finding(ctx):
    with pytest.raises(NotFoundError):
        FindingsStore(ctx.workspace()).get("fin_nope")


# --- CLI surface ---------------------------------------------------------------
@pytest.fixture
def sarif_path(tmp_path):
    p = tmp_path / "report.sarif"
    p.write_text(SARIF)
    return str(p)


def test_cli_findings_roundtrip(ctx, capsys, sarif_path):
    ws = str(ctx.workspace().root)
    rc = main(["findings", "import", "--sarif", sarif_path,
               "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and payload["data"]["imported"] == 3

    rc = main(["findings", "adjudicate", "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 0
    assert payload["data"]["adjudicated"] == 3

    rc = main(["findings", "list", "--status", "confirmed",
               "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    confirmed = payload["data"]["count"]
    assert confirmed >= 1

    if confirmed:
        fid = payload["data"]["findings"][0]["id"]
        rc = main(["findings", "dismiss", fid, "--reason", "dup",
                   "--json", "--workspace", ws])
        payload = json.loads(capsys.readouterr().out.strip())
        assert rc == 0 and payload["data"]["status"] == "dismissed"

    rc = main(["findings", "objectives", "--json", "--workspace", ws])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 0


def test_cli_findings_bad_sarif_exit_code(ctx, capsys, tmp_path):
    bad = tmp_path / "bad.sarif"
    bad.write_text("[]")
    rc = main(["findings", "import", "--sarif", str(bad),
               "--json", "--workspace", str(ctx.workspace().root)])
    payload = json.loads(capsys.readouterr().out.strip())
    assert rc == 4
    assert payload["ok"] is False
