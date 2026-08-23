"""Constraint-guided mutation: dictionaries, token provenance, value profiles.

Issue #30. The core acceptance criterion is exercised end to end:
a gated parser state that unguided mutation does not reliably reach within a
bounded budget IS reached when dictionary guidance is enabled.
"""

from __future__ import annotations

import pytest

from ios_research import mutation, targets as target_registry
from ios_research.dictionary import (
    DictionaryToken, discover_tokens, load_dictionary, parse_dictionary,
    tokens_from_records, tokens_to_records)
from ios_research.errors import ValidationError
from ios_research.experiment import ExperimentStore
from ios_research.corpus import CorpusStore
from ios_research.fuzz import FuzzEngine
from ios_research.targets.base import ExecResult, Outcome, Target


# --- parsing / validation ----------------------------------------------------

DICT_TEXT = """\
# comment line
// also a comment
png_magic="\\x89PNG\\r\\n\\x1a\\n"
jpeg_soi="\\xff\\xd8"
plain="MOBC"
"""


def test_parse_dictionary_tokens_and_escapes():
    tokens = parse_dictionary(DICT_TEXT)
    by_name = {t.name: t for t in tokens}
    assert by_name["png_magic"].value == b"\x89PNG\r\n\x1a\n"
    assert by_name["jpeg_soi"].value == b"\xff\xd8"
    assert by_name["plain"].value == b"MOBC"


def test_parse_dictionary_is_deterministic():
    assert [t.value for t in parse_dictionary(DICT_TEXT)] == \
        [t.value for t in parse_dictionary(DICT_TEXT)]


def test_parse_dictionary_rejects_malformed():
    for bad in ('no_quotes=abc', 'unterminated="abc', 'dup="a"\ndup="b"',
                'empty=""', 'bad_escape="\\q"'):
        with pytest.raises(ValidationError):
            parse_dictionary(bad)


def test_parse_dictionary_allows_multiple_unnamed_tokens():
    tokens = parse_dictionary('"AAA"\n"BBBB"')
    assert [t.value for t in tokens] == [b"AAA", b"BBBB"]
    assert all(t.name == "" for t in tokens)


def test_parse_dictionary_enforces_bounds():
    with pytest.raises(ValidationError):
        parse_dictionary('big="%s"' % ("A" * 129))
    many = "\n".join('t%d="%s"' % (i, "A" * 4) for i in range(5000))
    with pytest.raises(ValidationError):
        parse_dictionary(many)


def test_load_dictionary_missing_file(tmp_path):
    with pytest.raises(ValidationError):
        load_dictionary(tmp_path / "missing.dict")


# --- discovery ---------------------------------------------------------------

def test_discover_tokens_finds_common_magic_with_provenance():
    seeds = [b"\x89PNG\r\n\x1a\nIHDRxxxx", b"\x89PNG\r\n\x1a\nIDATyyyy",
             b"RIFF\x00\x00WAVEfmt "]
    tokens = discover_tokens(seeds, source_name="corpus-xyz", limit=10)
    values = [t.value for t in tokens]
    assert b"\x89PNG" in values and b"RIFF" in values and b"WAVEfmt" in values
    assert all(t.origin == "discovery:corpus-xyz" for t in tokens)
    # Deterministic order: frequency desc, then value asc.
    again = discover_tokens(seeds, source_name="corpus-xyz", limit=10)
    assert [t.value for t in tokens] == [t.value for t in again]


# --- deterministic guided mutation -------------------------------------------

TOKENS = [DictionaryToken(name="magic", value=b"SEKRIT")]


def test_dict_mutations_are_deterministic_and_apply_token():
    a = mutation.mutate(b"AAAABBBB", 7, 3, strategies=("dict_insert",),
                        tokens=TOKENS)
    b = mutation.mutate(b"AAAABBBB", 7, 3, strategies=("dict_insert",),
                        tokens=TOKENS)
    assert a == b
    mutated, strategy = a
    assert strategy == "dict_insert"
    assert b"SEKRIT" in mutated


def test_dict_overwrite_preserves_length():
    mutated, strategy = mutation.mutate(
        b"AAAABBBBCCCC", 11, 1, strategies=("dict_overwrite",), tokens=TOKENS)
    assert strategy == "dict_overwrite"
    assert len(mutated) == 12 and b"SEKRIT" in mutated


def test_dict_strategy_without_tokens_falls_back_to_byte():
    mutated, strategy = mutation.mutate(
        b"AAAABBBB", 5, 5, strategies=("dict_insert",), tokens=None)
    assert strategy == "byte"


# --- engine integration ------------------------------------------------------

GATED_MAGIC = b"SEKRIT"


class GatedMagicTarget(Target):
    """Parser with a magic-gated deep state, exposed via coverage features.

    Unguided byte/insertion mutation essentially never synthesizes the six-byte
    magic; dictionary guidance reaches it quickly.
    """

    target_id = "test:gated"
    kind = "mock-parser"
    description = "gated magic-value parser for guidance tests"

    def _run(self, data: bytes) -> ExecResult:
        if GATED_MAGIC in data:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail="gated state reached")
        return ExecResult(outcome=Outcome.ACCEPTED)

    def coverage_features(self, data: bytes, result: ExecResult):
        features = ["gate:entry"]
        if GATED_MAGIC in data:
            features.append("gate:secret")
        return tuple(sorted(features))


@pytest.fixture()
def gated_target():
    target_registry.register("test:gated", lambda: GatedMagicTarget())
    yield "test:gated"
    target_registry._REGISTRY.pop("test:gated", None)


def _seeded_corpus(workspace, target_id):
    store = CorpusStore(workspace)
    corpus = store.create("gated-seeds", target=target_id)
    store.add_bytes(corpus, b"AAAAAAAABBBBBBBB", origin="seed")
    return corpus.id


GUIDE_BUDGET = 400


def test_dictionary_guidance_reaches_gated_state(workspace, gated_target):
    """Acceptance (#30): guided traversal within a bounded budget."""
    exp = ExperimentStore(workspace).create(
        target=gated_target, device="mock:device", os_version="17.0",
        config_hash="guided", seed=9)
    corpus_id = _seeded_corpus(workspace, gated_target)
    engine = FuzzEngine(workspace)
    session = engine.create(
        experiment_id=exp.id, target=gated_target, corpus_id=corpus_id,
        seed=9, workers=1, max_cases=GUIDE_BUDGET, duration_s=None,
        dictionary_tokens=[DictionaryToken(name="gate", value=GATED_MAGIC,
                                           source="unit-test")])
    session = engine.advance(session)

    stats = session.stats()
    assert "gate:secret" in stats["coverage"]["features"], stats["coverage"]
    assert stats["guidance"]["token_uses"] > 0
    assert stats["guidance"]["dictionary_source"] == "unit-test"
    # The retained input carries lineage back to the dictionary usage.
    corpus = CorpusStore(workspace).get(corpus_id)
    secret_inputs = [tc for tc in corpus.testcases
                     if tc.get("coverage_new_features")]
    assert secret_inputs


def test_unguided_mutation_misses_gated_state_same_budget(workspace, gated_target):
    """Control: same seed/budget without the dictionary does not reach it."""
    exp = ExperimentStore(workspace).create(
        target=gated_target, device="mock:device", os_version="17.0",
        config_hash="unguided", seed=9)
    corpus_id = _seeded_corpus(workspace, gated_target)
    engine = FuzzEngine(workspace)
    session = engine.create(
        experiment_id=exp.id, target=gated_target, corpus_id=corpus_id,
        seed=9, workers=1, max_cases=GUIDE_BUDGET, duration_s=None)
    session = engine.advance(session)
    assert "gate:secret" not in session.stats()["coverage"]["features"]
    assert session.stats()["guidance"]["token_uses"] == 0


def test_session_persists_dictionary_for_deterministic_resume(
        workspace, gated_target, tmp_path):
    dict_file = tmp_path / "gate.dict"
    dict_file.write_text('gate="SEKRIT"\n')
    exp = ExperimentStore(workspace).create(
        target=gated_target, device="mock:device", os_version="17.0",
        config_hash="resume", seed=3)
    corpus_id = _seeded_corpus(workspace, gated_target)
    engine = FuzzEngine(workspace)
    session = engine.create(
        experiment_id=exp.id, target=gated_target, corpus_id=corpus_id,
        seed=3, workers=1, max_cases=50, duration_s=None,
        dictionary_path=str(dict_file))
    assert session.dictionary_source == str(dict_file)

    loaded = engine.tokens_for(session)
    assert loaded is not None and len(loaded) == 1
    assert loaded[0].value == GATED_MAGIC

    chunk = engine.advance(session, max_new=10)
    assert chunk.status == "paused"
    resumed = engine.resume(engine.get(session.id))
    assert resumed.token_uses > 0 or resumed.cursor == 50


def test_create_rejects_conflicting_dictionary_sources(workspace, gated_target):
    exp = ExperimentStore(workspace).create(
        target=gated_target, device="mock:device", os_version="17.0",
        config_hash="conflict", seed=1)
    corpus_id = _seeded_corpus(workspace, gated_target)
    engine = FuzzEngine(workspace)
    with pytest.raises(Exception):
        engine.create(
            experiment_id=exp.id, target=gated_target, corpus_id=corpus_id,
            seed=1, workers=1, max_cases=10, duration_s=None,
            dictionary_path="/nonexistent.dict",
            dictionary_tokens=[DictionaryToken(name="x", value=b"x")])


# --- persisted-token round trip ----------------------------------------------

def test_token_record_round_trip():
    tokens = [DictionaryToken(name="a", value=b"\x00\x01SEKRIT",
                              origin="discovery:seeds", source="s")]
    rebuilt = tokens_from_records(tokens_to_records(tokens))
    assert [(t.name, t.value, t.origin) for t in rebuilt] == \
        [("a", b"\x00\x01SEKRIT", "discovery:seeds")]


# --- native libFuzzer value profile -----------------------------------------

def test_libfuzzer_command_includes_value_profile_flag():
    from ios_research.targets.mac import MacFuzzTarget
    base = MacFuzzTarget.build_libfuzzer_command(
        __import__("pathlib").Path("/h"), "/corpus", "/art", runs=100,
        workers=2)
    assert "-use_value_profile=1" not in base
    guided = MacFuzzTarget.build_libfuzzer_command(
        __import__("pathlib").Path("/h"), "/corpus", "/art", runs=100,
        workers=2, value_profile=True)
    assert "-use_value_profile=1" in guided
