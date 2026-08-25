"""Corpus manifests stay equivalent while using compact engine-owned JSON."""

from __future__ import annotations

from ios_research.corpus import CorpusStore


def test_corpus_manifest_is_compact_and_round_trips(workspace):
    store = CorpusStore(workspace)
    corpus = store.create("compact", target="mock:parser")
    store.add_bytes(corpus, b"seed", origin="seed")
    raw = workspace.path(f"corpus/{corpus.id}/corpus.json").read_text()
    assert "\n  \"" not in raw
    loaded = store.get(corpus.id)
    assert loaded.to_dict() == corpus.to_dict()
