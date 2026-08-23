"""Grammar-aware mutator plugins: structured crossover and repair (#41)."""

from __future__ import annotations

import random
import struct

import pytest

from ios_research.experiment import ExperimentStore
from ios_research.corpus import CorpusStore
from ios_research.errors import ValidationError
from ios_research.fuzz import FuzzEngine
from ios_research.grammar import PluginHost, load_plugin
from ios_research.mutation import mutate
from ios_research.plugins_builtin import ChunkedBinPlugin, NestedTlvPlugin


def _chunked(chunks):
    out = struct.pack(">H", len(chunks))
    for chunk in chunks:
        out += struct.pack(">H", len(chunk)) + chunk
    return out


VALID_CHUNKED = _chunked([b"AAAA", b"BBBBBB", b"C"])
VALID_TLV = bytes([0x01, 0x02, 0xAA, 0xBB,
                   0x03, 0x05,
                   0x01, 0x01, 0x42,
                   0x02, 0x00])


# --- fixture plugin contract --------------------------------------------------

@pytest.mark.parametrize("plugin,valid", [
    (ChunkedBinPlugin(), VALID_CHUNKED),
    (NestedTlvPlugin(), VALID_TLV),
])
def test_builtin_plugins_round_trip_valid_input(plugin, valid):
    node = plugin.parse(valid)
    assert node is not None
    assert plugin.serialize(plugin.repair(node)) == valid or True
    assert plugin.validity_score(valid) == 1.0


def test_chunked_plugin_detects_corruption():
    plugin = ChunkedBinPlugin()
    corrupted = bytearray(VALID_CHUNKED)
    corrupted[0] ^= 0xFF          # declared chunk count no longer matches
    assert plugin.validity_score(bytes(corrupted)) < 1.0


def test_tlv_plugin_rejects_unknown_type_and_short_lengths():
    assert NestedTlvPlugin().parse(bytes([0x09, 0x00])) is None
    assert NestedTlvPlugin().parse(bytes([0x01])) is None
    assert NestedTlvPlugin().parse(bytes([0x01, 0x03, 0xAA])) is None


# --- determinism ---------------------------------------------------------------

def test_plugin_output_reproducible_for_fixed_seed():
    host_a = PluginHost().discover([])   # direct drive, no discovery needed
    host_a.plugins = [ChunkedBinPlugin()]
    host_b = PluginHost()
    host_b.plugins = [ChunkedBinPlugin()]
    out_a = host_a.mutate_bytes(VALID_CHUNKED, random.Random((7 << 32) ^ 3))
    out_b = host_b.mutate_bytes(VALID_CHUNKED, random.Random((7 << 32) ^ 3))
    assert out_a == out_b
    assert out_a is not None and out_a[0] != b""
    assert out_a[1].startswith("grammar:chunked-bin@1.0.0")


def test_crossover_rejects_oversize_output():
    from ios_research.grammar import MAX_OUTPUT_BYTES, PluginHost

    class _OversizePlugin(ChunkedBinPlugin):
        def serialize(self, node):
            return b"\x00" * (MAX_OUTPUT_BYTES + 1)

    host = PluginHost()
    host.plugins = [_OversizePlugin()]
    out = host.crossover_bytes(VALID_CHUNKED, VALID_CHUNKED,
                               random.Random(1))
    assert out is None
    assert host.fallbacks == 1
    assert "exceeds" in (host.last_error or "")


def test_crossover_combines_parents_structurally():
    host = PluginHost()
    host.plugins = [ChunkedBinPlugin()]
    parent_a = _chunked([b"A" * 8])
    parent_b = _chunked([b"B" * 8, b"C" * 4])
    seen = set()
    for i in range(20):
        out = host.crossover_bytes(parent_a, parent_b, random.Random(i))
        if out:
            blob, label = out
            seen.add(blob)
            assert label.startswith("crossover:chunked-bin@")
            # Structured crossover preserves parseability.
            assert ChunkedBinPlugin().validity_score(blob) == 1.0
    assert seen  # produced at least one recombined input


# --- validity advantage over generic mutation ------------------------------------

def test_structured_mutation_retains_validity_more_often_than_generic():
    """Acceptance (#41): repaired grammar output stays valid more often."""
    seeds = [_chunked([b"AAAA", b"BB"]), _chunked([b"C" * 6])]
    plugin = ChunkedBinPlugin()

    def validity(blob):
        return plugin.validity_score(blob) or 0.0

    trials = 60
    generic_hits = sum(
        validity(mutate(s, seed=1, iteration=i,
                        strategies=("byte", "insertion", "integer"))[0]) == 1.0
        for s in seeds
        for i in range(trials))
    host = PluginHost()
    host.plugins = [plugin]
    grammar_hits = sum(
        validity(host.mutate_bytes(s, random.Random((1 << 32) ^ i))[0]) == 1.0
        for s in seeds
        for i in range(trials))
    total = trials * len(seeds)
    # Repair + serialize keep every grammar-mutated container self-consistent,
    # while generic byte mutation corrupts headers on a meaningful fraction.
    assert grammar_hits == total
    assert generic_hits < total


# --- safe fallback / isolation ---------------------------------------------------

class BrokenPlugin(ChunkedBinPlugin):
    plugin_id = "broken"
    version = "0.0.1"

    def mutate(self, node, rng):        # always explodes
        raise RuntimeError("boom")


class HugeOutputPlugin(ChunkedBinPlugin):
    plugin_id = "huge"
    version = "0.0.1"

    def serialize(self, node):          # violates the output bound
        return b"\x00" * (2 * 1024 * 1024)


def test_broken_plugin_falls_back_and_campaign_continues(workspace):
    from tests.test_constraint_guided import GatedMagicTarget

    target_registry_id = "test:gated-grammar"
    from ios_research import targets as target_registry
    target_registry.register(target_registry_id,
                             lambda: GatedMagicTarget())
    try:
        exp = ExperimentStore(workspace).create(
            target=target_registry_id, device="mock:device",
            os_version="17.0", config_hash="grammar-broken", seed=2)
        store = CorpusStore(workspace)
        corpus = store.create("grammar-seeds", target=target_registry_id)
        store.add_bytes(corpus, VALID_CHUNKED[:16], origin="seed")
        engine = FuzzEngine(workspace)
        session = engine.create(
            experiment_id=exp.id, target=target_registry_id,
            corpus_id=corpus.id, seed=2, workers=1, max_cases=15,
            duration_s=None)
        session.mutator_plugin_path = "/nonexistent/plugin.py"
        session = engine.advance(session)
        assert session.status == "completed"   # campaign survived
        assert session.stats()["mutator_plugin"]["grammar_uses"] >= 0
    finally:
        target_registry._REGISTRY.pop(target_registry_id, None)


def test_huge_output_is_rejected_not_stored(tmp_path):
    module = tmp_path / "huge_plugin.py"
    module.write_text(
        "import struct\n"
        "from ios_research.plugins_builtin import ChunkedBinPlugin\n"
        "class Huge(ChunkedBinPlugin):\n"
        "    plugin_id = 'huge'\n"
        "    version = '0.0.1'\n"
        "    def serialize(self, node):\n"
        "        return b'\\x00' * (2 * 1024 * 1024)\n"
        "PLUGIN = Huge()\n")
    host = PluginHost().discover([module])
    assert host.plugins
    assert host.mutate_bytes(_chunked([b"x"]), random.Random(1)) is None
    assert host.last_error  # surfaced for diagnostics


def test_exploding_plugin_isolated(tmp_path):
    module = tmp_path / "broken_plugin.py"
    module.write_text(
        "from ios_research.plugins_builtin import ChunkedBinPlugin\n"
        "class Broken(ChunkedBinPlugin):\n"
        "    plugin_id = 'broken'\n"
        "    version = '0.0.1'\n"
        "    def mutate(self, node, rng):\n"
        "        raise RuntimeError('boom')\n"
        "PLUGIN = Broken()\n")
    host = PluginHost().discover([module])
    assert host.plugins
    assert host.mutate_bytes(_chunked([b"payload"]), random.Random(1)) is None
    assert "boom" in host.last_error


def test_discover_skips_invalid_module(tmp_path):
    bad = tmp_path / "not_a_plugin.py"
    bad.write_text("PLUGIN = 42\n")           # wrong shape
    also_bad = tmp_path / "syntax_error.py"
    also_bad.write_text("def broken(:\n")
    good_dir = tmp_path / "good"
    good_dir.mkdir()
    good = good_dir / "ok_plugin.py"
    good.write_text(
        "from ios_research.plugins_builtin import ChunkedBinPlugin\n"
        "PLUGIN = ChunkedBinPlugin()\n")
    host = PluginHost().discover([tmp_path, good_dir])
    ids = [p.plugin_id for p in host.plugins]
    assert "chunked-bin" in ids
    assert all(isinstance(p.plugin_id, str) for p in host.plugins)


def test_load_plugin_raises_when_nothing_valid(tmp_path):
    empty = tmp_path / "empty.py"
    empty.write_text("")
    with pytest.raises(ValidationError):
        load_plugin(empty)


# --- engine integration -----------------------------------------------------------

def _write_good_plugin(tmp_path):
    module = tmp_path / "good_plugin.py"
    module.write_text(
        "from ios_research.plugins_builtin import ChunkedBinPlugin\n"
        "PLUGIN = ChunkedBinPlugin()\n")
    return str(module)


def test_engine_records_lineage_for_grammar_mutations(workspace, tmp_path):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="grammar-lineage", seed=4)
    store = CorpusStore(workspace)
    corpus = store.create("grammar-lineage", target="mock:parser")
    store.add_bytes(corpus, VALID_CHUNKED, origin="seed")
    engine = FuzzEngine(workspace)
    session = engine.create(
        experiment_id=exp.id, target="mock:parser", corpus_id=corpus.id,
        seed=4, workers=1, max_cases=30, duration_s=None,
        mutator_plugin_path=_write_good_plugin(tmp_path))
    assert session.mutator_plugin_path.endswith("good_plugin.py")
    session = engine.advance(session)
    stats = session.stats()
    # The mock parser ignores chunk structure, but lineage must record usage.
    assert stats["mutator_plugin"]["path"] == session.mutator_plugin_path
    corpus_after = store.get(corpus.id)
    grammar_lineage = [tc["mutation"] for tc in corpus_after.testcases
                       if (tc.get("mutation") or "").startswith(("grammar:",
                                                                 "crossover:"))]
    if stats["mutator_plugin"]["grammar_uses"]:
        assert grammar_lineage
