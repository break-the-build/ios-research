"""Lockdown Mode differential-testing profile (#60).

Apple doubles rewards for issues that bypass the specific protections of
Lockdown Mode. This module provides a **paired-run profile**: identical inputs
executed against an authorized target in two researcher-declared
configurations — standard vs. Lockdown Mode — with Lockdown-specific oracles
classifying the behavior transitions.

Oracles (observations only; never auto-labeled "bypass"):

* ``candidate-finding``     — the lockdown-side execution *crashes*: the attack
  surface appears reachable despite Lockdown protections.
* ``hardening-delta``       — the lockdown side rejects an input (or avoids a
  crash) that the standard side accepts. Hardening evidence, not a finding.
* ``inconclusive``          — a timeout on either side: tracked explicitly and
  never promoted to hardening or candidate evidence.

Provenance is explicit: both sides must declare build identifiers and a
researcher attestation that the lockdown configuration was actually enabled.
Hardware-gated: real-device pairing is opt-in; CI uses simulation fixtures
(any two registered targets standing in for the configurations). Reports keep
"behavior observed under LM" strictly separated from exploitability claims.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from . import targets
from .clock import now_iso
from .corpus import CorpusStore
from .errors import NotFoundError, ValidationError
from .hashing import sha256_bytes
from .ids import make_id
from .targets.base import Outcome
from .workspace import Workspace, validate_component

LOCKDOWN_SCHEMA_VERSION = 1

CANDIDATE = "candidate-finding"
HARDENING = "hardening-delta"
OK = "consistent"
INCONCLUSIVE = "inconclusive"

# Behavior categories for relation checks.
_CRASHY = {Outcome.CRASH, Outcome.ABNORMAL}


@dataclass
class LockdownPair:
    """A declared standard/Lockdown configuration pair."""

    id: str
    name: str
    target_standard: str
    target_lockdown: str
    corpus_id: str
    build_standard: str = ""
    build_lockdown: str = ""
    attested_lockdown_enabled: bool = False
    simulation: bool = True            # CI fixtures vs. real device pairing
    created_at: str = ""
    status: str = "created"
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _classify(out_std: str, out_lm: str,
              sig_std: str, sig_lm: str) -> tuple[str, str]:
    # A timeout on either side is inconclusive: a hang under Lockdown Mode is
    # not hardening evidence and must never become (or mask) a verdict.
    if out_std == Outcome.TIMEOUT or out_lm == Outcome.TIMEOUT:
        return INCONCLUSIVE, ("timeout observed on "
                              f"{'standard' if out_std == Outcome.TIMEOUT else 'lockdown'}"
                              " side; observation inconclusive")
    if out_lm in _CRASHY:
        reason = ("lockdown-side crash: surface appears reachable under "
                  "Lockdown Mode")
        return CANDIDATE, reason
    if out_std in _CRASHY and out_lm not in _CRASHY:
        return HARDENING, ("standard side crashes where the lockdown side "
                           "does not; consistent with hardening")
    if out_std == Outcome.ACCEPTED and out_lm == Outcome.REJECTED:
        return HARDENING, ("lockdown side rejects input the standard side "
                           "accepts")
    return OK, "behavior consistent across configurations"


class LockdownEngine:
    def __init__(self, workspace: Workspace):
        self.ws = workspace
        self.corpora = CorpusStore(workspace)

    def _rel(self, pair_id: str) -> str:
        return f"analysis/{pair_id}.json"

    def get(self, pair_id: str) -> LockdownPair:
        validate_component(pair_id, what="lockdown pair id")
        record = self.ws.read_json(self._rel(pair_id))
        if record.get("kind") != "lockdown-pair":
            raise ValidationError(f"'{pair_id}' is not a lockdown pair")
        return LockdownPair(**{k: v for k, v in record.items()
                               if k in LockdownPair.__dataclass_fields__
                               and k != "kind"})

    def list(self) -> list[LockdownPair]:
        out = []
        for record in self.ws.list_json("analysis"):
            if record.get("kind") == "lockdown-pair":
                out.append(LockdownPair(**{
                    k: v for k, v in record.items()
                    if k in LockdownPair.__dataclass_fields__
                    and k != "kind"}))
        return out

    def create(self, *, name: str, target_standard: str, target_lockdown: str,
               build_standard: str, build_lockdown: str,
               attested_lockdown_enabled: bool, simulation: bool = True,
               corpus_id: str | None = None) -> LockdownPair:
        for tid in (target_standard, target_lockdown):
            if not targets.is_registered(tid):
                raise NotFoundError(f"unknown target '{tid}'")
        if not str(build_standard).strip() or \
                not str(build_lockdown).strip():
            # Provenance is mandatory (#60): missing build provenance fails
            # validation rather than degrading.
            raise ValidationError(
                "both configurations require declared build identifiers")
        if corpus_id is None:
            corpus = self._default_corpus(target_standard)
            corpus_id = corpus.id
        else:
            self.corpora.get(corpus_id)

        pair_id = make_id("lmpair", name, target_standard, target_lockdown,
                          corpus_id, build_standard, build_lockdown)
        pair = LockdownPair(
            id=pair_id, name=name,
            target_standard=target_standard, target_lockdown=target_lockdown,
            corpus_id=corpus_id,
            build_standard=str(build_standard),
            build_lockdown=str(build_lockdown),
            attested_lockdown_enabled=bool(attested_lockdown_enabled),
            simulation=bool(simulation), created_at=now_iso())
        self.ws.write_json(self._rel(pair_id),
                           {"kind": "lockdown-pair", **pair.to_dict()})
        return pair

    def _default_corpus(self, target_id: str):
        name = f"lm-default-{target_id.replace(':', '-')}"
        for corpus in self.corpora.list():
            if corpus.name == name:
                return corpus
        corpus = self.corpora.create(name, target=target_id)
        target = targets.create(target_id)
        seeds = target.seeds() or [
            b"MOCK\x01\x01\x00\x02ok", b"MOCK\x01\xff\x00\x00",
            b"MOCK\x02\x01\x00\x02payload", b"MOCK\x01\x01\xff\xffshort"]
        for data in seeds:
            self.corpora.add_bytes(corpus, data, origin="seed")
        return corpus

    def run(self, pair: LockdownPair) -> dict[str, Any]:
        if not pair.attested_lockdown_enabled:
            raise ValidationError(
                "researcher must attest the lockdown configuration was "
                "enabled ('--attest-lockdown-enabled'); refusing to run an "
                "unattested pair")
        corpus = self.corpora.get(pair.corpus_id)
        std = targets.create(pair.target_standard)
        lm = targets.create(pair.target_lockdown)

        results: list[dict[str, Any]] = []
        counts = {CANDIDATE: 0, HARDENING: 0, OK: 0, INCONCLUSIVE: 0}
        for tc in corpus.testcases:
            data = self.corpora.read_bytes(corpus, tc["sha256"])
            r_std = std.execute(data)
            r_lm = lm.execute(data)
            sig_std = r_std.diagnostics.signature if r_std.diagnostics else ""
            sig_lm = r_lm.diagnostics.signature if r_lm.diagnostics else ""
            verdict, reason = _classify(r_std.outcome, r_lm.outcome,
                                        sig_std, sig_lm)
            counts[verdict] += 1
            results.append({
                "input_sha256": tc["sha256"],
                "standard": {"outcome": r_std.outcome, "signature": sig_std},
                "lockdown": {"outcome": r_lm.outcome, "signature": sig_lm},
                "verdict": verdict,
                "reason": reason,
                "observation_only": verdict in (CANDIDATE, HARDENING),
            })

        summary = {
            "schema_version": LOCKDOWN_SCHEMA_VERSION,
            "inputs_checked": len(results),
            "counts": counts,
            "results": sorted(results,
                              key=lambda r: (r["verdict"], r["input_sha256"])),
            "provenance": {
                "build_standard": pair.build_standard,
                "build_lockdown": pair.build_lockdown,
                "attested_lockdown_enabled": pair.attested_lockdown_enabled,
                "simulation": pair.simulation,
            },
            "note": ("verdicts are observations of paired-run behavior only; "
                     "a candidate finding requires researcher confirmation "
                     "and carries no exploitability claim"),
        }
        pair.status = "run"
        pair.summary = {"inputs_checked": summary["inputs_checked"],
                        "candidates": counts[CANDIDATE]}
        self.ws.write_json(self._rel(pair.id),
                           {"kind": "lockdown-pair", **pair.to_dict()})
        self.ws.write_json(f"analysis/{pair.id}-results.json", {
            "id": f"{pair.id}-results", "kind": "lockdown-results",
            "created_at": now_iso(), "pair_id": pair.id, **summary})
        return summary
