# Lockdown Mode Differential Campaign Plan (#228 §4)

Status: **prepared, awaiting user opt-in**. Enabling Lockdown Mode (LM) is a
user action — reversible, requires a reboot. Nothing in this plan enables it
programmatically; the framework only *reads* host state.

## Verified prerequisites (2026-08-25, this host)

| Check | Result |
|---|---|
| LM state readable | `sysctl security.mac.lockdown_mode_state` → `0` (disabled) |
| Paired-run tooling | `ios-research lockdown create/run/list/show` operational |
| Readiness probe | `ios-research lockdown state` → `paired_run_ready: true`, 61 mock targets constructible |

## Campaign design

**Question**: which parser behaviors change under LM's attack-surface
reduction (theme attachment sanitization, font stripping in Messages,
WebKit JIT/older-JavaScript exclusions), and do any *divergences* mark
hardening boundaries an attacker would otherwise cross?

**Method** (paired runs, same corpus, same seeds):

1. Standard leg: run the corpus against selected targets on this host
   (`lockdown create --target-standard X --target-lockdown X-lm ...`).
2. Enable LM via System Settings → Privacy & Security → Lockdown Mode;
   reboot; verify with `ios-research lockdown state` (`enabled: true`).
3. Run the lockdown leg with `--attest-lockdown-enabled` (researcher
   attestation recorded in the pair).
4. Reboot back to standard for analysis; classify divergences:
   - `candidate-finding`: accepted pre-LM, rejected/hardened post-LM
     (behavioral delta worth characterizing)
   - `hardening-delta`: outcome changed without a crash (documented, not a
     finding)
   - identical: corpus is LM-invariant (expected majority)

**Targets**: real-surface harnesses first (coregraphics PDF render path,
imageio full decode, audiotoolbox open→convert), then mock-tier for pipeline
validation only.

## Safety / honesty notes

- The engine is observations-only: no bypass tooling, no policy modification.
- Attestation is explicit and recorded per run; a run executed while LM was
  verifiably off (`lockdown state`) must not be labeled as a lockdown leg.
- Divergences are *differences*, not vulnerabilities, until characterized.
