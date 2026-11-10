# Head-aware CUSUM admission gate: predeclared live study

Prepared 2026-11-10. Protocol and clean thresholds are frozen; **no guard or
evaluation training has run yet.** Deployed policies, thresholds and thesis are
unchanged. This is a software research study: prerequisite trust is assumed
passed and no new TPM Quotes are produced.

## Why

The original Sequential and Gated Composite gates share one averaged statistical
score and exclude the same clients on every recorded input
([gate audit](../results/revision-gate-mechanism-audit-v1/README.md)). Two offline
studies on retained trajectories located the bottleneck:

1. [Non-compensatory replay](../results/revision-noncompensatory-replay-v1/README.md):
   better combination rules help, but the five deployed indicators cap AUC at
   about 0.82–0.85.
2. [Tensor indicators](../results/revision-tensor-indicators-v1/README.md): geometry
   of the **classification head** separates adaptive attackers far better
   (holdout AUC 0.93–0.94). A non-compensatory max with per-client CUSUM caught
   90/120 holdout attackers vs 2/120 for the deployed rule at 2% clean FPR.

Both are fixed-trajectory replays against an attacker that did not know these
indicators. This study tests the candidate with independent live trajectories and
defender-aware attacks.

## Candidate (frozen in `scripts/head_cusum_gate.py`)

- Round-relative indicators of each delta (local minus base model): relative norm,
  cosine to the coordinate median, mean distance to 3 nearest peers, and relative
  norm / cosine restricted to `classification_head.*`.
- Adverse robust z against cohort-specific (IID / non-IID) clean references;
  round score = **maximum** adverse z (non-compensatory, uncapped).
- `head_max`: quarantine when the score exceeds the clean 98th percentile.
- `head_cusum`: per-client `S_t = max(0, S_{t-1} + score - k)`; `k` = clean 90th
  percentile of scores (chosen on offline development seeds only); quarantine when
  `S_t` exceeds the clean 98th percentile of `S`. The statistic keeps updating
  while quarantined, so there is no permanent exclusion state.
- Mandatory trust failure remains a hard veto.

## Fitted clean thresholds

From reused, verified, clean TPM-only histories of
`revision-clean-gate-calibration-v1` (no attack data, no new training):
references from the 4 `fit` histories (900 observations), `k` and thresholds from
the 8 `calibration` + `selection` histories (1,800 observations).

| Cohort | k | head_max threshold | head_cusum threshold |
|---|---:|---:|---:|
| IID | 2.836 | 4.157 | 3.671 |
| non-IID | 4.521 | 6.269 | 11.067 |

Pins: protocol `914735d73114276b39f47f01d3c68b04d683b7e9f6aee5b1f43eed94d167f284`,
model `950d5c3117eab7fee126b604829f0d18408ad8894c37b5e92d19dee227f443ce`,
`head_cusum_gate.py` `463f257f…`, controller `3fbda88c…` (full source locks in the protocol).

## Stages

| Stage | Cases | Content |
|---|---:|---|
| guard | 12 | 4 fresh clean assignments (2 IID, 2 non-IID) × {TPM-only, head_max, head_cusum} |
| evaluation | up to 120 | 6 fresh reserved assignments (3 IID, 3 Dirichlet α=0.3) × {TPM-only, gated_composite, head_max, head_cusum} × {clean, distributed, complete-trigger, adaptive, adaptive-headfrozen} |

- **Guard rule (clean only):** a candidate enters evaluation only if, on every
  guard assignment, its own clean history completes 15 rounds, quarantine ≤5%,
  pooled nominal mass ≥90%, every round ≥80%, and validation macro-F1 loss vs
  paired TPM-only ≤2 points at rounds 10 and 15. No retuning after the guard.
- **Attacks:** 15 rounds, attack in rounds 1–10, 50% poisoning at three clients,
  same triggers and six-alpha query budget as the earlier gate studies. The
  adaptive attacker optimizes against each evaluated defender, including the
  current CUSUM state. `adaptive-headfrozen` keeps the attacker's classification
  head equal to its own clean endpoint: a defender-aware evasion of the head
  indicators, run for every arm.
- Seeds 2026111011–14 (guard) and 2026111021–26 (evaluation) are disjoint from
  every earlier gate study; same Data24 rows and warm start.

## Hypotheses and promotion

- **H1** head_cusum has lower paired worst-trigger peak harm than gated_composite
  in a majority of defined attacked comparisons, within clean budgets.
- **H2** head_cusum reduces paired peak harm vs TPM-only in effective TPM-only
  controls (≥20 point ASR increase, ≤5 point clean F1 loss).
- **H3** (robustness) report whether any benefit remains under
  adaptive-headfrozen. A loss of benefit is a limitation, not a reason to retune.

No automatic promotion. Reportable as improved only if the guard passes, H1 and
H2 hold, no new quorum failure on reserved clean assignments and ≤2 point paired
test F1 loss at rounds 10/15. Failures are undefined, never ASR 0. The seed is the
repetition unit; one dataset; the test split was inspected in earlier work.

## Commands

```bash
.venv/bin/python scripts/revision_head_cusum_study.py guard --workers 3
.venv/bin/python scripts/revision_head_cusum_study.py guard-decide
.venv/bin/python scripts/revision_head_cusum_study.py evaluation --workers 3
```

A 2-round dry run of every adapter path (`prepare`, `fit` and `smoke` with
`--lab <scratch>`) passed. It checked the CUSUM state chain, the defender-aware
adaptive search, the frozen-head invariant and the original composite arm.

## Still to build before opening the test split

An independent verifier (recompute head features, CUSUM chain, decisions and
FedAvg from saved updates), the test-phase evaluator and the report generator.
They must be committed before any test inference. Estimated cost: about 2 hours
wall-clock with 3 workers and about 10 GB of evidence, based on dry-run timing
and the earlier 72-case study (5.2 GB).
