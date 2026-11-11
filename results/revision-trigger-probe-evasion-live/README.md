# Behavioural trigger probe vs a probe-aware attacker: live study

Completed 2026-11-11. Predeclared protocol: `PROTOCOL.md` (committed `f8da54d` before any
training) and `artifacts/revision-trigger-probe-evasion-live/protocol-before-guard.json`
(sha256 `3dba50b9…`). Controller `scripts/revision_probe_evasion_study.py`, gate
`scripts/pair_probe_gate.py`, independent verifier `scripts/revision_probe_evasion_audit.py`
(recomputes both probes, decisions, executed attacker rows, masses, aggregates, model chain).
Data24, fresh partitions (4 guard, 8 evaluation), distinct from all surviving earlier studies.
Software trust assumption; no TPM Quotes.

**Outcome in one line: the predeclared hypotheses E1–E4 are undefined because both probe
arms failed the clean guard; the study does not show that the probe is robust to a
probe-aware attacker, nor that it is not.**

## Pair-probe calibration (clean only, before `prepare`)

Clean maximum of the peer-relative pair-probe score over 12 verified clean TPM-only
histories (`calibration/pair-thresholds.json`): **IID 0.9675, non-IID 1.0** (q98 0.90 / 0.96).
Honest clean models already show near-total pair shortcuts. With the declared zero-honest-flag
rule the pair probe is inert in non-IID (score ≤1) and fires only on extreme cases in IID.
Recorded before training. The rule was not changed.

## Guard (16 clean cases, independently verified)

| Arm | Qualified | Failure |
|---|---|---|
| tpm_only+fedavg | yes | — |
| tpm_only+bounded | yes | — |
| probe+bounded | **no** | non-IID s2027603001: one honest client excluded in 2 consecutive rounds (Q 0.9%, mass 99.4%) |
| probe2+bounded | **no** | the same, plus IID s2027600001: honest client excluded 5 consecutive rounds (Q 2.2%) |

All other criteria (Q ≤5%, mass ≥90%, F1 loss ≤2 pt) were met by every arm. In the previous
live study the same single-probe thresholds gave 0% honest quarantine. On these fresh
partitions they do not, so the probe's clean-maximum threshold does not generalise reliably
to new partitions.

## Evaluation (48 cases: reference + clipping only, as the protocol requires; all complete, verified, then tested)

Mean test full-trigger peak / final ASR (%), 4 assignments per cell:

| Cohort | Attack | TPM+FedAvg | TPM+clipping |
|---|---|---:|---:|
| IID | pair DBA | 17.4 / 0.0 | 14.6 / 0.0 |
| IID | evasive (probe-aware) | 3.2 / 0.0 | 1.5 / 0.0 |
| non-IID | pair DBA | 49.0 / 24.8 | 51.5 / 24.8 |
| non-IID | evasive (probe-aware) | 47.4 / 25.0 | 55.0 / 24.9 |

Worst trigger (complete or a single pair) peaks are higher in IID: pair DBA 34–50%, evasive
15–21%. Clean arms: 0% ASR, no benign cost.

### Predeclared hypotheses

| Hypothesis | lower / higher / equal / undefined | Result |
|---|---|---|
| E1 single probe+clipping vs clipping, evasive | 0/0/0/8 | **undefined** (arm not qualified) |
| E2 single+pair probe+clipping vs clipping, evasive | 0/0/0/8 | **undefined** |
| E3 single+pair probe+clipping vs FedAvg, effective controls | 0/0/0/10 | **undefined** |
| E4 positive control, pair DBA | 0/0/0/8 | **undefined** |

### Secondary endpoints (descriptive, declared)

* **Attacker cost of evasion.** IID: evasion lowers the reference worst-trigger harm from
  34–50 to 15–21 points, and 1 of 4 evasive controls is effective. Non-IID: there is no cost.
  Evasive harm is 100 / 51 / 38 / 0 points vs pair DBA 100 / 48 / 48 / 0. One evasive
  control (38 points) is not effective because of its F1 loss.
  **Effective evasive controls: 3 of 8 (< 4)** (IID 1, non-IID 2). Under the declared interpretation rule the
  evasive attack counts as weak live overall. That rule hides a cohort split: evasion is
  costly in IID and essentially free in non-IID.
* Clipping alone gives **no protection against pair attacks in non-IID** (peaks 48–55%,
  final ≈25%, one assignment at 100% to the end with a 38% attacker data share). This is
  the attack the probe layer would need to stop.
* Detection and honest quarantine in attacked runs are not available (probe arms were not run).

## Reading

* The blocking problem is **not** the evasive attacker but the **probe's stability on
  honest clients**. On fresh partitions a clean-max threshold still produces repeated
  exclusions of the same honest client. The previous confirmatory result (zero honest
  exclusions) did not replicate under the stricter consecutive-exclusion rule.
* The pair probe as designed (peer-relative, max over 600 keys) is not discriminative.
  Clean honest models reach scores ≈1, so a zero-honest-flag threshold disables it. The
  offline result (pair probe recovers the true pairs with 0/120 honest flags) relied on an
  in-sample threshold and does not survive a clean-only calibration.
* Offline the probe-aware attack cost the attacker most of its effect (0–15% ASR).
  Live this holds in IID only. In non-IID the evasive attack is as strong as the ordinary
  pair DBA.

## Limits and deviations

No deviations from the frozen protocol. One dataset (Data24, test split used in earlier
work); 8 evaluation assignments; one evasion strategy at one trigger value. Non-IID
s2027623001 (attacker share 8%) had no effect for any attack. Evidence: cases archived
per case (tar.gz) under `artifacts/revision-trigger-probe-evasion-live/`; summary data in
`summary.json`, `cases.csv`, `paired-harm.csv`.
