# Per-key normalised probe: predeclared confirmatory live study

Written 2026-11-11, before any training of this study. The machine-readable freeze is
`artifacts/revision-probe-keynorm-confirm/protocol-before-guard.json` (written by `prepare`;
its sha256 goes in the results README).

## Question

Does the per-key normalised probe (`probek`), developed offline in
`../revision-probe-keynorm-dev/`, remove the honest exclusions that made the deployed probe
fail the guard, while still stopping the ordinary and the probe-aware pair DBA on **fresh**
partitions?

## Rule (frozen from development, not tuned here)

For each key k = (feature, value ∈ {3, 6, 12}): excess_k = shortcut_k − round peer median_k.
Scale s_k = max(clean maximum of excess_k in the cohort, 0.1). Quarantine when
max_k excess_k / s_k > 2. The scales are refitted by `calibrate` on the 12 verified clean
TPM-only histories of `revision-clean-gate-calibration-v1` (the data the development used)
and pinned (`calibration/key-scales.json`). Multiplier 2 and floor 0.1 come from development,
where they were chosen with those data visible. That is why this study exists.

## Design

* Data24, unchanged engine and training configuration; software trust assumption.
* Fresh partitions: guard 4 (2 IID, 2 Dirichlet α=0.3), evaluation 8 (4 + 4). Distinctness is
  checked against every surviving earlier study, including both probe live studies.
  3 attackers per evaluation partition, drawn from the seed.
* Attack plan in every case, clean included: pairs {3,18}, {8,15}, {11,22} at 6 std units,
  rounds 1–10, target benign.
* Variants:
  * `clean`
  * `pair-dba`
  * `evasive`: probe-aware negative augmentation, as in `../revision-trigger-probe-evasion-live/`
  * `adaptive`: interpolation-strength search against the complete defence
* Arms:
  * `tpm_only+fedavg`: reference
  * `tpm_only+bounded`: clipping
  * `probe+bounded`: deployed raw rule
  * `probek+bounded`: the rule under test

## Guard (clean, 16 cases, independently verified before the decision)

Each arm and guard assignment must meet all of these:
* honest quarantine ≤5%
* nominal mass ≥90%
* no honest client excluded in 2 consecutive rounds
* validation macro-F1 loss ≤2 points at rounds 10 and 15

An arm enters evaluation only if all four assignments qualify.
**If `probek+bounded` fails, K1–K4 are undefined and the rule is reported as not confirmed.**

## Hypotheses

Paired worst-trigger peak harm vs the arm's own clean history. The seed is the repetition unit.
A hypothesis holds if harm is strictly lower in a majority of the defined comparisons.

| Id | a vs b | Variants |
|---|---|---|
| K1 | probek+bounded vs tpm_only+bounded | pair-dba, evasive, adaptive |
| K2 | probek+bounded vs tpm_only+bounded | pair-dba, evasive |
| K3 | probek+bounded vs tpm_only+fedavg, effective controls only | pair-dba, evasive, adaptive |
| K4 (descriptive) | probek+bounded vs probe+bounded | pair-dba, evasive |

Secondary, descriptive:
* attacker client-rounds quarantined per arm and variant
* honest quarantine and longest consecutive honest exclusion in **attacked** runs of
  probek+bounded (target ≤5% and no run ≥2; not a hypothesis)
* effective controls per variant

If fewer than 4 of 8 evasive reference controls are effective, the evasive part is reported
as weak live.

## Procedure

1. `calibrate`
2. `prepare` (freeze)
3. smoke (not evidence)
4. guard
5. independent verification (`scripts/revision_probe_keynorm_audit.py guard`)
6. guard-decide
7. evaluation
8. independent verification
9. test (precommit, opened only after verification)
10. `scripts/report_arm_study.py`
11. README
12. archive the cases

Failures and deviations are reported as observed.
