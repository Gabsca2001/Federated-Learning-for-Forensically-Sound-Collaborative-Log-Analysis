# Probe-aware attacker vs behavioural trigger probe: predeclared protocol

Written 2026-11-11, before any training of this study. The machine-readable freeze is
`artifacts/revision-trigger-probe-evasion-live/protocol-before-guard.json` (written by
`prepare`, sha256 recorded in the results README); this file states the same design.

## Question

Does the behavioural trigger probe (+ per-tensor clipping), which removed DBA in the
previous live study (`../revision-trigger-probe-live/`), survive an attacker that knows
the probe and hides single-feature shortcuts? Does a pair probe close the gap?

## Design

* Data24, engine and training configuration unchanged (`scripts/revision_probe_study.py`
  wrapped by `scripts/revision_probe_evasion_study.py`); software trust assumption.
* Fresh partitions: guard 4 (2 IID, 2 Dirichlet α=0.3), evaluation 8 (4 + 4); distinctness
  checked against this study and every surviving earlier gate study, including the
  previous probe live study. Attackers: 3 per evaluation partition, drawn from the seed.
* Attack plan (identical in every case, clean included, so paired harm measures the same
  trigger): AND-trigger pairs {3,18}, {8,15}, {11,22} at 6 standard units, rounds 1–10,
  target `benign`. Worst trigger = max(complete six-feature trigger, each pair).
* Variants: `clean`; `pair-dba` (ordinary DBA on the pairs, core `poison_local_rows`);
  `evasive` (probe-aware: per attack round 50% of rows get the pair and label benign,
  25% only the first feature, 25% only the second, original labels kept).
  Value 6 chosen from the offline prototype (value 12 gave 0% ASR); no live tuning.
* Arms: `tpm_only+fedavg` (reference), `tpm_only+bounded` (clipping), `probe+bounded`
  (unchanged single-feature probe, unchanged clean-max thresholds), `probe2+bounded`
  (single OR pair probe; 300 pairs × {6, 12} on 400 fixed validation attack rows,
  peer-relative score).
* Pair-probe thresholds: clean maximum per cohort over the 12 verified clean TPM-only
  histories of `revision-clean-gate-calibration-v1`, computed by `calibrate` **before**
  `prepare` and pinned (`calibration/pair-thresholds.json`). No study partition is used.

## Guard (clean, 16 cases; rule declared now)

Per arm and guard assignment: honest quarantine ≤5%, nominal mass ≥90%, no honest client
excluded in 2 consecutive rounds, validation macro-F1 loss vs reference ≤2 points at
rounds 10 and 15. An arm enters evaluation only if every guard assignment qualifies.
The guard is independently verified before the decision.

## Hypotheses (paired worst-trigger peak harm vs the arm's own clean history; seed = unit;
holds = strictly lower in a majority of defined comparisons)

| Id | a vs b | Variants |
|---|---|---|
| E1 | probe+bounded vs tpm_only+bounded | evasive |
| E2 | probe2+bounded vs tpm_only+bounded | evasive |
| E3 | probe2+bounded vs tpm_only+fedavg, effective controls only | pair-dba, evasive |
| E4 (positive control) | probe+bounded vs tpm_only+bounded | pair-dba |

Effective control: reference arm paired worst-trigger harm ≥20 points with F1 loss ≤5
points at round 10 or 15 (definition of `report_arm_study.py`).

Secondary, descriptive: attacker cost of evasion (reference-arm peaks, evasive vs
pair-dba; number of effective evasive controls); attacker client-rounds quarantined per
arm/variant and which probe fired, with the features found; honest quarantine rate.

**Interpretation rule declared now:** if fewer than 4 of 8 evasive reference controls are
effective, E1–E3 are reported but the conclusion is "the evasive attack is weak live",
not "the probe is robust".

## Procedure

calibrate → prepare (freeze) → smoke (not evidence) → guard → independent verification
(`scripts/revision_probe_evasion_audit.py guard`) → guard-decide → evaluation →
independent verification → test (precommit, opened only after verification) →
`scripts/report_arm_study.py` → README → archive cases. Failures, deviations and guard
outcomes are reported as observed.

## Note added after `calibrate`, before `prepare` (no training yet)

Calibration result (clean data only): pair-probe clean maxima IID 0.9675, non-IID 1.0
(q98 0.9025 / 0.96). The rule is kept as declared. Consequence stated in advance: in
non-IID the pair probe cannot fire (score ≤ 1 by construction), so `probe2+bounded`
equals `probe+bounded` there; in IID it fires only on near-total pair shortcuts. Honest
clean models already show large pair shortcuts, i.e. the pair probe is weakly
discriminative under a zero-honest-flag rule. This is a finding, not a tuned parameter.
