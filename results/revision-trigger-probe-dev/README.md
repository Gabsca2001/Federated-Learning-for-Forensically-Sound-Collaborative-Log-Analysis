# Behavioural trigger probing of client models: offline development check

2026-11-11. Development only: recorded local models of the head-gate v2 exploratory
study (TPM-only FedAvg arms, attackers unconstrained), no training, test not used.
Script: `scripts/revision_trigger_probe_dev.py`; data: `dev-report.json`.

Probe: for each client model and each single feature j, set j to 3/6/12 standard units
on the server's clean validation attack rows; shortcut = increase in the fraction
predicted benign. Score = largest shortcut in excess of the round's peer median for the
same (feature, value). No attacker identity or attack-plan feature/value is used.
Threshold: clean 98th percentile per cohort from 12 verified clean TPM-only histories
of revision-clean-gate-calibration-v1 (IID 0.481, non-IID 0.692).

## Results

| Cohort | Attack | Attacker slots flagged | Benign flagged | AUC | Most frequent shortcut found |
|---|---|---:|---:|---:|---|
| IID | distributed DBA | **150/150** | 2/600 | **1.000** | features 17, 24, 13 at 12 (the true components) |
| IID | complete-trigger DBA | **150/150** | 8/600 | **1.000** | feature 17 at 12 |
| non-IID | distributed DBA | **135/150** | 4/600 | **0.996** | features 17, 13, 24 at 12 |
| non-IID | complete-trigger DBA | **137/150** | 11/600 | **0.994** | feature 17 at 12 |
| IID | adaptive | 19/150 | 1/600 | 0.40 | scattered |
| IID | adaptive, head frozen | 59/150 | 0/600 | 0.77 | scattered |
| non-IID | adaptive | 11/150 | 31/600 | 0.22 | scattered |
| non-IID | adaptive, head frozen | 25/150 | 13/600 | 0.54 | scattered |

Clean histories (10 assignments): 0–3.1% of honest client-rounds flagged; but some honest
clients are flagged in up to 4–5 consecutive rounds.

## Generality check (unchanged probe, four new triggers declared before running)

`scripts/revision_trigger_probe_generality.py`, `generality.json`. TPM-only FedAvg trained in
memory on 2 IID + 2 non-IID partitions; attack rounds 1–10; attacker slots counted in rounds 1–10.

| Trigger | IID flagged (2 partitions) | non-IID flagged (2 partitions) | Benign flagged | Peak ASR | Shortcuts found |
|---|---|---|---|---:|---|
| T1 features 2/9/20 at 12 | 30/30, 30/30 | 26/30, 25/30 | 0–3/120 | 0% (attack ineffective globally) | f9, f20, f2 (true) |
| T2 features 4/11/19 at 6 | 30/30, 30/30 | 21/30, 30/30 | 0–5/120 | 58–67% | f11, f19, f4 (true) |
| T3 pairs {1,7}/{10,16}/{21,23} at 4 | 30/30, 30/30 | 18/30, 26/30 | 0–3/120 | 15–21% | f1, f21, f10, f23 (true) |
| T4 features 6/14/22 at 3 | 30/30, 30/30 | 11/30, 30/30 | 0–3/120 | 2–19% | f14, f22 (true) |

Clean runs: 0–5/225 honest client-rounds flagged.

The unchanged single-feature probe detects poisoned local models for triggers on other
features, milder values, multi-feature components and an in-distribution value, and
recovers the true trigger features. Detection is complete in IID and weaker in non-IID
for the subtlest triggers (T4: 11/30 on one partition). It flags poisoned local models even
when the attack does not succeed globally (T1). Attackers were not aware of the probe.

## Threshold severity vs persistent honest flags (`../revision-trigger-probe-thresholds/`)

Clean-only thresholds per cohort; detection counts are attacker client-rounds (rounds 1–10).

| Threshold | Clean honest flagged | Longest honest run | IID DBA (dist./complete) | non-IID DBA (dist./complete) |
|---|---:|---:|---|---|
| 98th pct | 1.7% | 5 | 150/150, 150/150 | 135/150, 137/150 |
| 99.5th pct | 0.5% | 3 | 150/150, 150/150 | 98/150, 111/150 |
| clean max | **0%** | **0** | **150/150, 150/150** | 74/150, 69/150 |
| clean max ×1.1 | 0% | 0 | 150/150, 150/150 | 37/150, 1/150 |

IID: a clean-maximum threshold removes every honest flag and keeps full DBA detection.
Non-IID: a trade-off remains between persistent honest flags and detection (about half of
attacker client-rounds at zero honest flags).

## Probe-aware attacker (`evasion.json`): AND-trigger on feature pairs

Each attacker teaches "pair → benign" while each single feature keeps the true label.

| Cohort, value | Global ASR | Single-feature probe | Pair probe (300 pairs) | Honest flagged (pair) | Pairs found |
|---|---:|---:|---:|---:|---|
| IID, 6 | 6% | 30/30 | 27/30 | 0/120 | (11,22), (3,18) true |
| IID, 12 | 0% | 18/30 | 30/30 | 0/120 | (11,22), (3,18) true |
| non-IID, 6 | 15% | 18/30 | 20/30 | 0/120 | (11,22) true |
| non-IID, 12 | 0% | 16/30 | 20/30 | 0/120 | (11,22) true |

Hiding single-feature shortcuts makes the backdoor nearly useless (0–15% ASR, vs 58–67% for
an ordinary DBA such as T2), and a pair probe still recovers the true pairs with no honest
flags. Pair-probe threshold is in-sample (same partitions' clean runs): development only.
One evasion strategy, two partitions.

## Reading

* **DBA is detected almost perfectly, including in non-IID** — where every geometric
  gate, clipping and Byzantine aggregator failed — and the probe recovers the actual
  trigger components without knowing them (forensically explainable decisions).
* **Adaptive attacks are not detected** by the probe; they are the attacks per-tensor
  clipping is confirmed to contain. The two mechanisms are complementary.
* **Open risk:** persistent benign flags (up to 5 consecutive rounds) would fail the
  confirmatory guard rule used for head_v2; and an attacker aware of the probe could use
  multi-feature or less extreme triggers. Both must be tested before any live study.
