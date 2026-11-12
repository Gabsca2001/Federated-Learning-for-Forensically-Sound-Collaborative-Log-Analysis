# Global-model probe with rollback: predeclared live study

Written 2026-11-12, before any training of this study. The machine-readable freeze is
`artifacts/revision-global-probe-confirm/protocol-before-guard.json` (written by `prepare`;
its sha256 goes in the results README).

## Question

The per-key client probe (`probek`, confirmed in `../revision-probe-keynorm-confirm/`) stops
pair DBA and the probe-aware evasive attack, but two problems remain:
* it does not stop the adaptive interpolation attacker;
* once the backdoor reaches the global model, it excludes honest clients that inherit it.

Does a probe on the **global** model, which rolls the round back on alarm, close these gaps
without cost on clean data, on fresh partitions?

## Rule (frozen from development, not tuned here)

1. The client gate is unchanged `probek`, with the pinned scales of the key-norm study and ×2.
2. After clipping aggregation, compute drift_k = probe shortcut_k(candidate global) −
   shortcut_k(the case's initial model) for each key k = (feature, value).
3. Scale s_k = max(clean max drift_k per cohort, 0.1). The scales are refitted by `calibrate` on
   the 12 verified clean TPM-only histories of `revision-clean-gate-calibration-v1` and pinned
   (`calibration/global-scales.json`).
4. If max_k drift_k / s_k > 1.5, the round is rolled back: the new global model is the previous one.

Floor 0.1 and multiplier 1.5 come from `../revision-global-probe-dev/`, where they were chosen
with those data visible. That is why this study exists. The adaptive attacker's search scores its
candidates after the complete defence, rollback included.

## Design

* Data24, unchanged engine and training configuration, software trust assumption.
* Fresh partitions: guard 4 (2 IID, 2 Dirichlet α=0.3) and evaluation 8 (4 + 4). Distinctness is
  checked against every surviving earlier study, including the key-norm study. Each evaluation
  partition has 3 attackers, drawn from the seed.
* The attack plan and the variants are those of the key-norm study: clean, pair-dba, evasive and
  adaptive, with pairs {3,18}, {8,15}, {11,22} at 6 std units in rounds 1–10.
* Arms:
  * `tpm_only+fedavg` (reference)
  * `tpm_only+bounded`
  * `probek+bounded`
  * `probekg+bounded` (the rule under test)

## Guard

* **Clean guard:** 16 cases, independently verified before the decision. Same revised rule as before:
  honest quarantine ≤5%, nominal mass ≥90%, no honest client excluded in 2 consecutive rounds, and
  validation macro-F1 loss ≤2 points at rounds 10 and 15. A false rollback freezes the model, so it
  shows up as F1 loss. If `probekg+bounded` fails, G1–G4 are undefined.
* **Attacked guard (G4, predeclared):** over all 24 attacked evaluation runs of `probekg+bounded`,
  honest client-round quarantine ≤5% and no honest client excluded in 2 consecutive rounds in any
  run. It holds only if both conditions hold.

## Hypotheses

Paired worst-trigger peak harm against the arm's own clean history. The seed is the unit. A
hypothesis holds if harm is strictly lower in a majority of the defined comparisons.

| Id | a vs b | Variants |
|---|---|---|
| G1 | probekg+bounded vs probek+bounded | adaptive |
| G2 | probekg+bounded vs tpm_only+bounded | pair-dba, evasive, adaptive |
| G3 | probekg+bounded vs tpm_only+fedavg, effective controls only | pair-dba, evasive, adaptive |
| G4 | attacked guard (above) | all attacked |

Secondary, descriptive:
* rollback rounds per arm, variant and cohort
* attacker client-rounds quarantined
* effective controls per variant
* clean final F1 of probekg vs probek

## Procedure

1. `calibrate`
2. `prepare` (freeze)
3. smoke (not evidence)
4. guard
5. independent verification (`scripts/revision_global_probe_audit.py guard`)
6. guard-decide
7. evaluation
8. independent verification
9. test (opened only after verification)
10. `scripts/report_arm_study.py`
11. README with G4 computed from round statuses
12. archive the cases

Failures and deviations are reported as observed.
