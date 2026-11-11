# Clipping confirmation: declared before evaluation training and before the test

Written 2026-11-11, after the confirmatory guard and before any evaluation case was
trained or any test outcome computed for this study.

The predeclared confirmatory guard (`artifacts/revision-head-gate-v2-confirm/guard-decision.json`)
qualified `tpm_only+fedavg` (reference) and `tpm_only+bounded`; `head_v2+bounded` failed
and is not evaluated. Hypotheses C1/C2 (about head_v2) are therefore not evaluable.

The evaluation proceeds with the qualified arms under the unchanged frozen protocol
(8 fresh assignments: 4 IID, 4 Dirichlet 0.3; attacks: distributed, complete-trigger,
adaptive, adaptive-headfrozen; 15 rounds, attack rounds 1–10). The single confirmatory
comparison is declared now:

* **K1 (primary):** `tpm_only+bounded` has lower paired worst-trigger peak harm than
  `tpm_only+fedavg` in a majority of defined comparisons, over all attacked variants.
* **K2 (secondary):** the same restricted to effective reference controls (≥20-point
  ASR increase, ≤5-point clean F1 loss), and separately per attack variant (descriptive).
* Clean budgets on the 8 reserved clean assignments are reported for both arms.

Prior evidence motivating K1 (factorial v1: 14/18 lower, 0 higher; v2 exploratory
TPM+clip vs TPM+FedAvg) used different assignments. No parameter is changed.
Report command: `report_arm_study.py --lab artifacts/revision-head-gate-v2-confirm
--out results/revision-head-gate-v2-confirm/clipping-report
--hypothesis tpm_only+bounded,tpm_only+fedavg,distributed|complete-trigger|adaptive|adaptive-headfrozen
--hypothesis tpm_only+bounded,tpm_only+fedavg,distributed|complete-trigger|adaptive|adaptive-headfrozen,effective`
(per-variant counts are computed from the paired-harm table).
