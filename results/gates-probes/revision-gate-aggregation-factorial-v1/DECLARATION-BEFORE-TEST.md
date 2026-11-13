# Factorial v1: analysis declared before the test split is opened

Written 2026-11-10 while evaluation training was still running; no test outcome
had been computed for this study.

The predeclared guard (`artifacts/revision-gate-aggregation-factorial-v1/guard-decision.json`)
qualified only `tpm_only+fedavg` (reference) and `tpm_only+bounded`. All gate arms
failed on clean data: `gated_composite` lost quorum in non-IID; `head_cusum` arms
retained only 65.7% of mass in a round (an honest client with 34% of the data was
permanently quarantined); `tpm_only+trimmed_mean` exceeded the 2-point F1 budget.
The frozen hypotheses H1–H4 all involve `head_cusum` arms and are therefore **not
evaluable**; this is recorded as an outcome, not hidden.

Note: guard non-IID seeds 2026111043 and 2026111044 received an identical partition
(partitioning defect, see results/gates-probes/revision-head-cusum-gate-v1/README.md erratum);
evaluation partitions 2026111031–36 are verified distinct.

The only comparison reported for this study (descriptive, seed as unit):

* **D1** `tpm_only+bounded` vs `tpm_only+fedavg`: paired worst-trigger peak harm,
  in all attacked variants (distributed, complete-trigger, adaptive), and separately
  restricted to effective reference controls (≥20-point ASR increase, ≤5-point clean
  F1 loss). Majority-lower is reported; no promotion follows from it.

Command: `report_arm_study.py --lab artifacts/revision-gate-aggregation-factorial-v1
--out results/gates-probes/revision-gate-aggregation-factorial-v1/report
--hypothesis tpm_only+bounded,tpm_only+fedavg,distributed|complete-trigger|adaptive
--hypothesis tpm_only+bounded,tpm_only+fedavg,distributed|complete-trigger|adaptive,effective`
