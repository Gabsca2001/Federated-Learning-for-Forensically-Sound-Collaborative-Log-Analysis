# Adaptive paired multiseed — completed 2026-09-30

One exploratory reference (341593, v4) and four prespecified extensions (342593–345593).
Five pairs, 30 rounds per arm, 300 rounds total. The extension itself adds 240 rounds.
This report reads stored evaluations only; no new training, attack tuning or test inference.

## Selected-checkpoint outcomes

| Seed | Clean macro-F1 | Adaptive macro-F1 | Difference (pp) | Clean target errors | Adaptive target errors |
|---|---:|---:|---:|---:|---:|
| 341593 | 0.924250 | 0.938970 | +1.4720 | 0/669 | 0/669 |
| 342593 | 0.962488 | 0.962569 | +0.0081 | 0/669 | 0/669 |
| 343593 | 0.918839 | 0.932190 | +1.3352 | 0/669 | 0/669 |
| 344593 | 0.962525 | 0.962631 | +0.0106 | 0/669 | 0/669 |
| 345593 | 0.932106 | 0.924037 | -0.8069 | 0/669 | 0/669 |

All-five paired macro-F1 difference: mean +0.4038 pp,
sample SD 0.9728 pp.
Four-new-seed difference: mean +0.1367 pp,
sample SD 0.8868 pp.
Individual outcomes and mean/sample SD for both cohorts are in summary.json.
These are descriptive statistics, not a superiority/equivalence test.

## Interpretation

Targeted ASR counts true reconnaissance samples predicted benign divided by all
reconnaissance samples. The same held-out dataset is reused across seeds: do not
treat repeated test examples as independent observations or pool denominators as
new independent samples. Zero ASR does not imply perfect multiclass classification.
Maximum validation macro-F1 (earliest tie) selects each model separately.

Admission of malicious contributions and attack success are different outcomes.
There are 60 malicious client-rounds per seed, 240 honest adaptive client-rounds
and 300 clean client-rounds during rounds 11–30. See admission-counts and summary.json.
Within-state drops compare an attacked candidate against untouched proposals on
the adaptive state, not against the separate clean trajectory.
The optimizer has privileged validation and all proposals; this is a strong-knowledge
stress test, not a guaranteed upper bound over possible attacks.
The first seed was already observed before fixing the extension; this is not an
entirely fresh confirmatory study. Five seeds are a small sample. Do not claim
universal robustness, general attack failure or beneficial poisoning.

## Cost, failures and verification scope

6600 search queries across 100 attacked rounds, plus
independent campaign recomputation; 0
rounds meet the locked validation success criterion. Query counts are not CPU time.
Exact wall-clock/GPU cost was not reconstructed by this report.
The first reference retained its documented v1–v3 failures and v4 recovery.
The extension had two pre-training invocation failures; recovery2 used the absolute
runner path and explicit numeric wrapper without altering the locked protocol.
See [execution history](../../docs/M6_ADAPTIVE_MULTIROUND.md) and local recovery receipts.
No failed attempts were converted into successful observations or discarded.

The extractor checks completion receipts, source locks, checkpoint/model/evaluation
and decision hashes, exact first-ten-round equality, selected-query metrics, query
budget and model selection. It does not rerun the expensive optimizer or replace
the independent campaign verifiers. Existing M8 packages do not cover this extension.

## Outputs

- paired-test-macro-f1: paired endpoints and differences.
- validation-trajectories: every seed and both arms; stars mark selected checkpoints.
- within-state-effects: immediate attack effects, with distinct counterfactual scope.
- admission-counts: honest/malicious interventions with explicit denominators.

Figures are PNG and vector PDF; data are CSV/JSON. manifest.json binds the files read
and generated. Run once with python scripts/report_m6_adaptive_multiseed_v1.py.
Existing output is protected from overwriting.
