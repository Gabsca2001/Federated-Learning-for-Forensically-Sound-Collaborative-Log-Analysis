# Paired adaptive M6 — completed v4

Exploratory IID seed 341593, 15 clients, 30 rounds per arm. Clients 02, 05 and 14
perform targeted reconnaissance-to-benign model poisoning in rounds 11–30.
The original gated-composite policy and the fixed 66-query budget per attacked round
are unchanged. The optimizer sees validation and all proposals, never test.

## Selected-checkpoint results

| Outcome | Clean | Adaptive |
|---|---:|---:|
| Selected round | 20 | 25 |
| Test macro-F1 | 0.924250 | 0.938970 |
| Targeted test errors / reconnaissance examples | 0/669 | 0/669 |

Adaptive minus clean test macro-F1: +1.4720 percentage points.
All first ten checkpoints match exactly. The attack performed 1320
queries in twenty rounds; 0 rounds met the prespecified
validation success criterion. See searches.json for individual outcomes and controls.

## Interpretation and boundaries

ASR is the number of true reconnaissance examples predicted benign divided by all
true reconnaissance examples (343 validation, 669 pooled test). Other mistakes
are not targeted attack successes. A zero targeted ASR does not mean perfect
classification: the confusion matrices show the other errors.

Admission and attack effectiveness are separate outcomes: authenticated malicious
updates can contribute without attaining their targeted objective. See admission
counts and the explicit honest/attacker denominators in the figure. Changes in
macro-F1 need not track changes in targeted ASR. The within-round drop compares
the selected candidate with untouched proposals at the SAME adaptive trajectory
state; it is not the effect relative to the separate clean trajectory.

Checkpoint selection used maximum validation macro-F1 with earliest-round ties.
Test was accessed only after both complete trajectories; this report reads stored
metrics and performs no new model inference or final-round test evaluation.
One paired seed cannot establish significance, superiority, universal robustness,
or a general failure of adaptive poisoning. Prior dataset reuse makes this
exploratory. No post-test tuning or attack-budget expansion is performed.

## Evidence and reproducibility

Completion: 2026-09-28, local log final marker at 18:30. The detached recovery
retained the original 10 clean/9 adaptive rounds, checked the original lock and
reverified prior rounds. The completed runner stopped TPMs only after verification.
The failed v1–v3 workspaces and original v4 log remain preserved.

Generate once with `.venv/bin/python scripts/report_m6_adaptive_paired_v4.py`.
The generator refuses an existing result directory, checks locked source hashes,
checkpoint/evaluation/decision bindings, selected-search metrics and checkpoint
selection. It does not rerun the expensive 1,320-query optimizer or replace the
independent per-round verifications already performed by the campaign.
`manifest.json` binds input and report file hashes; no private signing keys are
exported. Existing M8 closures do not cover these new experiment artifacts.

## Figures

- validation-trajectories: separate arms, treatment window and selected checkpoints.
- within-round-validation-drop: immediate validation effect on the adaptive state.
- selected-test-confusion: pooled test errors for the selected checkpoints only.
- admission-outcomes: honest and malicious client-round interventions.

Figures are provided as PNG and vector PDF. Underlying data are JSON.
