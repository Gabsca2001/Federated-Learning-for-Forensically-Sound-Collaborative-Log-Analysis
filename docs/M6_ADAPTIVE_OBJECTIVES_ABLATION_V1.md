# Adaptive objective and statistical-filter ablation v1

Prespecified: 2026-09-30, before running any cell in this ablation.

## Question and design

Does the observed adaptive-attack outcome depend on choosing one target class, and
how does removing the statistical gate change the attack's ability to alter the
frozen aggregate? This is a validation-only screening pilot for two factors:

| Attack objective | Admission policy | Meaning |
|---|---|---|
| Targeted | gated-composite | Raise reconnaissance-to-benign validation ASR under the existing gate |
| Targeted | TPM-only | Same objective with valid TPM trust as the admission decision; no statistical filter |
| Untargeted | gated-composite | Lower all-class validation macro-F1 under the existing gate |
| Untargeted | TPM-only | Same general degradation objective with TPM-only admission |

All four cells use the same signed round-11 source, clients 02/05/14, validation
split, 66-query budget and radius/step schedule. Each search contains one clean
control, one fixed sign-flip control and 64 adaptive proposals (16 per radius).
Trust and M5 integrity checks remain active in both policy cells. In TPM-only,
statistical indicators are recorded for analysis but do not filter, downweight or
quarantine an update. Clean accepted decisions and aggregates must reproduce the
source byte for byte in the gated-composite cells. All clients in the source have
valid trust; this ablation therefore isolates the statistical decision, not TPM
failure handling.

## Endpoints and decision rules

The targeted cell selects feasible proposals by highest reconnaissance-to-benign
validation ASR, then lower target cross-entropy, then earliest query. Prespecified
success is at least +0.10 absolute ASR over that cell's clean aggregate.

The untargeted cell uses all labeled validation rows. It performs gradient ascent
on true-label cross-entropy and selects the feasible proposal with the lowest
all-class validation macro-F1, then highest all-row cross-entropy, then earliest
query. Prespecified screening success is at least 0.01 absolute macro-F1 loss from
the corresponding policy's clean aggregate. The targeted ASR remains a secondary
metric for this cell.

No test or temporal holdout is read. Validation drives attack optimization,
selection, feasibility and screening success; results are therefore optimization
set outcomes and require a later independently designed live evaluation to support
generalization. This pilot is one frozen round on one seed, not a multi-seed or
signed adaptive campaign. Do not describe it as proof of universal robustness.

## Interpretation

Compare policy cells within the same objective to assess the statistical filter's
effect on this finite attack search. Compare objectives within a policy to assess
whether the conclusion changes beyond the original class-targeted objective. A
success only under TPM-only is evidence that the statistical gate affected this
frozen search outcome. Failure in both cells cannot establish that the filter was
necessary: the optimizer is finite and validation-specific. Differences between
objectives also change the optimization loss, so do not treat their raw scores as
one common endpoint.

The 341593 multi-round study is a separate signed live experiment and remains the
primary adaptive runtime result. This ablation creates derived unsigned candidate
updates only; it does not modify that campaign, its artifacts, locked protocol or
TPM state. If this pilot motivates a new live experiment, freeze its objective,
policy, seed, budget and evaluation plan before using test outcomes.

## Reproduction and integrity

Config: `configs/m6-adaptive-objectives-ablation-v1.json`.
The lock binds the runner, frozen-pilot runner/config/lock and this protocol.
Before execution, run `check` for each of the four objective-policy pairs; it
re-verifies the source round and clean path without creating candidate artifacts.
Only proceed if all four checks pass. Then run each fresh output once and preserve
partial workspaces on error. The runner refuses existing output directories,
verifies all source bindings, keeps test access disabled, and records every query.
The report must separately verify each cell before interpreting it.

Commands, from the repository root:

```bash
for objective in targeted untargeted; do
  for policy in gated_composite tpm_only; do
    .venv/bin/python scripts/run_m6_adaptive_objectives_ablation_v1.py check \
      --objective "$objective" --policy "$policy"
  done
done
```

After all four checks pass, replace `check` with `run` once per cell. The output
workspaces are under `artifacts/m6-adaptive-objectives-ablation-v1/`.