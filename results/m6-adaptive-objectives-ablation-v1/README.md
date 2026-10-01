# Adaptive objective and statistical filter ablation — frozen pilot

Prespecified on 2026-09-30 and completed on the same date. Four cells compare a
targeted reconnaissance-to-benign objective and an untargeted all-class degradation
objective under gated-composite and TPM-only admission. Each cell used one verified
signed source round, three attacker identities and 66 queries (two controls plus 64
adaptive proposals). Independent runner verification recomputed every stored query
for all four cells. No test data were accessed; no training, new signing or live
multi-round trajectory was performed by this pilot.

## Selected validation outcomes

| Objective | Admission policy | Clean macro-F1 | Candidate macro-F1 | Baseline − candidate (pp) | Prespecified success | Secondary targeted ASR |
|---|---|---:|---:|---:|---|---:|
| targeted | gated_composite | 0.948184 | 0.937989 | +1.019 | False | 0.000 |
| targeted | tpm_only | 0.948333 | 0.874138 | +7.420 | False | 0.000 |
| untargeted | gated_composite | 0.948184 | 0.941438 | +0.675 | False | 0.000 |
| untargeted | tpm_only | 0.948333 | 0.695360 | +25.297 | True | 0.000 |

For the targeted objective, success required at least +0.10 absolute targeted ASR.
Neither policy achieved it; reconnaissance-to-benign ASR remained zero. For the
untargeted objective, success required a macro-F1 reduction of at least 0.01. The
gated-composite search selected a 0.675-point reduction and did not meet the
criterion; TPM-only selected a 25.297-point reduction and did. The all-class
cross-entropy objective therefore found a much more damaging validation candidate
when the statistical filter was removed, on this specific source round and finite
search. The fixed sign-flip control was infeasible under gated-composite but feasible
under TPM-only; it is a separate, non-adaptive control and must not be attributed to
the adaptive search.

All three attacker updates contribute in the selected candidate in each cell. Under
gated-composite, their selected targeted statuses are {'client02': 'accepted', 'client05': 'accepted_downweighted', 'client14': 'accepted_downweighted'}; the selected untargeted statuses are {'client02': 'accepted_downweighted', 'client05': 'accepted_downweighted', 'client14': 'accepted_downweighted'}. Under TPM-only all three are accepted in the selected candidates. Admission and damage remain distinct outcomes.

## Interpretation and limits

This factorial pilot directly tests whether the result depends on the target objective
and whether the statistical gate changes this finite search. It supports the
hypothesis that the gate constrained the untargeted candidate on this round. It does
not establish that gated-composite prevents untargeted poisoning in live training,
that TPM-only generally fails, or that the found validation candidate transfers to
held-out data. The attacker has privileged access to the exact validation oracle;
selection and the reported effect use the same validation set. One seed and one
frozen round are not independent replication. The multi-round five-seed experiment
remains separate and showed zero selected-test targeted ASR for its narrower target.

The gate control preserves M4 trust and M5 integrity checks; all source clients were
trusted. TPM-only removes the statistical admission effect, not attestation or
signature checks. Candidate updates are derived from signed inputs and are not newly
signed TPM submissions. The validation drop is baseline macro-F1 minus selected
candidate macro-F1; positive means degradation. Query count is a search budget, not
an independent sample size. Both thresholds were fixed before these four cells ran.

A new live adaptive campaign should be considered only after reviewing this screening
pilot and freezing a separate protocol. To support a thesis claim about held-out or
multi-seed effectiveness, it needs new paired signed trajectories and an untouched
evaluation endpoint; test metrics must not steer attack search or policy selection.

## Reproducibility

Protocol: [M6_ADAPTIVE_OBJECTIVES_ABLATION_V1](../../docs/M6_ADAPTIVE_OBJECTIVES_ABLATION_V1.md).
The report manifest binds every query artifact, config, lock, runner and report output
by SHA-256. Each cell's `summary.json` records the selection, query budget, trust/policy,
source bindings and explicit no-test-access flag. The four independent `verify`
commands completed successfully; they deterministically recomputed the searches and
matched stored artifacts. No existing experiment workspace was overwritten.

Figures: `validation-policy-objectives` compares clean and selected validation F1;
`validation-degradation` shows baseline-minus-candidate changes and the 1 pp screening
threshold. CSV and JSON retain the exact values and attacker decisions.
