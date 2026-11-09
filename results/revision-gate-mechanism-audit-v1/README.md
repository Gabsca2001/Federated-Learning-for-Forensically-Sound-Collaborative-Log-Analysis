# Gate mechanism audit

Completed 2026-11-05. The deployed policy code, thresholds and thesis are
unchanged. The audit uses existing source trajectories and does not train a new
model, run test inference, or access raw test examples.

## Verified scope

28 campaigns, 840 rounds, 12,600 statistically scored contribution decisions:

- 20 original five-seed clean/controlled-disagreement campaigns, 9,000 decisions.
- Eight retained gated clean/adaptive arms across four seeds, 3,600 decisions.
- 13,468 coordinator signatures rechecked: 28 manifests, 840 checkpoints and
  12,600 decisions under the retained local coordinator public keys.
- Checkpoint-to-contract and checkpoint-to-decision byte hashes checked;
  stored raw indicator values normalized again; trust signals reconstructed
  from recorded checks; all four policy vectors and deployed masses reproduced.

TPM Quotes, raw training, raw indicator extraction from tensors and numerical
checkpoint reconstruction are not repeated here. Earlier full campaign
verification remains a separate obligation. This report records source and
public-key fingerprints; it does not independently establish those keys' trust.
Original policy-comparison manifests match their published report pins. The
adaptive report pins completion records/execution locks, not individual source
manifests; those manifests are newly fingerprinted and signature-checked here.

## Findings

**No same-input contributor-set differences:** Sequential and Gated Composite
retain exactly the same clients on all 12,600 recorded inputs. There are 12,000
admissible zero-trust-risk observations, 600 controlled failed-trust observations
and no admissible warnings. Their quarantine thresholds are proportional; the
additional observed mechanism is graded nominal weighting. See the
[conditional derivation](../../docs/GATE_MECHANISMS_AND_VALIDATION.md).

On the four **gated adaptive source trajectories**, during attack-active client
slots only:

| Outcome on the same recorded signals | Sequential replay | Composite |
|---|---:|---:|
| Active attacker submissions | 240 | 240 |
| Quarantined | 11 | 11 |
| Retained at reduced nominal mass | 0 | 124 |
| Retained at full nominal mass | 229 | 105 |

The corresponding Composite benign counts on these adaptive trajectories are
29 quarantines and 227 downweights out of 1,560 benign observations (including
pre-attack rounds). These are not the original report's pooled clean-plus-adaptive
benign denominator. Counts are repeated client/round observations, not independent
detection trials or evidence that all retained attacker submissions caused harm.

**Indicator compensation:** 135/240 active attacker submissions have at least one
zero component; all 135 are retained. Seventy have zero `validation_impact` risk.
With five equal weights and the current threshold, one zero component bounds
statistical risk by 0.8, below the 0.818309 quarantine threshold. This establishes
a structural detection limitation, not that any one indicator caused ASR success.
All-positive components do not guarantee detection either: 94 other attacker
submissions also remain below the quarantine threshold.

**Normalized participation is not always reduced:** compare the actual composite
factors with hypothetical Sequential factors on the exact same source inputs.

| Adaptive source seed | Attack rounds with lower attacker share | Higher | Equal |
|---:|---:|---:|---:|
| 342593 | 20 | 0 | 0 |
| 343593 | 16 | 4 | 0 |
| 344593 | 17 | 3 | 0 |
| 345593 | 8 | 10 | 2 |
| Total | 61 | 17 | 2 |

The largest increase is seed 343593, round 30: 21.4253% Sequential share versus
24.9956% Composite share (+3.5703 percentage points). The largest decrease is
seed 342593, round 29: 23.0732% versus 13.0411% (-10.0321 points).
These are exact-rational coefficient comparisons, displayed as rounded percentages.
They are not changes in ASR, model damage or long-term causal influence.

## Interpretation

Hard trust non-compensation remains valid. The new audit does not invalidate the
formal separation of provenance, participation and semantic state. It narrows the
empirical explanation: different live Sequential/Composite quarantines arise on
different later inputs, not a different no-warning same-input exclusion boundary.

The 450/450 unsafe exclusions per original policy were scenario-specific and
included 300 controlled trust failures and 150 trusted attacked inputs per policy.
They are not a general attack-detection rate. The current adaptive results show
why that distinction matters.

A defensible next study separates admission from numerical aggregation, uses
matched-input controls plus independent live trajectories, and measures peak
and final ASR, benign cost, exact participation, availability and total runtime.
The [mechanism review and proposed protocol](../../docs/GATE_MECHANISMS_AND_VALIDATION.md)
give the hypotheses, formulas and controls. No new full training campaign is
claimed by this report. Current evidence does not establish a universally best
gate or justify permanent automatic exclusion of client identities.

## Reproduction

From the repository root, with retained source workspaces available:

```bash
.venv/bin/python scripts/revision_gate_mechanism_audit.py
.venv/bin/python scripts/revision_gate_mechanism_audit.py --verify
.venv/bin/python -m pytest -q tests/test_gate_mechanism_properties.py tests/test_composite_admission.py tests/test_admission.py
```

The generator refuses an existing output directory. Use `--verify` for an
existing report or `--output` with a new destination. `summary.json` retains
all source bindings, per-seed counts, exact round shares and representative
retained attack decisions. CSV tables provide compact numerical outputs.

All 21 focused tests passed: eight added mechanism tests, nine existing
composite-admission tests and four existing admission tests.
The tests include actual threshold/adjacent-float checks, warning/degenerate
conditions, four-saturated-indicator counterexamples, and exact normalized-mass
counterexamples. Finite tests do not substitute for the conditional arguments.
