# Admission policies, aggregation and retrospective analysis

Admission determines whether and with what operational factor a contribution
enters an aggregation. Aggregation determines how admitted numerical inputs
produce a checkpoint. Retrospective assessment records investigative hypotheses.
These operations have separate evidence and guarantees.

## Effective configuration

| Execution context | Selected behavior |
| --- | --- |
| M5 without `--in-round-admission-config` | Mandatory secure-round checks; no optional in-round statistical file is installed implicitly |
| Explicit standard `configs/in-round-admission.yaml` | `gated_composite`, policy `m5-in-round-gated-composite-v1`, minimum ten contributors |
| Explicit `configs/revision-unified-v2-admission.yaml` | `tpm_only` for the selected unified witnessed profile |
| V5 numerical assessment | Count-weighted FedAvg with prerequisite trust assumed passed in software; offline group analysis |

The optional argument is defined in `secure_round.py`; the standard file does
not override a profile that explicitly binds another configuration.

## Four original policies

| Policy | Decision mechanism | Interpretation |
| --- | --- | --- |
| `tpm_only` | Required trust/integrity eligibility | Authentication is not evidence of benign numerical intent |
| `statistics_only` | Statistical-risk comparison ablation | It has no mandatory-trust non-compensation guarantee |
| `sequential` | Required trust gate followed by a statistical threshold | Passing trust cannot compensate for a failed required gate |
| `gated_composite` | Required trust veto followed by combined trust/statistical risk and full/downweighted/quarantined treatment | The statistical mixture remains distinct from the hard veto |

`statistics_only` is a comparison policy, not an allowed primary secure-runtime
policy in the current `InRoundAdmissionConfig` schema. Under the retained
no-warning settings, Sequential and Composite have the same contributor set on
fixed inputs, while Composite can assign different weights. Their separately
trained trajectories can consequently diverge.

The [gate mechanism audit](../admission-gates/GATE_MECHANISMS_AND_VALIDATION.md) retains the
derivations, thresholds and observed warning coverage. Its hard-trust
non-compensation property does not imply non-compensation among averaged
statistical indicators. Downweighting does not necessarily reduce an attacker's
normalized share when benign mass is reduced more strongly.

## Separate numerical defenses

Frozen Byzantine comparisons, bounded/clipped updates, robust aggregation and
final-coefficient projection define distinct operators. Coefficient ceilings
can hold while poisoning succeeds. The mass-feasibility result concerns the
original sample-proportional contract; transformed final coefficients resolve
that particular algebraic constraint by changing the operator, not by proving
an ASR guarantee. The completed capped-final study retains negative security
results despite passing its declared clean-utility conditions.

Positive coherent endpoint containment cases are documented under their exact
root/reference, loss, attacker and horizon assumptions. Zero measured ASR in
those cases coexists with residual parameter differences.

## Retrospective V5

V5 keeps macro-F1 utility risk separate from actor-anomaly evidence. Actor flags
use a clean-calibrated third-largest magnitude score over ten rounds. Group
edges require at least three common threshold-exceedance rounds on the same
mechanism; feasible cliques leave ten contributors. Tensor descriptors remain
investigative evidence.

The rule neither infers malicious intent from utility loss nor authorizes
automatic permanent exclusion. One/two-round, staggered, small or norm-limited
episodes can escape its contract. Current results and intervention controls are
summarized in [Experimental findings](EXPERIMENTS.md).
