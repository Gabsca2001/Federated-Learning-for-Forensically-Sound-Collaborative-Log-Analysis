# Framework architecture and execution boundaries

The framework composes verifiable artifact contracts. A milestone identifies a
functional responsibility; an execution profile selects the contracts actually
used in a campaign. The presence of several defenses in the repository does not
imply that every campaign executes every defense.

## Functional path

| Stage | Responsibility | Principal retained objects |
| --- | --- | --- |
| M2 | Controlled Data24 ingestion, deterministic consolidation/windows, split and training-only preprocessing | Dataset/scaler manifests and source lineage |
| M3 | IID/non-IID partitions, clean FedAvg and separate PROTEAN adaptation | Client snapshots, evaluation snapshot and baseline models |
| M4 | Enrollment, identity bindings, mTLS and Quote appraisal | Public identity bindings, challenges and appraisal evidence |
| M5 | Signed context/update validation, selected admission and aggregation | Submission occurrences, decisions, coefficients and checkpoints |
| M6 | Byzantine/admission experiments under named protocols | Frozen inputs or independently trained trajectories and comparison reports |
| M7 | Verified inference, explanations, ATT&CK interpretation and reporting | Prediction, explanation and report manifests |
| M8 | Inventory, Merkle commitment, timestamp, recovery and final accounting | Preservation manifest, time proof, archive and verification receipt |

M1 demonstrates controlled acquisition and custody on a separate small source.
The public Data24 release enters at controlled ingestion in M2. Its earlier
capture does not acquire TPM provenance retrospectively.

## Formal investigation layer

The formal layer distinguishes numerical-use, decision-dependency and audit
relations. Authenticated occurrences remain distinct even when their bundle
bytes coincide. A signed semantic review appends an attributed judgment without
changing the historical admission action, coefficient or model.

Client receipts support accounting against the supplied authentic evidence set.
The stronger witnessed profile also binds registration intervals, cutoff and
closure. Occurrence coverage is a separate committed-input property. None of
these contracts establishes completeness before the declared input boundary.

The multiround graph links declared contributions and checkpoints to later
checkpoints and actual prediction/explanation/report products. Reachability
describes structural exposure. Numerical damage requires an intervention and
the appropriate numerical verifier. Direct reaggregation changes one round;
later causal replay retrains updates from corrected parents.

## Representative integration

The `unified-witnessed-fedavg-v1` profile selects a witnessed M5 path, an actual
M7 investigation and an authenticated graph. Its separately versioned M8 profile
preserves and reconstructs that declared chain. The representative integration
case is one round with fifteen software-TPM clients. Earlier multiround attack
and replay studies supply separate evidence, not additional rounds of this case.

The shared system definition and its exact assumptions are retained in
[SYSTEM_MODEL.md](../SYSTEM_MODEL.md), with the
[profile correspondence](../SYSTEM_PROFILE_CORRESPONDENCE.md) and
[integration report](../UNIFIED_CHAIN_VALIDATION.md). Mathematical statements
remain in the [formal reference](../formal/FORMAL_MODEL_THEOREMS.md).
