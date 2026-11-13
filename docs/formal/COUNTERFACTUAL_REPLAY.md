> Formal clarification, 2026-11-03: with fixed K and the explicit
> `not_submitted` marker, every nonempty allowed removal has `J_K=1`.
> With frozen survivor masses and valid normalization/quorum,
> `Delta_K = 2 * removed_original_coefficient_mass`. Use the existing survivor
> action-change list/fraction and additional rescoring coefficient distance for
> the separate indirect-effect question. Exact hypotheses and proofs are in
> [FORMAL_MODEL_THEOREMS.md](FORMAL_MODEL_THEOREMS.md).

# Counterfactuals and replay with retraining

The reference is R09/P6. Single-round interventions and subsequent training
trajectories are separate operations. Outputs are new experimental derivations
signed by the analysis authority; they are not fresh client-signed bundles or
Quotes. Historical decisions and models remain unchanged.

## Single round

`counterfactual-create` requires a pinned historical derivation manifest, the
coordinator key, bundle sources, and an isolated validation split. The module
authenticates references, verifies input hashes, associates decisions and
masses, checks alpha and operational weights, and reproduces the historical
aggregate before measuring a removal. Inputs consumed by the calculation are
frozen in temporary snapshots. This aggregation check does not revalidate
historical policy decisions; full round verification remains a separate step
using the appropriate preserved release.

The two modes are:

| Mode | Operation |
|---|---|
| `frozen_decisions` | Remove the selected submissions, retain survivor decisions, and renormalize masses |
| `rescore_round` | Remove inputs from the population and recompute indicators, policy, and aggregation, retaining historical effective trust checks |

Neither mode produces fresh attestation. In the second mode, counterfactual
decisions are analysis cores; new client or coordinator signatures are not
simulated. Historical bundles are not signed again.

The survivor comparison population consists of remaining submissions with a
runtime decision; protocol-rejection history is unchanged. Removal itself does
not count as a change in other contributions' actions. The report includes:

- survivor masses, rational coefficients, and actions;
- the fraction of survivor actions that change;
- L1 distance between historical and counterfactual survivor coefficients;
- additional L1 distance beyond frozen-decision removal, separating rescoring
  from renormalization;
- parameter L2 difference and model-byte equality, when defined.

When quorum fails, the outcome is `failed_without_model`: no model is invented,
and undefined coefficients or distances remain null. Removing a zero-weight
input can change a survivor decision without changing the model. This is a
policy effect and must not be presented as an unmeasured numerical change.

Public `counterfactual-verify` repeats the computation and compares analysis
and model bytes with the signed manifest's commitments. The fingerprint binds
the package release; historical interventions require their preserved release.

```bash
.venv/bin/fl-forensics counterfactual-create \
  --workspace analysis/removal-round-001 \
  --round-workspace evidence/round-001 \
  --expected-source-manifest-sha256 "$ROUND_DERIVATION_SHA256" \
  --submissions evidence/submissions-round-001 \
  --validation-split evidence/validation.json \
  --coordinator-public-key trusted/coordinator.public.pem \
  --authority-public-key trusted/analysis.public.pem \
  --authority-private-key private/analysis.private.pem \
  --mode rescore_round \
  --remove-submission-id "$SUBMISSION_ID"
```

`--remove-submission-id` may be repeated for group removals. Omitting it creates
a no-removal control. Verification uses the same public locators,
`counterfactual-verify`, and the intervention manifest's `--expected-sha256`;
it does not accept a private key, mode, or removal list to reinterpret.

## Controlled multiround replay

`retraining-create` implements the explicit
`controlled-offline-cpu-fedavg-v1` protocol. Every selected client is actually
trained in every round from its branch's current base. There is no option to
reuse historical future updates. Removal is specified per round: omitting a
client in round 1 does not automatically remove it from later rounds. This
isolates removing one contribution from permanently excluding a client.

This protocol uses FedAvg without a fresh TPM gate or new composite admission.
It is a circumscribed experimental check of numerical propagation; it does not
replace DBA campaigns, defense comparisons, or a full attested live replay.
Those experiments retain their own protocols.

Inputs are the base, partition manifest, training snapshots, and validation
snapshot, all pinned by hash. Classes and their order must agree; test and
holdout splits are not used for selection. Training uses the original
`train_local`, a new Adam optimizer for each local call, single-thread CPU,
seed `seed + round * 10000 + partition_id`, deterministic DataLoader behavior,
and fixed client order. Local models, seeds, optimizer steps, experimental
checkpoints, and validation metrics are preserved.

Example plan, to adapt before execution:

```json
{
  "rounds": 3,
  "seed": 341593,
  "local_epochs": 2,
  "batch_size": 128,
  "learning_rate_decimal": "0.001",
  "minimum_contributors": 2,
  "clients": ["client01", "client02", "client03"],
  "remove_at_round": {"1": ["client03"]}
}
```

```bash
.venv/bin/fl-forensics retraining-create \
  --workspace analysis/replay \
  --plan analysis/replay-plan.json \
  --base-model evidence/base-model.json \
  --expected-base-sha256 "$BASE_SHA256" \
  --partition-workspace evidence/partitions \
  --expected-partition-sha256 "$PARTITION_MANIFEST_SHA256" \
  --validation-split evidence/validation.json \
  --expected-validation-sha256 "$VALIDATION_SHA256" \
  --authority-public-key trusted/analysis.public.pem \
  --authority-private-key private/analysis.private.pem

.venv/bin/fl-forensics retraining-verify \
  --workspace analysis/replay \
  --expected-sha256 "$REPLAY_MANIFEST_SHA256" \
  --base-model evidence/base-model.json \
  --partition-workspace evidence/partitions \
  --validation-split evidence/validation.json \
  --authority-public-key trusted/analysis.public.pem
```

Verification actually repeats training and requires computation time. It
compares the environment, manifest, all artifacts, and trajectory byte for
byte; missing or unexpected files are rejected. A plan without intervention
provides a negative control. Reproducibility requires the preserved release
and environment; it is not promised across arbitrary PyTorch versions or
different backends.

Conclusions remain conditional on the declared data, protocol, randomness, and
intervention. A changed model does not prove malicious intent, attack success,
or certified unlearning through removal.

## Original proposal measures and survivor diagnostics

The report also retains `proposal_metrics`, using the
`original-fixed-expected-client-population-v1` profile. Coefficients are indexed
on the fixed set of expected clients in the authenticated context, with zero
for nonaggregated clients when normalization exists. `delta_l1` is the full L1
distance; `j_any_action_change` is the binary indicator of a changed treatment
vector. To define that vector for missing/removed slots, the operational marker
`not_submitted` is explicit: it is neither a trust decision nor a semantic label.
Protocol rejections remain historical; experimental removal permits only
submissions with runtime decisions, rather than calling an already excluded
protocol rejection an intervention.

Removal itself can make J equal to one without changes to other clients.
Survivor measures remain separate and describe that other effect. With two
valid aggregates, full Delta equals survivor Delta plus the sum of historical
removed coefficients. Without valid normalization, the corresponding
coefficient vector or Delta is undefined (`null`), not zero; J can still be
defined for recorded treatments. Earlier outputs require their own preserved
release and are not rewritten.

The property and assumption review is in `FORMAL_MODEL_REVIEW.md`.
Upstream record coverage is a separate profile documented in
`INGESTION_COVERAGE.md`.


## Follow-up: separated influence and successful-attack replay (2026-11-03)

The original fixed-population Delta/J definitions are retained. New versioned
diagnostics distinguish removed weight, survivor action changes, policy total
variation against removal-only renormalization, and direct/additional/total model
distances. Their L2 scalar values are not additive. Historical observed eligibility,
effective gate and scoring membership are exposed separately.

The composed investigation API verifies every supplied graph round with the full
admission verifier before setting its top-level policy-revalidation flag; anchored
reviews and exact intervention/source binding are checked separately. Deadline and
global artifact completeness claims are not strengthened by this composition.

All three historical DBA seeds now have full retraining interventions from before
the attack, with a byte-identical replay control and a clean matched-participation
branch. Both single and group removal yield ASR zero at attack end; this does not
demonstrate extra group synergy, and the single-removal models still differ from
the matched clean models. The original control also recovers ASR zero after clean
training. These software experiments remain distinct from fresh TPM evidence.

See [definitions, results and verification scope](../../results/admission/revision-effective-influence-v1/README.md).
