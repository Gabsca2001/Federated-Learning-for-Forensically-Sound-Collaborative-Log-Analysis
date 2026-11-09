# Receipt-bound round derivation

This increment connects the supplied client receipts and frozen input inventory
to final submission outcomes, the actual scoring population, effective FedAvg
masses and a signed derivation graph. It implements the single-round part of
R02–R05; reviews, multiround blast radius and causal replay are later increments.

## Activate the profile before admission

First generate receipts and the input inventory as described in
`SUBMISSION_EVIDENCE.md`. The complete profile requires enough external client
evidence to recompute every inventory entry and referenced receipt core. A
presented subset remains useful for the intake-only coverage verifier, but does
not certify a full round derivation.

```bash
PYTHONPATH=src python -m fl_forensics m5-admit-composite-aggregate \
  --workspace ROUND_WORKSPACE \
  --trust-workspace TRUST_WORKSPACE \
  --submissions SUBMISSIONS_ROOT \
  --validation-split VALIDATION_SPLIT \
  --coordinator-workspace COORDINATOR_WORKSPACE \
  --input-inventory INPUT_INVENTORY \
  --client-receipts RETAINED_CLIENT_RECEIPTS

PYTHONPATH=src python -m fl_forensics m5-verify-round-derivation \
  --workspace ROUND_WORKSPACE \
  --trust-workspace TRUST_WORKSPACE \
  --submissions SUBMISSIONS_ROOT \
  --validation-split VALIDATION_SPLIT \
  --client-receipts RETAINED_CLIENT_RECEIPTS
```

Run these commands from this checkout with the project's dependencies available.
`PYTHONPATH=src` ensures that an editable installation pointing to another copy
of the repository does not silently select the old implementation.

Before any trust/scoring decision, the profile verifies external evidence,
authenticates the inventory and freezes a signed binding. It also compares
base-model, training-contract, partition-manifest and federation configuration
bytes with the hashes in the signed context. Every actual bundle offered in a
context's client slot must be inventoried.

An intake rejection excludes that client from runtime admission/scoring. Each
submission still receives a signed final disposition in the manifest. Multiple
conflicting submissions remain separate dispositions, not multiple contributions
or a reused decision for the wrong bundle hash. Their bundle nodes are retained
as commitments when availability has not been established.

## Preserved artifacts

The fixed directory `ROUND_WORKSPACE/derivation/` contains:

- `input-inventory.json`: the preserved original inventory;
- `binding.json`: context/inventory/receipt commitments, intake policy and blocked
  clients, fixed before scoring;
- `scoring-state.json`: trust-eligible clients, clients actually scored, ordered
  bundle commitments, collective indicators, calibration and numerical state;
- `manifest.json`: one final disposition per submission, decision references,
  weights, checkpoint or failed-round outcome, and typed nodes/edges.

The new signed cores include protocol domains and versions. Finite numerical
measurements are represented explicitly as binary-float hexadecimal strings,
not silently serialized into the integer-only canonical profile.

The scoring state distinguishes eligible clients from actual computation. If
the candidate quorum is not met, scoring is skipped. A synthetic disagreement
contract is referenced separately: its effective trust intervention is not
confused with original trust eligibility.

Final dispositions distinguish `runtime_admission`, linked to the existing
recomputed trust/policy decision, and `protocol_rejection`, which has its own
negative result without inventing a training decision or payload.

## Numerical interpretation

For a valid checkpoint, the manifest records n*a as a decimal mass and the
normalized mathematical coefficient as reduced integer numerator/denominator.
It also records the binary weights actually passed to the aggregator, input
order, their binary sum, backend source fingerprint and environment versions.
The project implementation fingerprint covers all Python files in the package.

The verifier reruns the same multiply/sum/divide backend on the verified tensors
and compares the serialized checkpoint. It does not replace the computation
with a differently rounded sum of normalized coefficients. A changed coefficient
must be detected even if identical updates leave the checkpoint bytes unchanged.

The graph distinguishes numeric, decision and audit edges. A zero-weight input
can still have a path through scoring and another client's decision to the
checkpoint. This is structural dependence; actual counterfactual changes are a
separate experiment. The final disposition documents the produced outcome and
does not pretend to be an input file consumed before its own creation.

## Failed rounds and retries

When contributing quorum is lost, the manifest records
`round_status=failed_without_checkpoint`. No checkpoint is fabricated and all
normalized coefficients are undefined (`null`). Eligibility, skipped/computed
scoring, decisions and rejection evidence remain verifiable.

The verifier can return `status=verified` for a correctly documented failed
round. That means the failure evidence is valid; it does not mean training may
advance using a nonexistent checkpoint. Check `round_status` as well as status.

Successful and failed closed-round retries verify existing artifacts without
re-signing or rewriting their bytes. An incomplete artifact set fails closed;
it is not silently certified as a complete derivation.

## Scope of verification

A successful full report has `verification_scope=receipt_bound_round_derivation`
and `admission_decisions_verified=true`. Per-property statuses distinguish
verified, failed, insufficient evidence, not checked and coefficients undefined
without a checkpoint. Compatibility booleans are retained.

Delivery and deadline remain `not_checked`: client commitments and the supplied
evidence set do not independently witness coordinator delivery or registration
time. Enrollment, valid signatures and existing round attestation are checked
under the existing trust contract; no new physical TPM campaign is claimed.

Use `m5-verify-round-derivation`, or `m5-verify-composite-round` with
`--require-derivation`, whenever full derivation is required. Missing binding or
manifest must fail that request. If all extension artifacts are removed, an old
verifier invocation without an explicit profile requirement can only check
legacy claims; it does not establish a new full-derivation guarantee. Declare
the required profile in the experiment protocol, outside coordinator-controlled
artifact discovery.

Existing checkpoint schemas are unchanged. Published historical implementations
and the two identified pre-derivation versions are separately allowlisted, with
their original scope. Historical artifacts are never upgraded by the presence
of new code. A bound single round currently needs its external receipts passed
to verification; campaign-runner propagation and final preservation integration
remain part of the multiround increment.

## Validation requirements

Run the signed multi-client fixture tests, adversarial tests with coherent
coordinator re-signing, and regression suite. Validate the real aggregation
backend separately from controlled scoring fixtures. Retain all results and
label software keys/quotes and controlled validation honestly. Predictive
accuracy, DBA, external generalization and multiround causal effects require
their subsequent experiments.
