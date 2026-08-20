# Milestone 5 — secure multi-round campaign

## Scope

This extension turns the independently verified M5 round into a complete
30-round learning campaign. It does not replace the single-round acceptance
gate. Each round retains the same 15-client attestation, ESK signature,
admission, replay, tensor-validation, checkpoint-input, and independent FedAvg
checks.

Round 1 starts from the deterministic random model defined by
`configs/federation.yaml`. Round `r > 1` can start only when the previous
checkpoint:

- is signed by the same campaign coordinator;
- belongs to the same campaign and round `r - 1`;
- contains all 15 accepted inputs and no quarantined input;
- commits to the exact global-model bytes used as round `r` base model.

The new signed context contains the SHA-256 digest of the previous checkpoint.
Consequently, every accepted bundle is transitively linked to all earlier
checkpoints while still binding its own round, client, snapshot, attestation,
base model, metrics, and tensor update.

## Evaluation boundary

Every global checkpoint is evaluated on the server validation snapshot. The
highest validation macro-F1 is selected, with the earliest round used to break
ties. Test and temporal-holdout rows are evaluated only after this selection.
Independent verification repeats inference to validate the preserved result;
test data is never used to choose a round or change hyperparameters.

The final coordinator-signed campaign manifest commits to:

- 30 ordered round contexts and checkpoints;
- 450 accepted contributions (`30 × 15`);
- every per-round validation artifact;
- the selected checkpoint and global model;
- the selected-checkpoint validation, test, and temporal-holdout evaluation.

## Fresh M4 state

The measured source list changes in this extension. Recreate the M4 trust
workspace and provision a new Compose namespace only after the implementation
and unit tests are final. Do not delete an older namespace if it is needed as
preserved evidence.

```bash
export COMPOSE_PROJECT_NAME=flforensics_m5_multiround

python scripts/run_m5_secure_round.py build \
  --partition-workspace artifacts/m3-data24-parquet-iid

fl-forensics m4-init \
  --workspace artifacts/m4-trust \
  --project-root .

python scripts/run_m4_swtpm.py provision

fl-forensics m4-enroll \
  --workspace artifacts/m4-trust \
  --node-root artifacts/m4-nodes

fl-forensics m4-mtls-test \
  --workspace artifacts/m4-trust \
  --node-root artifacts/m4-nodes
```

The multi-round runner issues fresh M4 challenges and Quote evidence before
round 1 and then every five rounds by default. It never deletes volumes or
starts a missing TPM service.

## Run or resume

```bash
python scripts/run_m5_secure_multiround.py run \
  --partition-workspace artifacts/m3-data24-parquet-iid \
  --workspace artifacts/m5-secure-multiround \
  --rounds 30 \
  --workers 4 \
  --attestation-refresh-interval 5
```

The runner is resumable. Completed checkpoints are independently verified and
skipped. Byte-identical client submissions are idempotent. A context that has
expired during an incomplete round must not be silently rewritten; preserve
it for diagnosis and restart that round in a new campaign workspace.

Verify an already finalized campaign with:

```bash
python scripts/run_m5_secure_multiround.py verify \
  --partition-workspace artifacts/m3-data24-parquet-iid \
  --workspace artifacts/m5-secure-multiround \
  --rounds 30
```

The acceptance result must report `status: verified`, `round_count: 30`,
`accepted_contribution_count: 450`, no errors, and one validation-selected
checkpoint.

## Learning diagnostics

After campaign verification:

```bash
python scripts/m5_campaign_report.py \
  --workspace artifacts/m5-secure-multiround \
  --trust-workspace artifacts/m4-trust \
  --partition-workspace artifacts/m3-data24-parquet-iid \
  --output artifacts/m5-secure-multiround-report
```

The report contains global validation curves, client train/validation loss and
macro-F1 across all local epochs, per-client validation and update-norm
heatmaps, selected validation/test confusion matrices, a CSV export, and a
SHA-256 report manifest. The report refuses to run unless the whole secure
campaign verifies.
