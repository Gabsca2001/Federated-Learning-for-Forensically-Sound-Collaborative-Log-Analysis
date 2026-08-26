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
ties. Test, temporal-holdout, and client-local test rows are evaluated only
after this selection. The round containers receive only each client's
`clients/<client_id>/dataset.json`, which contains train and validation; the
separate `evaluation/clients/<client_id>/test.json` is not mounted for training.
The coordinator likewise reads `server/splits/validation.json` while examining
rounds and does not open the isolated server test or temporal-holdout artifacts
until selection is complete. Independent verification repeats inference to
validate the preserved result. No test data can choose a round, update a model,
or change hyperparameters.

When the M3 partition includes the local-test contract, the selected global
checkpoint is evaluated on every client-local domain. The per-client metrics and
client-unweighted mean, population standard deviation, minimum, and maximum are
included in the final evaluation committed by the coordinator signature.
The coordinator also verifies that their disjoint union exactly reconstructs
the server test split and rejects paths that escape the evaluation boundary.

The final coordinator-signed campaign manifest commits to:

- 30 ordered round contexts and checkpoints;
- 450 accepted contributions (`30 × 15`);
- every per-round validation artifact;
- the selected checkpoint and global model;
- the selected-checkpoint validation, pooled test, temporal-holdout, and, when
  available, per-client local-test evaluation.

## Fresh M4 state

The measured source list changes in this extension. Recreate the M4 trust
workspace and provision a new Compose namespace only after the implementation
and unit tests are final. Do not delete an older namespace if it is needed as
preserved evidence.

```bash
export COMPOSE_PROJECT_NAME=flforensics_local_test_v1
export M4_TRUST_WORKSPACE="$PWD/artifacts/m4-trust-local-test-v1"
export M4_NODE_ROOT="$PWD/artifacts/m4-nodes-local-test-v1"

python scripts/run_m5_secure_round.py build \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1

fl-forensics m4-init \
  --workspace "$M4_TRUST_WORKSPACE" \
  --project-root .

python scripts/run_m4_swtpm.py provision \
  --trust-workspace "$M4_TRUST_WORKSPACE" \
  --node-root "$M4_NODE_ROOT"

fl-forensics m4-enroll \
  --workspace "$M4_TRUST_WORKSPACE" \
  --node-root "$M4_NODE_ROOT"

fl-forensics m4-mtls-test \
  --workspace "$M4_TRUST_WORKSPACE" \
  --node-root "$M4_NODE_ROOT"
```

The multi-round runner issues fresh M4 challenges and Quote evidence before
round 1 and then every five rounds by default. Custom `--trust-workspace` and
`--node-root` values are passed to both the Quote producer and verifier. The
runner never deletes volumes or starts a missing TPM service.

## Run or resume

```bash
python scripts/run_m5_secure_multiround.py run \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --workspace artifacts/m5-secure-multiround-local-test-v1 \
  --trust-workspace "$M4_TRUST_WORKSPACE" \
  --node-root "$M4_NODE_ROOT" \
  --rounds 30 \
  --workers 4 \
  --attestation-refresh-interval 5
```

The runner is resumable. Completed checkpoints are independently verified and
skipped. Byte-identical client submissions are idempotent. A context that has
expired during an incomplete round must not be silently rewritten; preserve
it for diagnosis and restart that round in a new campaign workspace.

The round coordinator is not mounted with the server test, temporal holdout,
or client-local test snapshots. After all round checkpoints have been written,
the runner starts a separate network-disabled `finalizer` container. Only that
container receives read-only mounts for the digest-bound evaluation snapshots,
selects the checkpoint from stored validation metrics, and then evaluates the
already-selected model on the isolated test material.

Verify an already finalized campaign with:

```bash
python scripts/run_m5_secure_multiround.py verify \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --workspace artifacts/m5-secure-multiround-local-test-v1 \
  --trust-workspace "$M4_TRUST_WORKSPACE" \
  --node-root "$M4_NODE_ROOT" \
  --rounds 30
```

The acceptance result must report `status: verified`, `round_count: 30`,
`accepted_contribution_count: 450`, no errors, and one validation-selected
checkpoint.

## Learning diagnostics

After campaign verification:

```bash
python scripts/m5_campaign_report.py \
  --workspace artifacts/m5-secure-multiround-local-test-v1 \
  --trust-workspace "$M4_TRUST_WORKSPACE" \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --output artifacts/m5-secure-multiround-local-test-v1-report
```

The report contains global validation curves, client train/validation loss and
macro-F1 across all local epochs, per-client validation and update-norm
heatmaps, absolute and normalized selected validation/test/benign-only-holdout
confusion matrices, one selected-checkpoint local-test confusion figure per
client, a CSV export, and a SHA-256 report manifest. Campaign finalization,
campaign verification, and the report command also print the three global
matrices in their JSON output. The report refuses to run unless the whole secure
campaign verifies, and its manifest covers files in nested per-client folders.

## Completed runtime gate

The 15-client Docker campaign completed on the verified IID Parquet snapshot
with the current local-test reference result. Every client passed its `swtpm`
appraisal before contributing. Training and validation completed before the
validation-selected checkpoint opened the pooled test, benign-only temporal
holdout, or isolated per-client test snapshots. This workspace and its M7
derivatives are preserved by the current M8 recovery package. Historical
reference workspaces remain immutable and separately verifiable.

- campaign ID: `campaign-aa22aafea800a7d59fe308fc`;
- 30 verified rounds and 450 accepted TPM ESK-signed contributions;
- zero quarantined contributions and zero campaign-verification errors;
- validation-selected checkpoint: round 11;
- selected validation macro-F1: `0.9483333731727267`;
- selected test macro-F1: `0.9225672285470168`;
- benign-only temporal-holdout accuracy: `0.9958333333333333`;
- client-local test macro-F1, unweighted mean: `0.9284429268218769`;
- client-local test macro-F1, population standard deviation: `0.03533358666804803`;
- worst client-local test macro-F1: `0.8763479758828595`;
- campaign manifest SHA-256:
  `6a372239c3877dd2abd18b5671b856f00b6c20b8376beeee258b1d8e39d4fb8f`;
- report manifest SHA-256:
  `082baafe3008baa73da2e83e15df803fc3893feeae750fa9472720a249fcb8f4`.

The selected secure checkpoint reproduces the validation and test metrics of
the validation-selected clean M3 IID reference. This demonstrates that the M5
signature, admission, replay, attestation, and checkpoint-chain controls did
not change the deterministic FedAvg learning result. The temporal holdout is
benign-only, so its multiclass macro-F1 is not interpreted as a six-class
generalization score.
