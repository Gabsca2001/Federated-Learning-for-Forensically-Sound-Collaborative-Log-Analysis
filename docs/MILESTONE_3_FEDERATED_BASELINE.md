# Milestone 3 — federated baseline contract

## Scope

M3 establishes the clean federated reference before trust-gated execution, malicious updates,
or robust aggregation. It uses the verified UWF-ZeekData24 M2 snapshot and does not alter its
features, splits, scaler, sampling policy, labels, or lineage.

The baseline has 15 logical clients, 100% participation, 30 FedAvg rounds, two local epochs
per round, batch size 128, Adam at learning rate `0.001`, and seed `341593`. The PyTorch model
is `25 → 128 → 64 → 32 → 6`, matching the M2 encoder/head shape while changing the training
backend from scikit-learn to PyTorch.

The canonical reference workspaces use the M2 Parquet profile:

- `artifacts/m2-data24-parquet`;
- `artifacts/m3-data24-parquet-iid-local-test-v1`;
- `artifacts/m3-data24-parquet-non-iid`.

## Partition profiles

### IID

The IID profile applies deterministic stratified round-robin allocation within each training
class. In the canonical snapshot, each client receives 473 or 474 training windows.

### Non-IID

The non-IID profile draws per-class client proportions from a Dirichlet distribution with
`alpha = 0.3`. It retries deterministically until every client has at least 32 training
windows and records the final distribution. Canonical client sizes range from 52 to 1,688
training windows.

Validation windows use the same stratified IID policy in both profiles so local validation is
comparable. Test windows are partitioned separately in proportion to each client's
training-class profile. This produces an approximately IID local test for IID clients and a
domain-matched local test for non-IID clients. Every train, validation, and local-test window
appears in exactly one client allocation for its split.

The training artifact `clients/<client_id>/dataset.json` contains only scaled train and
validation feature windows. The evaluation-only artifact
`evaluation/clients/<client_id>/test.json` has its own SHA-256 binding and is never mounted as
a training snapshot. Neither artifact contains raw source rows, normalized Zeek events,
source-line digests, or event-level lineage. The server artifact retains the complete scaled
validation, development-test, and temporal-holdout sets for compatibility, while separately
digest-bound `server/splits/*.json` artifacts enforce split-specific runtime access.

The separation enforces three roles:

1. local train updates model parameters;
2. validation measures rounds, evaluates local-only models, and chooses the checkpoint;
3. all model training finishes;
4. global and client-local tests are opened only afterward and never change a model.

The local-test partition is an evaluation view of the existing M2 test split, not additional
data. The union of all client-local tests is exactly the complete server test, with no overlap
or omitted window.

## Create and verify partitions

```bash
fl-forensics m3-partition \
  --dataset-workspace artifacts/m2-data24-parquet \
  --output artifacts/m3-data24-parquet-iid-local-test-v1 \
  --mode iid

fl-forensics m3-verify-partitions \
  --workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --dataset-workspace artifacts/m2-data24-parquet

fl-forensics m3-partition \
  --dataset-workspace artifacts/m2-data24-parquet \
  --output artifacts/m3-data24-parquet-non-iid \
  --mode non-iid

fl-forensics m3-verify-partitions \
  --workspace artifacts/m3-data24-parquet-non-iid \
  --dataset-workspace artifacts/m2-data24-parquet
```

The partition verifier reconstructs coverage from the M2 manifest, rejects overlap or missing
windows separately for train, validation, and local test, checks all direct digests, rejects a
test split embedded in any training snapshot, verifies the three isolated server splits, and
rejects artifact paths that escape their declared evaluation directories.

## Two execution paths

`fl_forensics.flower_client` and `fl_forensics.flower_server` implement Flower's Message API
using `ClientApp`, `ServerApp`, `ArrayRecord`, and `serverapp.strategy.FedAvg`. This is the
runtime-portability path used for 15-SuperNode simulation.

`fl-forensics m3-train` is the deterministic forensic runner. It calls the same PyTorch
training primitives and example-weighted FedAvg aggregation, but executes client jobs in a
stable order so every accepted input, local update, checkpoint, metric, and round relation can
be published before the next round.

For round `t`, every participating client receives the same global parameters `w_t`, performs
two local epochs, and returns parameters `w_(t+1,k)` plus its local training count `n_k`. The
server computes the standard example-weighted FedAvg update:

```text
w_(t+1) = sum_k (n_k / sum_j n_j) * w_(t+1,k)
```

All 15 clients participate in every reference round. Full participation is a valid synchronous
cross-silo FedAvg profile; partial client sampling is common in cross-device deployments but
is not required by the algorithm. Validation and test row counts are never aggregation
weights. The verifier reloads the preserved local updates and independently recomputes this
equation.

```bash
fl-forensics m3-train \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --dataset-workspace artifacts/m2-data24-parquet \
  --output artifacts/m3-data24-parquet-iid-fedavg

fl-forensics m3-verify \
  --workspace artifacts/m3-data24-parquet-iid-fedavg \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --dataset-workspace artifacts/m2-data24-parquet
```

Repeat with the non-IID partition workspace for the heterogeneity comparison. For the Flower
Simulation Runtime, install `.[federated,simulation,dev]` and run 15 SuperNodes:

```bash
flwr run . --stream \
  --federation-config="num-supernodes=15 client-resources-num-cpus=1"
```

WSL2/Linux is the supported environment for this runtime gate.

## Preserved artifacts and verification

Each client/round produces an update object containing the local model state and a record that
links it to the base global model and frozen client snapshot. Each round lists all 15 updates,
their example counts, aggregation policy, resulting checkpoint, evaluation metrics, and
previous round digest. Model/update payloads are content-addressed by SHA-256.

The verifier checks M2 and partition lineage, direct artifact hashes, update structures,
round order, and hash-chain continuity. It then reloads all 15 local updates for every round,
recomputes example-weighted FedAvg, and requires equality with the preserved global
checkpoint. It also reloads every retained local-only model, repeats its validation and test
inference, and reconstructs the client summary statistics.

## Selection and evaluation

The selected checkpoint maximizes validation macro-F1 across all model classes; ties choose
the earliest round. All separately trained local-only baselines are also completed using only
train and validation. Only after every training operation finishes does the runner load the
test, temporal-holdout, and client-local test artifacts. It evaluates:

- the selected FedAvg checkpoint on the complete pooled test;
- the selected FedAvg checkpoint on every client-local test;
- each separately trained local-only model on its own local test;
- each local-only model on the complete pooled test as a common-distribution comparison.

`comparison.json` reports client-unweighted mean, population standard deviation, minimum, and
maximum macro-F1. The pooled global-test metric answers population-level performance; the
client-unweighted distribution exposes cross-client dispersion and the worst observed client.
Neither result is used for checkpoint or hyperparameter selection.

| Profile | Selected round | Validation macro-F1 | Test macro-F1 |
|---|---:|---:|---:|
| IID FedAvg | 11 | `0.9483333731727267` | `0.9225672285470168` |
| Non-IID FedAvg | 28 | `0.9477167842802467` | `0.9438490774173682` |

These are deterministic reference runs, not confidence intervals across random seeds. The
benign-only temporal holdout is kept separate and is not reported as a multiclass score.

## Evaluation report

`m3-report` derives deterministic figures from preserved `metrics.json` and
`comparison.json`; it does not repeat training or inference. Both `m3-train` and `m3-report`
print the post-selection global confusion matrices in their final JSON output. The report
validates source digests before generating:

- absolute and row-normalized validation, test, and benign-only temporal-holdout confusion
  matrices;
- per-class precision, recall, F1, and support;
- validation macro-F1 and training-loss curves by round;
- local-only, FedAvg, and optional M2-central comparison;
- per-client selected-global and local-only test performance;
- one per-client local-test confusion figure containing absolute and normalized selected
  FedAvg matrices and, when available, the corresponding local-only matrices;
- client-unweighted local-test dispersion and worst-client performance;
- `summary.json` with input and figure SHA-256 values.

Global figures are written as `confusion-matrix-<split>.png` and
`confusion-matrix-<split>-normalized.png`. Client figures are written below
`per-client-confusion/`. Rows always represent actual classes and columns predicted classes.
The temporal holdout contains benign windows only and is labelled accordingly; its matrix is
an operational false-alarm view, not a six-class generalization result.

```bash
fl-forensics m3-report \
  --workspace artifacts/m3-data24-parquet-iid-selected-cuda-run \
  --central-workspace artifacts/m2-data24-parquet-central
```

## PROTEAN extension

The `m3-protean-*` workflow is a separate prototype-guided experiment on the same non-IID
partition. It preserves local/global class prototypes, evaluates four alignment weights using
validation only, locks the paper-faithful nearest-prototype and operational
classification-head endpoints before test access, and then finalizes both once.

See [Milestone 3 PROTEAN evaluation](MILESTONE_3_PROTEAN.md) for its contract, commands,
results, and claim boundary.

## Interpretation boundary

M3 measures centralized-versus-local/federated learning and clean IID/non-IID effects. It does
not sign Update Bundles, enforce TPM identity, establish secure round replay protection, or
simulate Byzantine clients. Those properties are introduced and verified by M4–M6 and must
not be inferred from M3 scores.
