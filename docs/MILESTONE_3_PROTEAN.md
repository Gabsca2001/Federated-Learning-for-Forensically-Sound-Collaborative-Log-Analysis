# Milestone 3 extension — auditable PROTEAN evaluation

## Scope and claim boundary

This workflow evaluates a prototype-guided federated adaptation inspired by PROTEAN on the
frozen UWF-ZeekData24 non-IID partition. The implementation is explicitly identified in
`configs/federation-protean.yaml` as `auditable-protean-adaptation`; it is not claimed to be an
exact reproduction of the referenced paper.

The purpose is twofold:

1. measure prototype-guided learning under the same client heterogeneity used by the clean
   FedAvg reference;
2. make hyperparameter selection and final test access forensically auditable.

The FedAvg control remains an immutable, independently verified workspace. PROTEAN does not
rewrite or replace the M3 baseline.

## Frozen experimental contract

| Property | Value |
|---|---|
| Dataset | Canonical UWF-ZeekData24 Parquet snapshot |
| Partition | 15-client non-IID profile, Dirichlet `alpha = 0.3` |
| Rounds | 30 |
| Participation | 15/15 clients each round |
| Local epochs | 2 |
| Batch size | 128 |
| Optimizer | Adam, learning rate `0.001` |
| Seed | `341593` |
| Encoder | `25 → 128 → 64 → 32` |
| Classes | 6 |
| Prototype alignment candidates | `0.001`, `0.01`, `0.1`, `1.0` |
| Proximal parameter weight | `0.1` |
| Prototype minimum local support | 5 |
| Class quorum | 3 clients |
| Selection split | Validation only |
| Selection metric | Macro-F1 over all model classes |
| Candidate tie-breaker | Smallest alignment weight |
| Round tie-breaker | Earliest round |

The local objective combines weighted multiclass cross-entropy, squared Euclidean alignment
to the global class prototype, and squared-L2 proximity to the round's base model. Local class
prototypes are preserved with their support and bound to client, snapshot, model, and round.

The first round does not use prototype alignment because no previous global prototype exists.
Subsequent global prototypes use support-weighted aggregation subject to the declared quorum.
A coordinate-median prototype aggregation is retained as the robust reference profile.

## Inputs

The canonical run uses:

- dataset: `artifacts/m2-data24-parquet`;
- non-IID partitions: `artifacts/m3-data24-parquet-non-iid`;
- FedAvg control: `artifacts/m3-data24-parquet-non-iid-selected-cuda-run`;
- configuration: `configs/federation-protean.yaml`.

The partition, seed, model shape, round count, local epochs, optimizer, and participation
policy are held constant against the control. This does not make the two learning algorithms
identical; it makes their declared experimental inputs comparable.

## Candidate generation and verification

Run one isolated candidate per alignment weight:

```bash
fl-forensics m3-protean-train \
  --partition-workspace artifacts/m3-data24-parquet-non-iid \
  --dataset-workspace artifacts/m2-data24-parquet \
  --prototype-alignment-weight 0.001 \
  --output artifacts/m3-protean-noniid-lambda-0p001-v1

fl-forensics m3-protean-train \
  --partition-workspace artifacts/m3-data24-parquet-non-iid \
  --dataset-workspace artifacts/m2-data24-parquet \
  --prototype-alignment-weight 0.01 \
  --output artifacts/m3-protean-noniid-lambda-0p01-v1

fl-forensics m3-protean-train \
  --partition-workspace artifacts/m3-data24-parquet-non-iid \
  --dataset-workspace artifacts/m2-data24-parquet \
  --prototype-alignment-weight 0.1 \
  --output artifacts/m3-protean-noniid-lambda-0p1-v1

fl-forensics m3-protean-train \
  --partition-workspace artifacts/m3-data24-parquet-non-iid \
  --dataset-workspace artifacts/m2-data24-parquet \
  --prototype-alignment-weight 1.0 \
  --output artifacts/m3-protean-noniid-lambda-1p0-v1
```

Each workspace is checked without reading the test split:

```bash
fl-forensics m3-protean-verify \
  --workspace artifacts/m3-protean-noniid-lambda-0p01-v1 \
  --partition-workspace artifacts/m3-data24-parquet-non-iid \
  --dataset-workspace artifacts/m2-data24-parquet
```

Repeat verification for every candidate. The verifier checks the upstream dataset and
partition bindings, candidate value, round/prototype chains, local supports, aggregation,
metrics, and the absence of prohibited final-split access.

## Validation report and pre-test lock

The reporting command receives all four candidate workspaces plus the FedAvg control. It
selects and plots using validation evidence only:

```bash
fl-forensics m3-protean-report \
  --candidate-workspace artifacts/m3-protean-noniid-lambda-0p001-v1 \
  --candidate-workspace artifacts/m3-protean-noniid-lambda-0p01-v1 \
  --candidate-workspace artifacts/m3-protean-noniid-lambda-0p1-v1 \
  --candidate-workspace artifacts/m3-protean-noniid-lambda-1p0-v1 \
  --fedavg-workspace artifacts/m3-data24-parquet-non-iid-selected-cuda-run \
  --output artifacts/m3-protean-noniid-validation-report-v1
```

After verifying that report, `m3-protean-lock` freezes two predeclared endpoints:

- **paper-faithful endpoint:** nearest-global-prototype inference;
- **operational endpoint:** the jointly trained classification head.

The lock records the selected candidate and round for each endpoint before test or temporal
holdout metrics are released. `m3-protean-verify-lock` reconstructs that decision from the
candidate and validation-report workspaces.

## Finalization

`m3-protean-finalize` evaluates the two locked endpoints once on the final splits and writes
`artifacts/m3-protean-noniid-final-evaluation-v1`. The final verifier does not rerun model
inference; it verifies the immutable candidates, report, lock, final metrics, and the statement
that no selection changed after test access.

## Reference results

| Endpoint | Alignment weight | Selected round | Test macro-F1 | Temporal-holdout accuracy |
|---|---:|---:|---:|---:|
| Nearest global prototype | `0.01` | 28 | `0.874721460920355` | `0.9990740740740741` |
| Classification head | `0.1` | 30 | `0.9569839083978439` | `0.9837962962962963` |
| FedAvg non-IID control | — | 28 | `0.9438490774173682` | `0.9805555555555555` |

These endpoints answer different questions. The nearest-prototype result is closer to the
prototype classifier under study; the classification-head result is the stronger operational
classifier in this reference run. Reporting both prevents a post-hoc switch between
classifiers from being hidden.

The temporal holdout is benign-only, so its accuracy is not a multiclass generalization
metric. The results are also one deterministic seed and do not establish uncertainty across
training repetitions.

## Preserved evidence

The complete workflow preserves:

- local model updates and per-class prototypes for every client/round;
- prototype support and quorum decisions;
- global model and prototype checkpoints with chained round records;
- classification-head and nearest-prototype validation metrics;
- per-client/per-class metrics and prototype communication volume;
- candidate manifests and verifier results;
- deterministic report data and figures;
- pre-test selection lock;
- final test/holdout evaluation and verification receipt.

The final claim is therefore not merely “PROTEAN obtained a score.” It is that the declared
candidate set was run over the frozen non-IID data contract, selected without test access,
locked, evaluated once, and preserved with independently checkable lineage.
