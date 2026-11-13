# UWF-ZeekData24 dataset protocol

## Role in the experiments

UWF-ZeekData24 is the development dataset for the centralized baseline, clean federated
learning, secure campaign, robustness experiments, and investigation chain. The canonical
M2-to-M8 reference uses the publisher's Parquet release and `configs/m2-parquet.yaml`.

An earlier CSV profile remains supported for controlled-ingestion and preprocessing studies.
CSV and Parquet workspaces have different row coverage and reference metrics; they must never
share an experiment identifier or be combined silently.

UWF-ZeekData22 is not mixed into training, validation, or test selection. It is reserved for
a future external-generalization experiment.

## Official source and license

- [Dataset portal](https://datasets.uwf.edu/)
- [CSV index](https://datasets.uwf.edu/data/UWF-ZeekData24/csv/)
- [Parquet index](https://datasets.uwf.edu/data/UWF-ZeekData24/parquet/)
- M. Elam et al., [“Introducing UWF-ZeekData24: An Enterprise MITRE ATT&CK Labeled
  Network Attack Traffic Dataset for Machine Learning/AI”](https://doi.org/10.3390/data10050059),
  *Data* 10(5), 59 (2025)
- License reported by the publisher: CC BY 4.0

The project records the bytes it downloads, but does not redistribute the dataset or assert
authenticity of the historical capture performed by UWF.

## Controlled-ingestion boundary

Downloaded objects are written under `data/raw/uwf-zeekdata24/`, which is excluded from Git.
Each downloader creates `download_manifest.json` with source URL, byte count, SHA-256 digest,
and the controlled-ingestion timestamp. Verification re-hashes local files and preserves the
original ingestion identity when bytes are unchanged.

These values establish what this experiment received. They do not prove that upstream
collection, labeling, or publication was free from error.

### Canonical Parquet download

```bash
python scripts/download_uwf_zeekdata24_parquet.py
```

To validate existing source objects without downloading them again:

```bash
python scripts/download_uwf_zeekdata24_parquet.py --verify-only
```

The canonical manifest covers seven Parquet partitions, 1,916,757 source rows, and 1,897,812
unique event identities after consolidation.

### Alternate CSV download

```bash
python scripts/download_uwf_zeekdata24.py
python scripts/download_uwf_zeekdata24.py --verify-only
```

The CSV release contains eight tactic-oriented partitions and 95,871 rows in the audited
profile. Its smaller coverage and different serialization make its metrics unsuitable for a
direct same-experiment comparison with the Parquet reference.

## Audit

Create a source audit before preparing features:

```bash
fl-forensics m2-audit \
  --input data/raw/uwf-zeekdata24/parquet \
  --output artifacts/m2-data24-parquet-audit.json
```

The audit records:

- source manifest and per-file digests;
- schema, nulls, row counts, and temporal coverage;
- tactic, technique, binary-label, and CVE observations;
- exact duplicates and cross-label event identities;
- source-specific values that must not be silently normalized away.

The source exhibits an acquisition-time/class relationship: benign and attack records are not
uniformly distributed over the same capture periods. The protocol therefore never performs a
naive global random row split. Rare classes and multi-label identities are also retained as
material limitations in the artifacts and reports.

## Canonical M2 preparation

```bash
fl-forensics m2-prepare \
  --input data/raw/uwf-zeekdata24/parquet \
  --config configs/m2-parquet.yaml \
  --output artifacts/m2-data24-parquet

fl-forensics m2-verify --workspace artifacts/m2-data24-parquet
```

### Event identity and label consolidation

Label columns are excluded from the source-event identity. Rows that describe the same event
but carry different label observations are consolidated instead of being treated as
independent contradictory samples. All source paths, source-row references, tactic/technique
observations, and digests remain reachable through lineage.

A single normalized tactic retains its class. Multiple attack tactics become `multi_tactic`.
Literal source values that are not valid ATT&CK identifiers remain visible in audit and
lineage; they are not upgraded into technique claims.

### Feature windows

The canonical snapshot aggregates normalized events into deterministic 60-second windows
using a frozen 25-feature schema. The workspace separates:

- `normalized_events.jsonl`: normalized event layer;
- `lineage.jsonl`: source-to-event-to-window relations;
- `feature_schema.json`: ordered feature contract;
- split feature/label arrays: model inputs only;
- `training_sampling.json`: declared training-only sampling policy;
- `scaler.json`: parameters fitted from training windows only;
- `manifest.json`: digests and upstream bindings.

Client partitions receive scaled features, labels, and identifiers—not raw source records or
normalized events.

### Split policy

The split unit is a UTC capture date, never an individual row or window. Dates remain
indivisible to reduce direct temporal leakage. The final capture period beginning on
3 November 2024 is reserved as `temporal_holdout`; it is benign-only in the reference release
and is reported separately from the multiclass development test.

Before the frozen training-sampling policy, the canonical Parquet preparation yields 22,951
windows. The retained reference snapshot contains 19,576 windows:

| Split | Windows | Role |
|---|---:|---|
| Train | 7,096 | Fitting model, scaler, weights, and training-only explanation references |
| Validation | 3,223 | Round/hyperparameter selection |
| Development test | 4,937 | Final internal multiclass evaluation after selection |
| Temporal holdout | 4,320 | Benign-only temporal behavior check |

The verifier enforces disjoint window/capture assignments, training-only fitting provenance,
schema order, direct file digests, and lineage consistency.

## Centralized baseline

```bash
fl-forensics m2-train \
  --workspace artifacts/m2-data24-parquet \
  --output artifacts/m2-data24-parquet-central

fl-forensics m2-verify-baseline \
  --workspace artifacts/m2-data24-parquet-central \
  --dataset-workspace artifacts/m2-data24-parquet
```

The model uses a 25-dimensional input, encoder layers 128 and 64, a 32-dimensional embedding,
and a six-class head. The canonical Parquet run reached:

| Evaluation | Reference result |
|---|---:|
| Validation macro-F1 | `0.9456743899420609` |
| Development-test macro-F1 | `0.9230727893604583` |
| Temporal-holdout accuracy | `0.9986111111111111` |

The temporal holdout contains only benign examples, so its accuracy/benign recall is a narrow
drift check. It is not a six-class performance estimate and must not be compared to the test
macro-F1 as if it were one.

## Reproducibility and contamination rules

- Never change source bytes, configuration, or package versions under an existing workspace
  identifier.
- Never fit the scaler, class weighting, prototype baseline, or explanation baseline with
  validation/test/holdout data.
- Never use the development test to choose a training round, lambda, or aggregation defense.
- Preserve lineage when consolidating events; deduplication is not permission to discard
  conflicting label observations.
- Report class support and per-class metrics because the class distribution is strongly
  imbalanced.
- Keep CSV and Parquet results labeled as separate source profiles.
- Do not interpret the benign-only temporal holdout as external generalization.

The M8 preservation manifest binds the canonical Parquet workspace and its required M2 files,
so any later byte change is detected by inventory, Merkle, recovery, and final verification.
