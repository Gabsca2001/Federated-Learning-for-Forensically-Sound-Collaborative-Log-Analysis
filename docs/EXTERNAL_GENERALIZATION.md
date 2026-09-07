# External UWF-ZeekData22 generalization

## Purpose

This experiment tests the already selected secure Data24 checkpoint on a genuinely separate
dataset. UWF-ZeekData22 is never made available to training, validation, round selection,
hyperparameter selection, or threshold selection. The selected model remains round 11 of the
verified 30-round M5 reference campaign.

The source is the University of West Florida's official
[UWF-ZeekData22 CSV directory](https://datasets.uwf.edu/data/UWF-ZeekData22/csv/). The publisher
describes this CSV release as a smaller subset of the full Parquet dataset. It contains benign
traffic plus Reconnaissance and Discovery attacks; it must not be described as full Data22
tactic coverage. See the publisher's [dataset card](https://datasets.uwf.edu/) and the
[original dataset paper](https://doi.org/10.3390/data8010018).

## Why the result has two views

The frozen Data24 model predicts these six labels:

`benign`, `credential_access`, `exfiltration`, `initial_access`, `multi_tactic`, and
`reconnaissance`.

Data22 also contains `discovery`, which is not a model output. Mapping Discovery silently to a
different tactic would make the result misleading. The evaluator therefore produces:

1. an all-window binary result, where every non-benign truth and prediction is collapsed to
   `attack`;
2. a strict shared-label result on actual `benign` and `reconnaissance` windows only, with all
   six model predictions retained as columns;
3. explicit row coverage and the list of external labels outside the fixed model label space.

The binary view asks whether the frozen model detects attack-like traffic. The shared-label
view asks whether it transfers on labels that really exist in both datasets. Neither changes
the trained classification head.

## Reproducible workflow

Download the five official CSV files and create a controlled-ingestion manifest. The first
run records every file size and SHA-256; later runs refuse a byte mismatch.

```bash
python scripts/download_uwf_zeekdata22_csv.py \
  --output data/raw/uwf-zeekdata22/csv

python scripts/download_uwf_zeekdata22_csv.py \
  --output data/raw/uwf-zeekdata22/csv \
  --verify-only
```

Build and independently reconstruct the unscaled 25-feature external snapshot:

```bash
fl-forensics m5-prepare-external-data \
  --input data/raw/uwf-zeekdata22/csv \
  --config configs/external-generalization.yaml \
  --output artifacts/m5-data22-external-v1

fl-forensics m5-verify-external-data \
  --input data/raw/uwf-zeekdata22/csv \
  --config configs/external-generalization.yaml \
  --workspace artifacts/m5-data22-external-v1
```

Evaluate the checkpoint only after the Data22 snapshot, the Data24 training snapshot, and the
complete signed M5 selection chain verify:

```bash
fl-forensics m5-evaluate-external \
  --external-workspace artifacts/m5-data22-external-v1 \
  --campaign-workspace artifacts/m5-secure-multiround-local-test-v1 \
  --trust-workspace artifacts/m4-trust-local-test-v1 \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --dataset-workspace artifacts/m2-data24-parquet \
  --config configs/external-generalization.yaml \
  --output artifacts/m5-external-generalization-local-test-v1

fl-forensics m5-verify-external \
  --workspace artifacts/m5-external-generalization-local-test-v1 \
  --external-workspace artifacts/m5-data22-external-v1 \
  --input data/raw/uwf-zeekdata22/csv \
  --campaign-workspace artifacts/m5-secure-multiround-local-test-v1 \
  --trust-workspace artifacts/m4-trust-local-test-v1 \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --dataset-workspace artifacts/m2-data24-parquet \
  --config configs/external-generalization.yaml
```

Run the separate Discovery alignment-sensitivity experiment without changing the primary
configuration or workspace:

```bash
fl-forensics m5-stress-discovery \
  --primary-workspace artifacts/m5-external-generalization-local-test-v1 \
  --external-workspace artifacts/m5-data22-external-v1 \
  --input data/raw/uwf-zeekdata22/csv \
  --campaign-workspace artifacts/m5-secure-multiround-local-test-v1 \
  --trust-workspace artifacts/m4-trust-local-test-v1 \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --dataset-workspace artifacts/m2-data24-parquet \
  --primary-config configs/external-generalization.yaml \
  --config configs/discovery-stress.yaml \
  --output artifacts/m5-discovery-stress-local-test-v1

fl-forensics m5-verify-discovery-stress \
  --workspace artifacts/m5-discovery-stress-local-test-v1 \
  --primary-workspace artifacts/m5-external-generalization-local-test-v1 \
  --external-workspace artifacts/m5-data22-external-v1 \
  --input data/raw/uwf-zeekdata22/csv \
  --campaign-workspace artifacts/m5-secure-multiround-local-test-v1 \
  --trust-workspace artifacts/m4-trust-local-test-v1 \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --dataset-workspace artifacts/m2-data24-parquet \
  --primary-config configs/external-generalization.yaml \
  --config configs/discovery-stress.yaml
```

## Verified reference result

The controlled CSV ingestion reconstructed 2,044,734 source records into 1,100,574 unique
events and 10,128 windows: 10,018 benign, 107 reconnaissance, and three Discovery windows.
The frozen round-11 checkpoint produced:

- binary attack precision `0.2068965517`, recall `0.0545454545`, and F1 `0.0863309353`;
- binary balanced accuracy `0.5261247936` and benign specificity `0.9977041326`;
- shared-label macro-F1 `0.4968434657`;
- reconnaissance precision, recall, and F1 all equal to zero;
- an absolute scaled feature value above five in `0.9997037915` of external rows.

The high overall accuracy (`0.9874605055`) is therefore not evidence of useful attack
detection: it is dominated by benign support. The model predicts 10,099 windows as benign and
29 as `multi_tactic`, and recognizes only six of 110 attack windows after binary collapse.

The Discovery source contains 2,086 events in two temporal bursts, not three independent
episodes. Across 12 correlated offsets of the unchanged 60-second window, at least one segment
from each burst is classified non-benign in all 24 burst-offset trials. Every segment is
non-benign in 19/24 trials: 7/12 for the longer first burst and 12/12 for the compact second
burst. The zero-offset predictions reproduce the three primary windows exactly. These offset
trials reuse events and are descriptive sensitivity measurements, not independent samples.

## Artifact contract

`artifacts/m5-data22-external-v1/` contains the source audit, unscaled feature windows,
compact per-window lineage, feature schema, and manifest. Exact duplicate connection
identities are consolidated before windowing. Labels attached to the same connection identity
are unioned; multiple attack labels in one window become `multi_tactic`.

`artifacts/m5-external-generalization-local-test-v1/` contains:

- `metrics.json`: binary, shared-label, label-space coverage, prediction distribution, and
  feature-shift summaries;
- `predictions.jsonl`: one sanitized prediction record per external window;
- `manifest.json`: digests of the Data22 snapshot, Data24 scaler, partition, signed campaign,
  selected model, configuration, metrics, predictions, and implementation.

`artifacts/m5-discovery-stress-local-test-v1/` contains the two-burst definition, 12-offset
trial summary, target-window predictions, and a manifest bound to the immutable primary
evaluation. Its verifier reconstructs source events, windows, scaler application, predictions,
summary, primary zero-offset equality, and implementation binding.

The small Git-tracked snapshot under
`results/m5-external-generalization-local-test-v1/` publishes metrics, the Discovery summary,
two figures, a compact trial CSV, and verification receipts. Raw records, models, per-window
predictions, and trust material remain outside Git.

The final verifier reconstructs the Data22 snapshot from the controlled CSV files, re-verifies
the secure M5 campaign and its validation-only selection, reapplies the Data24 training-only
scaler, reruns inference, and compares predictions and metrics byte for byte.

## Claim boundary

This is a cross-dataset result for one frozen checkpoint and the publisher's limited CSV
subset. It demonstrates poor transfer for this frozen checkpoint; it does not demonstrate
open-set Discovery classification, full Data22 tactic coverage, calibrated uncertainty, or
universal deployment generalization. The Discovery stress has only two independent bursts and
cannot support confidence intervals or a population recall claim. Any adaptation based on
Data22 must receive a new experiment identifier and a new untouched final evaluation source.
