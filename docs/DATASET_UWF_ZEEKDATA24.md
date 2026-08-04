# UWF-ZeekData24 dataset protocol

## Role in the experiments

UWF-ZeekData24 is the primary dataset for development, the centralized baseline, and the federated experiments. The official dataset name is `UWF-ZeekData24`; “UWF-ZeekData2024” is used only as a descriptive long form.

UWF-ZeekData22 is not mixed into training or internal validation. It is reserved for a later external-generalization experiment so that results on the 2024 data remain distinguishable from cross-dataset transfer results.

## Official source and license

- Dataset portal: https://datasets.uwf.edu/
- CSV index: https://datasets.uwf.edu/data/UWF-ZeekData24/csv/
- Parquet index: https://datasets.uwf.edu/data/UWF-ZeekData24/parquet/
- Reference paper: M. Elam et al., “Introducing UWF-ZeekData24: An Enterprise MITRE ATT&CK Labeled Network Attack Traffic Dataset for Machine Learning/AI,” *Data*, 2025, 10(5), 59. DOI: https://doi.org/10.3390/data10050059
- License reported by the publisher: CC BY 4.0.

## Repository policy

The dataset is never committed to Git. Files are downloaded into `data/raw/uwf-zeekdata24/csv/`, which is ignored by `.gitignore`. The downloader writes `download_manifest.json` containing the source URL, byte length, and SHA-256 digest of every downloaded object.

These digests establish the local controlled-ingestion boundary. They do not prove the authenticity of the original historical capture performed by UWF.

## M2 source release

Milestone M2 starts with the eight CSV partitions published by UWF:

- Benign
- Credential Access
- Defense Evasion
- Exfiltration
- Initial Access
- Persistence
- Privilege Escalation
- Reconnaissance

The CSV release is the frozen input of the M2 centralized baseline. It has 26 columns, including the Zeek connection fields and `label_tactic`, `label_technique`, `label_binary`, and `label_cve`. CSV and Parquet results must not be silently combined under the same experiment identifier.

## Download

From the repository root:

```powershell
python scripts/download_uwf_zeekdata24.py
```

To verify already downloaded files without downloading again:

```powershell
python scripts/download_uwf_zeekdata24.py --verify-only
```

The downloader preserves the first controlled-ingestion timestamp when `--verify-only` is run again. Re-verification therefore does not change the manifest identity when the downloaded bytes are unchanged.

## Reproducible audit

```powershell
fl-forensics m2-audit `
  --input data\raw\uwf-zeekdata24\csv `
  --output artifacts\m2-data24-audit.json
```

The official CSV release audited on 4 August 2026 contains 95,871 rows and 95,182 distinct connection identities after label columns are excluded from the identity key. The audit records the full schema, missing values, class and technique counts, date coverage, exact duplicates, and cross-label conflicts.

Four properties affect the experimental protocol:

1. Benign records span 31 October–5 November 2024, while the attack partitions span 28 February–27 March 2024. A single global chronological split would therefore confound class with acquisition period.
2. There are 328 unique connection identities associated with more than one tactic. The pipeline unions their original labels instead of treating duplicated feature vectors as contradictory independent examples.
3. The literal technique value `Duplicate` occurs in the published source and is retained in the audit, but it is not interpreted as a MITRE technique identifier.
4. Exfiltration contains only 23 raw rows, so class imbalance is material and all metrics must include per-class support.

## Frozen M2 preparation policy

```powershell
fl-forensics m2-prepare `
  --input data\raw\uwf-zeekdata24\csv `
  --output artifacts\m2-data24

fl-forensics m2-verify --workspace artifacts\m2-data24
```

Connection identities that differ only in label fields are consolidated and their tactic/technique labels are retained in lineage. A single tactic remains its normalized MITRE tactic label; multiple attack tactics become `multi_tactic`. Events are aggregated in 60-second windows using the frozen 25-feature schema.

The split unit is the UTC calendar date, never an individual row or window. The final published Parquet week starts on 3 November 2024, so records from that point are reserved as `temporal_holdout`. The remaining dates are ordered within the `benign_only` and `attack_present` regimes and assigned to train, validation, and development test. This two-regime procedure is necessary because the CSV acquisition periods are disjoint; the limitation is written into `split_manifest.json` rather than hidden.

The real M2 snapshot contains 15,410 windows:

| Split | Windows |
| --- | ---: |
| Train | 5,704 |
| Validation | 2,270 |
| Development test | 3,132 |
| Last-week temporal holdout | 4,304 |

`scaler.json` contains standard-score parameters fitted exclusively on the 5,704 training windows. Repeating preparation from the same downloaded files and configuration produced identical dataset and scaler SHA-256 digests.

## Centralized baseline

```powershell
python -m pip install -e ".[m2,dev]"
fl-forensics m2-train `
  --workspace artifacts\m2-data24 `
  --output artifacts\m2-data24-central
fl-forensics m2-verify-baseline `
  --workspace artifacts\m2-data24-central `
  --dataset-workspace artifacts\m2-data24
```

The centralized model is a scikit-learn MLP with a 25-dimensional input, encoder layers 128 and 64, a 32-dimensional embedding, and a six-output classification head. Balanced sample weights are computed only from training labels. With seed 341593 and scikit-learn 1.8.0, the reference run reached macro-F1 0.7514 on validation and 0.7477 on the multiclass development test.

The temporal holdout is benign-only in the CSV release. Its benign recall is 0.9972, but its all-class macro-F1 is not a valid multiclass performance estimate. `metrics.json` preserves this constraint and reports support, precision, recall, F1, and the confusion matrix for every class and split.
