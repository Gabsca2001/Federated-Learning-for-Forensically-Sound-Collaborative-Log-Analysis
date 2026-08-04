# Federated Learning for Forensically-Sound Collaborative Log Analysis

This repository is the experimental implementation of the architecture defined in Chapter 4 of the thesis. The target system joins controlled Zeek log acquisition, cryptographic preservation, deterministic preprocessing, federated learning, Byzantine-resilient aggregation, end-to-end lineage, explainability, and investigative reporting.

The current milestone implements and tests the first vertical slice:

`Zeek JSONL → raw batch → canonical manifest → SHA-256 chain → ECDSA signature → attestation-aware admission → content-addressed vault → deterministic snapshot → lineage`

The Data24 centralized path is:

`controlled UWF-ZeekData24 CSV ingestion → schema/label audit → cross-label consolidation → 60 s feature windows → group/time split → training-only scaler → MLP encoder + classification head → metrics and digests`

It intentionally does **not** claim that a software key is equivalent to a TPM. The signer and attestation interfaces are already separated so that `swtpm` and the physical TPM 2.0 adapter can replace the development implementation without changing the artifact formats.

## Quick start

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
fl-forensics demo --input tests/fixtures/zeek_conn.jsonl --output demo-output
fl-forensics verify --workspace demo-output
python -m unittest discover -s tests -v
```

PowerShell:

```powershell
py -3.14 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
fl-forensics demo --input tests\fixtures\zeek_conn.jsonl --output demo-output
fl-forensics verify --workspace demo-output
python -m unittest discover -s tests -v
```

The demo output is disposable operational data. Formal experimental campaigns will use a separate namespace for every `experiment_id`, persistent Docker volumes, `swtpm`/TPM-backed keys, mutual TLS, and external root anchoring.

## Milestone 2 — UWF-ZeekData24 and centralized baseline

Install only the numerical dependencies required by M2; Flower and PyTorch remain M3 dependencies:

```powershell
python -m pip install -e ".[m2,dev]"
python scripts\download_uwf_zeekdata24.py
fl-forensics m2-audit --input data\raw\uwf-zeekdata24\csv --output artifacts\m2-data24-audit.json
fl-forensics m2-prepare --input data\raw\uwf-zeekdata24\csv --output artifacts\m2-data24
fl-forensics m2-verify --workspace artifacts\m2-data24
fl-forensics m2-train --workspace artifacts\m2-data24 --output artifacts\m2-data24-central
fl-forensics m2-verify-baseline --workspace artifacts\m2-data24-central --dataset-workspace artifacts\m2-data24
```

The scaler is fitted only on `train`. Capture dates are indivisible groups. The partition beginning on 3 November 2024 is kept as `temporal_holdout`; in the published CSV release it contains only benign records, so it is reported separately from the multiclass development test.

## Source-of-truth rules

- The finalized Chapter 4 takes precedence over earlier design notes.
- The target virtual federation contains 15 clients and 15 independent `swtpm` instances.
- FedAvg is the learning baseline; trimmed mean is the operational robust reference profile.
- Model parameters and class prototypes are validated and aggregated separately.
- UWF-ZeekData24 is the primary development dataset. Its provenance begins at controlled ingestion, not at the historical capture performed by UWF.
- UWF-ZeekData22 is reserved for a later external-generalization experiment and is not part of the M2 baseline.
- Raw evidence is never overwritten by normalized data or feature snapshots.
- Rejected artifacts are preserved with a resolvable reason.
- A valid signature proves origin/integrity after signing, not semantic truth or benign behavior.

See `docs/ARCHITECTURE.md`, `docs/IMPLEMENTATION_PLAN.md`, and `docs/STATUS.md` for boundaries, milestones, and current coverage.

Dataset setup is documented in `docs/DATASET_UWF_ZEEKDATA24.md`. The data itself is intentionally excluded from Git.


