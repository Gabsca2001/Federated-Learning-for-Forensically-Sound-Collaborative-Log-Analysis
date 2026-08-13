# Federated Learning for Forensically-Sound Collaborative Log Analysis

This repository is the experimental implementation of the architecture defined in Chapter 4 of the thesis. The target system joins controlled Zeek log acquisition, cryptographic preservation, deterministic preprocessing, federated learning, Byzantine-resilient aggregation, end-to-end lineage, explainability, and investigative reporting.

Milestones 1–3 are implemented and tested; the clean IID FedAvg run has also
completed. Milestone 4 implements the versioned trust protocol, 15-pair swtpm
deployment, TLS 1.3 mutual authentication, and the shared swtpm/physical TPM
adapter. Its Docker and physical-hardware runtime gates remain explicit. The
evidence vertical slice is:

`Zeek JSONL → raw batch → canonical manifest → SHA-256 chain → ECDSA signature → attestation-aware admission → content-addressed vault → deterministic snapshot → lineage`

The Data24 centralized path is:

`controlled UWF-ZeekData24 CSV ingestion → schema/label audit → cross-label consolidation → 60 s feature windows → group/time split → training-only scaler → MLP encoder + classification head → metrics and digests`

The clean federated path is:

`M2 feature snapshot → 15 IID/non-IID client snapshots → PyTorch local training → Flower FedAvg → chained round records → global model registry → local/FedAvg comparison`

The trust path is:

`client/node/TPM pair → EK/AK/ESK provisioning → signed enrollment → mTLS identity → one-use nonce → TPM2 Quote → PCR/log replay → signed Attestation Result v2 → admission or quarantine`

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

## Milestone 3 — clean 15-client Flower/FedAvg baseline

Install the M3 dependencies. The auditable runner uses Flower and PyTorch but does
not require Ray:

```powershell
python -m pip install -e ".[federated,dev]"
```

Create and verify both frozen partition profiles:

```powershell
fl-forensics m3-partition --dataset-workspace artifacts\m2-data24 --output artifacts\m3-data24-iid --mode iid
fl-forensics m3-verify-partitions --workspace artifacts\m3-data24-iid --dataset-workspace artifacts\m2-data24
fl-forensics m3-partition --dataset-workspace artifacts\m2-data24 --output artifacts\m3-data24-non-iid --mode non-iid
fl-forensics m3-verify-partitions --workspace artifacts\m3-data24-non-iid --dataset-workspace artifacts\m2-data24
```

Run and verify the clean FedAvg campaign first on IID and then on non-IID:

```powershell
fl-forensics m3-train --partition-workspace artifacts\m3-data24-iid --dataset-workspace artifacts\m2-data24 --output artifacts\m3-data24-iid-fedavg
fl-forensics m3-verify --workspace artifacts\m3-data24-iid-fedavg --partition-workspace artifacts\m3-data24-iid --dataset-workspace artifacts\m2-data24
fl-forensics m3-report --workspace artifacts\m3-data24-iid-fedavg --central-workspace artifacts\m2-data24-central

fl-forensics m3-train --partition-workspace artifacts\m3-data24-non-iid --dataset-workspace artifacts\m2-data24 --output artifacts\m3-data24-non-iid-fedavg
fl-forensics m3-verify --workspace artifacts\m3-data24-non-iid-fedavg --partition-workspace artifacts\m3-data24-non-iid --dataset-workspace artifacts\m2-data24
```

`m3-train` performs 30 rounds, two local epochs, full participation and
example-weighted FedAvg. It preserves every local update object, every global
checkpoint, a hash-chained record for each round, centralized evaluation, and a
fair local-only comparison using the same initial model and the same total number
of local epochs.

Install the reporting extra before generating figures:

```powershell
python -m pip install -e ".[federated,reporting,dev]"
```

`m3-report` validates the digests of `metrics.json`, `comparison.json`, and the
optional centralized metrics before generating seven immutable PNG figures and a
machine-readable `reports\summary.json`. The outputs include absolute and
row-normalized test confusion matrices, per-class precision/recall/F1, validation
and loss curves by round, the local/FedAvg/centralized comparison, and per-client
local-only performance. It does not repeat training or inference.

The repository also exposes a current Flower Message API `ClientApp` and
`ServerApp`. To validate Flower's Simulation Runtime, install the separate Ray
extra and run 15 SuperNodes:

```powershell
python -m pip install -e ".[federated,simulation,dev]"
flwr run . --stream --federation-config="num-supernodes=15 client-resources-num-cpus=1"
```

Flower documents native Windows/Ray support as experimental and recommends WSL2
for the Simulation Runtime. This limitation does not apply to the auditable
single-process `m3-train` runner.

## Milestone 4 — trust deployment, swtpm, Quote appraisal, and mTLS

M4 does not retrain the model or modify Data24. Install the project, run the full
suite, and verify the declared one-to-one topology:

```powershell
python -m pip install -e ".[m4,dev]"
python -m unittest discover -s tests -v
fl-forensics m4-verify-deployment --compose compose.m4.yaml --clients configs\clients.yaml
```

Initialize the experiment authorities, private PKI, and approved measurement
baseline. The command refuses partial or ambiguous existing state:

```powershell
fl-forensics m4-init --workspace artifacts\m4-trust --project-root .
```

Provision 15 independent TPM states. Every client generates a distinct EK, AK,
and ESK inside its paired emulator, extends the approved measurements, generates
its own TLS CSR, and writes an ESK-signed enrollment request:

```powershell
python scripts\run_m4_swtpm.py provision
fl-forensics m4-enroll --workspace artifacts\m4-trust --node-root artifacts\m4-nodes
```

Exercise a real TLS 1.3 mutual-authentication handshake for every enrolled
client, then issue one-use challenges and produce Quotes:

```powershell
fl-forensics m4-mtls-test --workspace artifacts\m4-trust --node-root artifacts\m4-nodes
fl-forensics m4-challenge --workspace artifacts\m4-trust --node-root artifacts\m4-nodes
python scripts\run_m4_swtpm.py quote
docker compose -f compose.m4.yaml --profile verify run --rm verifier
```

The final command must report `client_count: 15`, `passed_count: 15`, and
`status: verified`. It verifies the AK signature, exact nonce, registered pair,
revocation state, TLS certificate binding, measurement-log digest, and expected
PCR values. Identical evidence is idempotent; changed evidence using a consumed
nonce is rejected as stale.

Stop containers without deleting TPM state:

```powershell
python scripts\run_m4_swtpm.py stop
```

Never add `--volumes` during normal cleanup. Deleting a TPM state volume changes
the device identity and requires a new enrollment. The separate physical-node
preflight is Linux-only:

```bash
fl-forensics m4-physical-preflight --tcti device:/dev/tpmrm0
```

See `docs/MILESTONE_4_TRUST_DEPLOYMENT.md` for artifact semantics, negative
tests, and the limits of swtpm assurance.

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
