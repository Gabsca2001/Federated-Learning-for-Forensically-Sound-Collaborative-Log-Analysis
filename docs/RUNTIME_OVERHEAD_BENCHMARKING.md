# M4–M5 containerized runtime-overhead benchmarking

## Purpose

This profile measures the state-changing runtime path that the offline M4–M8 benchmark
deliberately excludes. It creates fresh trust authorities, 15 independent `swtpm` states,
new attestations, and a new one-round M5 workspace for every trial. It never opens or changes
the preserved `local-test-v1` trust, campaign, investigation, or M8 workspaces.

The result characterizes the current **containerized runtime prototype**. It is not a physical
TPM benchmark and it is not a distributed network deployment.

## Measured lifecycle

Each configured repetition performs these 12 ordered stages:

1. initialize the M4 trust workspace and approved PCR baseline;
2. start and provision 15 independent `swtpm` instances with EK, AK, and ESK roles;
3. validate and enroll all 15 nodes;
4. perform 15 real loopback TLS 1.3 mutual-authentication handshakes;
5. measure 20 ESK signatures through `tpm2_sign` after two warmups on `client01`;
6. issue 15 fresh, signed, one-use challenges;
7. generate 15 live TPM Quotes;
8. appraise all Quotes and require 15/15 passing Attestation Result v2 receipts;
9. create an attestation-gated signed M5 round context;
10. train and validate 15 isolated clients and TPM-sign all 15 Update Bundles;
11. perform admission checks and FedAvg aggregation;
12. independently reload every update and reproduce the checkpoint.

Docker image construction happens before timing and is explicitly excluded. The summary also
reports three additive spans: `bootstrap`, `trust-gate`, and `secure-round`. The external
duration of the ESK-probe stage includes container launch; the probe additionally reports its
internal per-signature wall time measured around `tpm2_sign` itself.

## Fresh-state and retention rules

The default configuration performs three independent trials. Their Compose projects are:

```text
flforensics_runtime_overhead_v1_001
flforensics_runtime_overhead_v1_002
flforensics_runtime_overhead_v1_003
```

The corresponding generated workspaces are placed under
`artifacts/runtime-overhead-work-local-test-v1/trial-NNN/`. Containers are stopped after each
trial, but Docker volumes are not deleted. This preserves the TPM state associated with the
measurement. Reusing the work root or receipt output is rejected; a repeated experiment needs
new `benchmark_id`, `project_namespace`, `work_root`, and output names.

## Run and verify

Run from the repository root with Docker Engine available in WSL2:

```bash
python scripts/run_runtime_overhead.py plan \
  --config configs/runtime-overhead-local-test-v1.yaml

python scripts/run_runtime_overhead.py run \
  --config configs/runtime-overhead-local-test-v1.yaml \
  --output artifacts/runtime-overhead-local-test-v1

fl-forensics runtime-overhead-verify \
  --config configs/runtime-overhead-local-test-v1.yaml \
  --workspace artifacts/runtime-overhead-local-test-v1
```

The run can take several minutes because every repetition provisions 15 new TPM identities
and performs a real 15-client local-training round. Progress is printed once per stage. Full
subprocess logs remain under each trial's `logs/` folder to diagnose a failed execution.

The receipt workspace contains:

- `samples.json`: wall/CPU observations, sanitized stage outcomes, trial paths, and additive
  spans;
- `summary.json`: recomputed per-stage and per-span distributions plus environment and
  methodology boundaries;
- `manifest.json`: receipt identifier and SHA-256 bindings for configuration, implementation,
  source files, trust evidence, Quotes, public ESKs, Update Bundles, and checkpoint artifacts.

`runtime-overhead-verify` does not repeat TPM or training operations. It validates every stage
assertion, recomputes statistics, re-hashes the current source contract, and reconstructs the
runtime-evidence snapshots left by all trials. Missing or modified evidence makes verification
fail closed.

## Verified reference execution

The WSL2 reference completed three fresh trials, all 36 stage executions, 45 live Quotes,
45 TPM-signed Update Bundles, and three independently reproduced FedAvg checkpoints. The
verifier recomputed 18 source snapshots, 207 runtime-evidence snapshots, and all statistics
with zero errors.

| Scope | Median wall time |
|---|---:|
| Fresh M4 bootstrap | `131.897 s` |
| Trust-related group, including the diagnostic ESK probe | `104.403 s` |
| Secure M5 round | `105.980 s` |
| All measured stages | `345.315 s` |
| Provision 15 independent `swtpm` clients | `126.627 s` |
| Generate 15 TPM Quotes sequentially | `88.290 s` |
| Train, validate, and TPM-sign 15 clients with four workers | `74.728 s` |
| Admission and FedAvg | `10.957 s` |
| Independent secure-round verification | `8.722 s` |
| Direct ESK signature through `tpm2_sign` | `13.854 ms` over 60 samples |

The receipt is `runtime-overhead-adb5811cce9ded407e4b1e0d`; the source runtime-manifest
SHA-256 is `2a8c19ee782a429a4ca40a020cd6e74897cbc30d1de241e8624dba9f657cb7e4`.
The compact public view is under
[`results/runtime-overhead-local-test-v1`](../results/runtime-overhead-local-test-v1/README.md).

## Interpretation boundary

The M5 prototype does not yet send updates through a contribution API. Client containers are
network-disabled and deliver their signed bundles through distinct bind-mounted submission
directories; the coordinator never mounts client datasets. Consequently:

- `m5-client-train-validate-sign-15-clients` measures local training, local validation,
  serialization, TPM signing, container scheduling, and writes to the mounted submission
  channel;
- it does **not** measure WAN transfer, an HTTP/gRPC request, server queueing, retry policy,
  or API-side backpressure;
- the direct ESK probe isolates signing from local training, while the complete client stage
  reflects the operational cost visible to the current prototype;
- `swtpm` validates TPM protocol behavior but does not establish hardware-backed
  non-exportability or physical-TPM latency;
- WSL2, Docker scheduling, host load, CPU allocation, and filesystem cache state remain part
  of the declared experimental environment.

A later multi-host profile must add an mTLS contribution endpoint and message/object storage,
then measure transport and queue latency separately. Those future values must not be silently
combined with this local bind-mounted result.

## Evaluation boundary

This benchmark runs one secure training round and therefore does not select a final model or
open pooled test, temporal-holdout, or client-local test artifacts. Those post-selection tests
remain part of the already verified 30-round reference campaign. The runtime experiment tests
security-path cost; it is not a replacement learning-performance experiment.
