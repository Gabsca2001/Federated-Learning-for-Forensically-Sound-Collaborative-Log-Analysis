# Implementation status

## Summary

The deterministic M1–M8 reference chain is implemented and merged. The complete local test
suite contains 223 passing tests. The principal remaining gaps are physical-TPM execution,
production-grade evidence storage/key management, multi-seed statistical replication, and
external-dataset generalization.

## Current coverage

| Component | State | Current assurance |
|---|---|---|
| Canonical manifests and SHA-256 commitments | Implemented | Integer-safe canonical profile; deterministic and tamper-tested |
| ECDSA P-256 signing | Implemented | Software authorities plus TPM ESK adapter; key roles remain explicit |
| Acquisition, batch chain, and custody | Implemented | Atomic local publication and chained events; production WORM storage not implemented |
| Admission and idempotency | Implemented | Identity, content, chain, signature, attestation status/expiry, replay semantics |
| Content-addressed evidence vault | Implemented | Tamper-evident prototype; object lock and retention service remain external |
| UWF-ZeekData24 controlled ingestion | Implemented (M2) | Canonical Parquet manifest covers seven source partitions and their sizes/digests |
| Deterministic normalization/windowing | Implemented (M1–M2) | Frozen 25-feature, 60-second contract; source/event/window lineage verified |
| Group/time split and training-only scaling | Implemented (M2) | Capture-date groups are disjoint; final capture reserved; scaler provenance checked |
| Central MLP baseline | Implemented and verified (M2) | Validation macro-F1 `0.945674`; test macro-F1 `0.923073` |
| 15-client IID/non-IID partitioning | Implemented and verified (M3) | Exact train/validation/local-test coverage; client and server test artifacts are isolated from training access |
| Flower ClientApp/ServerApp | Implemented (M3) | Current Message API; 15-client full-participation FedAvg profile |
| Auditable FedAvg runner | Implemented and verified (M3) | All training precedes test access; aggregation, local-only inference, and post-selection per-client tests are independently reconstructed |
| PROTEAN adaptation | Implemented and verified (M3 extension) | Four validation-only lambda candidates; two endpoints locked before test access |
| Enrollment, AK/ESK separation, challenge, revocation | Implemented (M4) | Signed one-to-one bindings and append-only revocation semantics |
| Quote/PCR appraisal and Attestation Result v2 | Implemented (M4) | One-use nonce and independent PCR replay; 15/15 `swtpm` gate passed |
| TLS 1.3 mutual authentication | Implemented (M4) | EKU, SAN, enrollment-fingerprint, and wrong-pair checks |
| Physical TPM adapter | Implemented; runtime pending | Same `tpm2-tools` interface via `device:/dev/tpmrm0`; no hardware result claimed |
| Secure FedAvg campaign | Implemented and verified (M5) | New campaigns bind post-selection client-local metrics; preserved reference has 30 rounds, 450/450 bundles, and selected round 11 |
| Byzantine/robust aggregation experiments | Implemented and verified (M6) | Frozen real M5 inputs; model and prototype campaigns; deterministic reports |
| Investigation chain | Implemented and verified (M7) | Six cases, 69 events, 81 source records; prediction-to-report lineage complete |
| Preservation inventory | Implemented and verified (M8.1) | 2,363 artifacts, seven external bindings, 2,631,940,087 payload bytes |
| Merkle commitment | Implemented and verified (M8.2) | 2,370 leaves, 13 levels, deterministic duplicate-last rule |
| Trusted timestamp | Implemented and verified (M8.3) | RFC 3161 token over the M8 Merkle root; offline verification succeeds |
| Offline recovery export | Implemented and verified (M8.4) | Deterministic TAR, 2,363 payload entries, 11 assurance entries |
| Campaign invariant accounting | Implemented and verified (M8.5) | 30 rounds, 15 clients, 450 contributions reconstructed from recovery TAR |
| Final preservation verification | Implemented and verified (M8.6) | Five assurance stages; offline inputs only; zero errors |

## Canonical reference chain

| Stage | Workspace or identifier |
|---|---|
| M2 dataset | `artifacts/m2-data24-parquet` |
| M3 IID partitions | `artifacts/m3-data24-parquet-iid` |
| M4 trust | `artifacts/m4-trust` |
| M5 campaign | `artifacts/m5-secure-multiround-v2` |
| M7 report | `artifacts/m7-investigation-report-test-first6-v1` |
| M8 inventory | `m8-preservation-07101d8294c8798f9a0b8f15` |
| M8 Merkle tree | `m8-merkle-tree-bd598d3ac8ed86eacff47611` |
| M8 timestamp | `m8-timestamp-anchor-7fe093ea54ecce8bf8e791db` |
| M8 recovery | `m8-recovery-export-eec242458090f9a22b62d86a` |
| M8 accounting | `m8-campaign-accounting-8145d39622bf25d39a135c38` |
| M8 final receipt | `m8-final-verification-2b1eb8e1ecba88dcaf234edc` |

The final assurance state is
`merkle-committed-time-anchored-recovery-exported-campaign-accounted-finally-verified`.

## Important boundaries

- The RFC 3161 timestamp anchors the M8 preservation root. It does not convert the local M1
  custody-event store into a continuously externally anchored production ledger.
- `swtpm` confirms protocol and artifact behavior but is not equivalent to hardware-backed
  key non-exportability.
- The M8 recovery package preserves the selected reference chain; it is not a substitute for
  an organizational retention, access-control, backup, or legal-admissibility policy.
- The temporal holdout is benign-only and cannot support a multiclass generalization claim.
- The reported scores come from deterministic reference runs, not a multi-seed confidence
  interval study.
- Model explanations and ATT&CK mappings are interpretive, not proof of attacker intent.

## Outstanding validation and engineering work

1. Run the M4 adapter against a physical TPM 2.0 host and document the hardware evidence.
2. Rebuild the canonical M3/M5 workspaces under the local-test contract before publishing new
   per-client scores; do not replace the preserved reference chain in place.
3. Replicate selected M3/M6 results across seeds and report dispersion and uncertainty.
4. Evaluate external generalization without mixing UWF-ZeekData22 into model selection.
5. Store retained packages in access-controlled WORM/object-lock storage.
6. Define production certificate/key lifecycle, service separation, monitoring, and recovery.
7. Validate multi-host performance and failure recovery outside the single-host research
   deployment.

See [Implementation plan](IMPLEMENTATION_PLAN.md) for milestone gates and
[Architecture](ARCHITECTURE.md) for the trust and claim boundaries.
