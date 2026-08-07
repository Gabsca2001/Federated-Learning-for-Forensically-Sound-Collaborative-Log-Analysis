# Implementation status

| Component | State | Current assurance |
| --- | --- | --- |
| Canonical manifests and SHA-256 commitments | Implemented | Unit-tested integer-only canonical profile |
| ECDSA P-256 signing interface | Implemented | Software keys for development; TPM adapter pending |
| Signed Attestation Result artifact | Implemented | Development issuer only; Quote/PCR/IMA appraisal pending |
| Acquisition queue and batch chain | Implemented | Single-process prototype with atomic publication |
| Admission and idempotency | Implemented | Identity, content, chain, signature, attestation status/expiry |
| Content-addressed Evidence Vault | Implemented | Tamper-evident prototype; WORM/object lock pending |
| Chained custody events | Implemented | Local append-only convention; external time anchor pending |
| UWF-ZeekData24 controlled download and audit | Implemented (M2) | 8 CSV partitions; size/SHA-256 verification; 95,871-row schema, label, null, time, duplicate, and leakage audit |
| Deterministic Zeek normalization/window snapshot | Implemented (M1–M2) | Generic JSONL and real Data24 CSV path; frozen 25-feature/60-second schema; repeated real preparation has identical digest |
| Group/time split and training-only scaling | Implemented (M2) | Capture-date groups are disjoint; final week reserved; scaler row count and digest verified |
| Lineage from source CSV rows to windows | Implemented (M2) | Raw line digest/path/line, consolidated identity, normalized event, and window links; rebuild/contamination traversal pending |
| Central MLP baseline | Implemented (M2) | sklearn 1.8 encoder 128/64, embedding 32, six-class head; validation macro-F1 0.7514, development-test macro-F1 0.7477 |
| Deterministic 15-client IID/non-IID snapshots | Implemented and verified (M3) | Exact M2 train/validation coverage; raw-data boundary; IID 380–381 rows/client, non-IID 58–1,046 on real Data24 |
| Flower Message API ClientApp/ServerApp | Implemented, runtime validation pending (M3) | Current ArrayRecord/MetricRecord API; 15-node full-participation FedAvg |
| Auditable PyTorch/FedAvg runner | Implemented, experiment pending (M3) | Content-addressed updates/checkpoints, chained rounds, FedAvg recomputation verifier, local-only comparison |
| Deterministic M3 evaluation report | Implemented (M3) | Digest-validated confusion matrices, per-class metrics, round curves, local/FedAvg/centralized and per-client plots; figure SHA-256 manifest |
| `swtpm`, mTLS, and physical TPM | Planned (M4) | — |
| Secure Update Bundle and robust aggregation | Planned (M5–M6) | — |
| Integrated Gradients and deterministic report | Planned (M7) | — |

M2 uses NumPy and scikit-learn only. Flower, PyTorch, Docker-based federation, `swtpm`, mTLS, and the physical TPM remain outside the validated M2 boundary.

The published Data24 CSV release has a documented acquisition-time/class confound, 328 cross-label connection identities, and a benign-only final-week holdout. The implementation preserves these facts in machine-readable audit, split, lineage, and metrics artifacts; the baseline scores must not be interpreted as evidence that those dataset limitations have been removed.
