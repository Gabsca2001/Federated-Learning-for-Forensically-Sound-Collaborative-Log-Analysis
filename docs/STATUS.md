# Implementation status

| Component | State | Current assurance |
| --- | --- | --- |
| Canonical manifests and SHA-256 commitments | Implemented | Unit-tested integer-only canonical profile |
| ECDSA P-256 signing interface | Implemented (M1–M4) | Software development signer plus tpm2-tools ESK adapter for swtpm/physical TPM |
| Signed Attestation Result artifact | Implemented (M1, M4) | Schema v1 remains valid; v2 binds enrollment, challenge, AK, Quote evidence, PCR policy, mTLS peer and Verifier signature |
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
| Flower Message API ClientApp/ServerApp | Implemented (M3) | Current ArrayRecord/MetricRecord API; 15-node full-participation FedAvg |
| Auditable PyTorch/FedAvg runner | IID experiment completed (M3) | 30 rounds; test macro-F1 0.74836, validation 0.73699, local-only mean 0.69419; non-IID run remains to be recorded |
| Deterministic M3 evaluation report | Implemented (M3) | Digest-validated confusion matrices, per-class metrics, round curves, local/FedAvg/centralized and per-client plots; figure SHA-256 manifest |
| Versioned enrollment, AK/ESK separation, challenge and revocation | Implemented and unit-tested (M4) | Signed ESK request; one-to-one client/node/TPM binding; append-only revocation; emulator assurance explicitly limited |
| Quote/PCR appraisal and Attestation Result v2 | Implemented, Docker runtime pending (M4) | One-use 256-bit nonce; ordered measurement replay; independent expected PCR input to `tpm2_checkquote`; failed evidence preserved |
| 15-pair `swtpm` Compose deployment | Implemented, Docker runtime pending (M4) | Dedicated state/socket volumes; no client state mount or foreign socket; static topology verifier |
| TLS 1.3 mutual authentication | Implemented and unit-tested (M4) | Private experiment CA, clientAuth/serverAuth EKU, SAN and enrollment-fingerprint binding, wrong pair rejected |
| Physical TPM 2.0 adapter | Implemented, hardware run pending (M4) | Same tpm2-tools adapter via `device:/dev/tpmrm0`; no simulator/hardware equivalence claim |
| Secure Update Bundle and robust aggregation | Planned (M5–M6) | — |
| Integrated Gradients and deterministic report | Planned (M7) | — |

M2 uses NumPy and scikit-learn only. Flower/PyTorch belong to M3 and the trust
deployment belongs to M4; neither changes the frozen M2 dataset contract.

The published Data24 CSV release has a documented acquisition-time/class confound, 328 cross-label connection identities, and a benign-only final-week holdout. The implementation preserves these facts in machine-readable audit, split, lineage, and metrics artifacts; the baseline scores must not be interpreted as evidence that those dataset limitations have been removed.
