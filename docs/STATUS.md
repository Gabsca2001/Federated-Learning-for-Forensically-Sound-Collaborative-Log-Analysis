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
| Deterministic Zeek normalization/window snapshot | Implemented | Generic Zeek JSONL contract; UWF schema audit pending |
| Lineage from batch to snapshot windows/events | Implemented | Local JSON graph; rebuild/contamination traversal pending |
| Central MLP baseline | Planned (M2) | — |
| Flower federation with 15 clients | Planned (M3) | — |
| `swtpm`, mTLS, and physical TPM | Planned (M4) | — |
| Secure Update Bundle and robust aggregation | Planned (M5–M6) | — |
| Integrated Gradients and deterministic report | Planned (M7) | — |

The absence of Docker, `swtpm`, Flower, and PyTorch in the current build environment means those components are not marked as validated.

