# Architecture contract

## Functional planes

| Plane | Client-side components | Core components | Stable artifacts |
| --- | --- | --- | --- |
| Local | Zeek source/replay, Acquisition Agent, Snapshot Builder, Flower ClientApp, Update Packager | — | Batch Bundle, Snapshot Bundle, Update Bundle |
| Trust | TPM adapter/Attester | Identity Registry, Attestation Verifier, Admission Controller | Enrollment Record, Attestation Result, Admission Decision, Receipt |
| Learning | Local trainer and prototype producer | Flower Server, Update Validator, Aggregator, Checkpoint Registry | Round Context, Contribution Decision, Checkpoint Bundle |
| Investigative | Local source-event resolution | Inference Service, Explanation Engine, Report Generator | Prediction Bundle, Explanation Bundle, Report Bundle |
| Cross-cutting | local queue and lineage emitters | Evidence Vault, Lineage Store, custody and anchoring services | Custody Event, Lineage Edge, Merkle Root/Time Proof |

## Immutable derivation path

1. A source record enters a closed raw batch.
2. The batch core is canonicalized; the content digest and predecessor commitment produce a chain hash.
3. The Evidence Signing Key signs the chain hash.
4. The Admission Controller verifies identity, attestation, signature, content, freshness, and continuity.
5. Accepted and quarantined objects are both preserved. Only accepted references reach the Snapshot Builder.
6. Deterministic normalization and window construction create a local Snapshot Bundle and a source-event lineage map.
7. A federated update references exactly one admitted snapshot, one round context, and one starting checkpoint.
8. The checkpoint references the exact contribution decisions and aggregation policy.
9. Predictions and explanations reference the checkpoint, window, snapshot, and source events.
10. A report is finalizable only when every evidentiary reference resolves and the lineage is complete.

## M2 centralized derivation path

The public UWF-ZeekData24 files enter the trust model only at controlled ingestion. Their source URL, size, and SHA-256 are recorded, but this does not retroactively attest the historical UWF capture. M2 then audits the 26-column CSV schema, consolidates identical connections carrying multiple labels, retains every source path/line/digest in lineage, builds 60-second windows with the frozen 25-feature schema, assigns whole UTC dates to splits, and fits standardization only on training windows. The centralized model, metrics, and manifest reference the exact dataset and scaler digests.

## Cryptographic profile

- Canonicalization: RFC 8785/JCS-compatible integer-only manifest profile. Floating-point values are prohibited in signed manifest cores; measurements are represented as strings or scaled integers.
- Digest: SHA-256.
- Application signatures: ECDSA P-256 with SHA-256.
- Batch commitment: `SHA256(previous_chain_hash || content_sha256 || SHA256(JCS(core)))`, using binary digest values in the concatenation.
- Transport target: TLS 1.3 with mutual client/service authentication.
- Attestation target: TPM2 Quote over a versioned PCR selection and a fresh verifier nonce.

## Trust boundaries

- The Flower Server never mounts raw client datasets or client workspaces.
- The Evidence Vault and the federated coordinator have separate storage and permissions.
- `swtpm` validates protocol behavior but does not provide hardware non-exportability or resistance to a hostile host administrator.
- The physical TPM experiment validates key use and measured-state appraisal on one node; it does not prove 15-node physical scalability.
- Statistical screening never changes a cryptographic admission result into proof of malicious intent.
- Explanations remain model-derived interpretive artifacts and do not become primary evidence.
