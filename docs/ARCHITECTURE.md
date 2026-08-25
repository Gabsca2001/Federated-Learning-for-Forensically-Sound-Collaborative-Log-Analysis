# Architecture contract

## Purpose

The system is an auditable research pipeline for collaborative Zeek-log analysis. It keeps
four concerns separate throughout the implementation:

1. evidence acquisition and preservation;
2. deterministic data and model derivation;
3. identity, attestation, and contribution admission;
4. analyst-facing interpretation and final recovery.

No downstream result replaces its inputs. Instead, each stage publishes a new workspace
whose manifest binds the configuration, upstream digests, output digests, and the identifiers
needed to reconstruct the derivation.

## Functional planes

| Plane | Primary components | Stable outputs |
|---|---|---|
| Evidence | Acquisition, canonicalization, signing, admission, vault, custody | Batch, receipt, custody event, snapshot, lineage |
| Data | Data24 audit, consolidation, windowing, split, scaling | Dataset manifest, feature schema, split manifest, scaler |
| Learning | Central MLP, Flower client/server, deterministic FedAvg, PROTEAN | Updates, round records, checkpoints, metrics, selection locks |
| Trust | Registry, CA, enrollment, mTLS, TPM adapter, Quote verifier, revocation | Enrollment, challenge, Quote evidence, Attestation Result v2 |
| Secure campaign | Round coordinator, update validator, aggregation, campaign finalizer | Round context, update bundle, decision, checkpoint, campaign manifest |
| Robustness | Attack freezer, Byzantine aggregators, sensitivity runner | Frozen input set, comparison, verification receipt, report |
| Investigation | Inference, lineage resolver, explanation, ATT&CK mapper, report generator | Prediction, explanation, mapping, JSON/Markdown report |
| Preservation | Inventory, Merkle builder, timestamp client, recovery exporter, accountant | Preservation manifest, Merkle root, RFC 3161 proof, TAR, final receipt |

The implementation lives in `src/fl_forensics/`. Versioned experiment contracts live in
`configs/`; JSON Schemas for signed and canonical objects are under `configs/schemas/`.
Container topology is declared by the root Compose files, while `scripts/` contains the
orchestration that is intentionally kept outside artifact-generation primitives.

## End-to-end derivation

```text
controlled source bytes
  └─> admitted raw batch + custody chain
       └─> normalized events + source/event lineage
            └─> immutable feature windows + frozen splits + training-only scaler
                 └─> client partitions + server evaluation snapshot
                      └─> signed/verified client updates
                           └─> chained global checkpoints
                                └─> predictions + explanations + ATT&CK mappings
                                     └─> deterministic investigation report
                                          └─> inventory + Merkle root + time proof
                                               └─> offline recovery + final audit
```

### M1 — evidence vertical slice

1. A source record enters a closed raw batch.
2. The batch core is canonicalized.
3. Its content digest and predecessor commitment produce a chain hash.
4. The Evidence Signing Key signs that commitment.
5. Admission checks identity, content, signature, attestation, freshness, and continuity.
6. Both admitted and quarantined artifacts are preserved with their decision.
7. Only admitted references may feed a deterministic snapshot.

This creates the artifact semantics reused by later milestones without claiming that the
small demonstration is itself the final Data24 campaign.

### M2 — dataset derivation

The public UWF-ZeekData24 release enters the trust model at controlled ingestion. The
downloader records URL, byte count, and SHA-256 for each file; these values do not
retroactively attest the publisher's historical capture.

The canonical Parquet path then:

1. audits all source partitions and their schema;
2. consolidates source rows that represent the same event identity;
3. retains every source reference and label observation in lineage;
4. builds 60-second windows with the frozen 25-feature schema;
5. assigns entire capture dates to train, validation, test, or temporal holdout;
6. fits the scaler and class weighting from training data only;
7. binds the central model and metrics to the exact dataset/scaler digests.

### M3 — clean federated learning

The partitioner creates 15 disjoint client snapshots in IID or label-Dirichlet non-IID mode.
Raw and normalized events remain outside those snapshots. The server evaluation artifact
contains only scaled validation, test, and temporal-holdout features.

The deterministic runner uses the same PyTorch primitives and example-weighted FedAvg rule
as the Flower path while serializing artifact publication. Every round records all 15 local
updates, their counts, the base model, the resulting global checkpoint, metrics, and the
previous round digest. The verifier reloads the updates and reproduces the aggregation.

PROTEAN is a separate auditable adaptation over the non-IID profile. Candidate alignment
weights are evaluated with validation data, the paper-faithful and operational endpoints are
locked before test access, and the finalizer verifies that selection did not change after
test metrics became available.

### M4 — identity and attestation

Each logical client is bound one-to-one to a node and TPM identity. An ESK-signed Enrollment
Request binds the client/node/TPM tuple, EK digest, separate AK and ESK public keys, TLS CSR,
and approved measurement-log digest. The authority issues a signed Enrollment Record and a
client certificate for the same identity.

The verifier issues a signed one-use challenge. The AK signs a TPM2 Quote over PCRs
`0,2,4,7,10` and the nonce. Appraisal independently replays the ordered measurement log,
checks the expected PCR values, certificate binding, enrollment, revocation state, and nonce,
then signs Attestation Result v2. The Admission Controller consumes this result; it cannot
approve its own attestation.

### M5 — secure campaign

The coordinator requires active enrollments and fresh passed attestations before issuing a
signed Round Context. That context binds the campaign, round, base model, training contract,
partition manifest, federation policy, client snapshot, and attestation.

Each isolated client mounts only its own snapshot and paired TPM socket, trains locally, and
signs its Update Bundle with the enrolled TPM ESK. Admission rechecks the complete chain,
round and client replay slot, model shape, finite tensors, digests, and policy. The checkpoint
lists every admitted bundle, decision, update, and example weight. Round `r` starts from the
accepted checkpoint of round `r - 1`.

### M6 — controlled Byzantine comparison

M6 begins from real, already verified M5 inputs. It deterministically freezes a clean or
attacked update set and binds the attacker identities, fault bound `f`, attack parameters,
and source round. FedAvg and the robust aggregators consume the same frozen bytes. This
separates the effect of aggregation from changes in client sampling, training, or attack
generation.

Prototype poisoning is evaluated independently from model-parameter poisoning because model
parameters and class prototypes have different structure and support semantics.

### M7 — investigation chain

A reportable prediction must resolve to the selected checkpoint, exact window, M2 snapshot,
normalized events, and controlled-ingestion source records. Explanations bind their baseline
and completeness checks; prototype distances use training-only centroids. ATT&CK mappings
use the predicted class and a versioned mapping table, never hidden reference labels.

The report is an interpretation layer. It cannot strengthen a model prediction into proof of
an incident, and unresolved multi-tactic cases remain explicit rather than being silently
forced to one technique.

### M8 — preservation and recovery

M8 closes the live experimental state in five verifiable stages:

1. inventory all required M2–M7 artifacts and declared external bindings;
2. commit artifact and binding leaves in a deterministic Merkle tree;
3. obtain and locally verify an RFC 3161 timestamp over the Merkle root;
4. create a deterministic offline TAR containing the payload and assurance material;
5. reconstruct the M5 campaign invariants from that recovery package.

The final verifier consumes the recovery and accounting workspaces and emits a receipt only
when preservation, Merkle commitment, timestamp, recovery payload, campaign accounting, and
final lineage all agree.

## Workspace contract

A generated workspace is treated as an immutable experiment object after successful
publication. Depending on the stage, it contains:

- one manifest or signed core identifying the schema and experiment;
- canonical configuration and upstream bindings;
- content-addressed or explicitly digested payloads;
- verification or finalization receipts;
- human-readable views derived from the same machine-readable source.

Writers use atomic publication and reject ambiguous pre-existing output. If inputs or policy
change, create a new workspace name; do not edit a finalized workspace in place.

`artifacts/` is operational evidence, not source code. It remains outside Git because it may
contain private keys, TPM state, model objects, large datasets, and multi-gigabyte archives.
M8 recovery packages should be retained in access-controlled external storage together with
the timestamp and final verification receipt.

## Cryptographic profile

- Canonicalization: RFC 8785/JCS-compatible integer-only manifest profile.
- Digest: SHA-256.
- Application signatures: ECDSA P-256 with SHA-256.
- Batch commitment: `SHA256(previous_chain_hash || content_sha256 || SHA256(JCS(core)))`.
- Transport target: TLS 1.3 with mutual client/service authentication.
- Attestation target: TPM2 Quote over a versioned PCR selection and fresh verifier nonce.
- Preservation commitment: deterministic binary Merkle tree with duplicate-last odd-node rule.
- External time evidence: RFC 3161 response bound to the SHA-256 Merkle root.

Floating-point values are excluded from signed manifest cores where canonical equivalence is
required; measurements are encoded using strings or scaled integers.

## Trust boundaries

- The server never mounts raw client evidence or client training workspaces.
- The M5 coordinator never mounts client snapshots; each client receives one snapshot only.
- A software TPM validates protocol behavior but cannot provide hardware non-exportability or
  protection from a hostile host administrator.
- The physical TPM adapter shares the artifact contract, but a completed hardware deployment
  is not part of the current reference results.
- A valid signature proves control of a key at signing time and integrity thereafter, not the
  semantic truth of signed content.
- A passed Quote proves consistency with the declared appraisal policy, nonce, identity, and
  measured state; it does not prove the entire host is uncompromised.
- Robust aggregation reduces specific modeled failures; it is not a cryptographic identity or
  intent detector.
- Explanations and ATT&CK mappings are model-derived analyst aids, not primary evidence.
- The RFC 3161 token anchors the committed root in time; it does not validate each artifact's
  substantive correctness.

## Deployment profiles

| Profile | Purpose | Assurance boundary |
|---|---|---|
| Local CLI | Deterministic generation, verification, and tests | Process/user account trust |
| Flower simulation | Runtime portability across 15 logical clients | Simulation scheduler and host |
| M4 Compose | Enrollment, mTLS, and 15 independent `swtpm` Quotes | Software-emulated TPMs |
| M5 Compose | Isolated, attestation-gated client training | Containers on one administrative host |
| Physical preflight | Validate access to a TPM 2.0 device | One prepared Linux node; run pending |
| M8 offline verification | Rebuild assurances without live M2–M7 workspaces | Integrity of retained package and trust material |

## Non-goals of the completed reference chain

The implementation does not claim production WORM storage, enterprise key rotation,
multi-host orchestration, confidential aggregation, differential privacy, statistical
confidence across repeated random seeds, physical-TPM fleet deployment, or external-dataset
generalization. These are explicit future validation or engineering tasks, not hidden
properties of the M1–M8 artifacts.
