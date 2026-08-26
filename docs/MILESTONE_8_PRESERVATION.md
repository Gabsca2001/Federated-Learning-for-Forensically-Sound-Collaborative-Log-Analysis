# Milestone 8 — preservation, timestamping, and offline recovery

## Purpose

M8 closes the canonical thesis experiment without retraining or reinterpreting its results.
It answers four practical questions:

1. **What exact bytes formed the final M2-to-M7 evidence chain?**
2. **Can one compact commitment detect a change to any included artifact or binding?**
3. **Can that commitment be shown to have existed by an independently signed time?**
4. **Can the chain and the M5 campaign invariants be verified without the live workspaces?**

The result is a deterministic offline recovery package plus a final verification receipt.
This is why `artifacts/` remains outside Git: source control preserves the implementation;
M8 preserves the generated evidentiary state.

## Canonical inputs

`configs/preservation-local-test-v1.yaml` freezes the upstream chain:

| Stage | Canonical input |
|---|---|
| M2 | `artifacts/m2-data24-parquet` |
| M3 | `artifacts/m3-data24-parquet-iid-local-test-v1` plus the selected partition/server manifests |
| M4 | `artifacts/m4-trust-local-test-v1` and declared public trust-policy context |
| M5 | `artifacts/m5-secure-multiround-local-test-v1` |
| M7 prediction | `artifacts/m7-prediction-bundle-test-first6-local-test-v1` |
| M7 explanation | `artifacts/m7-explanation-bundle-test-first6-local-test-v1` |
| M7 ATT&CK mapping | `artifacts/m7-attack-mapping-test-first6-local-test-v1` |
| M7 report | `artifacts/m7-investigation-report-test-first6-local-test-v1` |

The contract requires 30 M5 rounds and binds M7 to derivation round 11. A different campaign,
selected round, report, or configuration requires a new preservation workspace.

Private PEM keys and mutable challenge state are excluded by policy. They are operational
secrets/state, not recoverable public evidence. Seven declared external files are represented
as digest bindings; the recovery profile does not copy those external evidence files into the
archive (`include_external_evidence_files: false`).

## Assurance stages

### M8.1 — deterministic preservation inventory

```bash
fl-forensics m8-preserve \
  --config configs/preservation-local-test-v1.yaml \
  --output artifacts/m8-preservation-manifest-local-test-v1

fl-forensics m8-verify-preservation \
  --config configs/preservation-local-test-v1.yaml \
  --workspace artifacts/m8-preservation-manifest-local-test-v1
```

The generator walks only declared roots and required files, applies the exclusions, records
each relative path, size, SHA-256 digest, and stage classification, and validates required
campaign/lineage semantics before publication.

The workspace contains:

- `preservation-manifest.json`: canonical inventory and external bindings;
- `manifest.json`: workspace identity and output digests.

It is an inventory, not yet a copy of all payload bytes.

Reference result:

| Field | Value |
|---|---|
| Preservation ID | `m8-preservation-ef926a6449b257ad9602bb5a` |
| Inventoried artifacts | 2,381 |
| Inventoried payload bytes | 2,642,172,551 |
| External bindings | 7 |
| Inventory SHA-256 | `65837ed9e7e962d8cdc38359539edb81a3e35ca6b2887013aa3943abccf07e78` |

The verifier reconstructs the inventory from the live declared inputs and rejects a missing,
extra, moved, resized, or modified required object.

### M8.2 — Merkle commitment

```bash
fl-forensics m8-build-merkle \
  --config configs/merkle-local-test-v1.yaml \
  --output artifacts/m8-merkle-tree-local-test-v1

fl-forensics m8-verify-merkle \
  --config configs/merkle-local-test-v1.yaml \
  --workspace artifacts/m8-merkle-tree-local-test-v1
```

The leaves cover 2,381 artifact entries plus seven external bindings. Sorting, leaf encoding,
node encoding, and the duplicate-last rule for an odd level are deterministic. The complete
tree is stored so the verifier can recompute every level and the root.

| Field | Value |
|---|---|
| Merkle tree ID | `m8-merkle-tree-97e2d8a71d5b1ef11fb6c91c` |
| Leaves | 2,388 |
| Levels | 13 |
| Root SHA-256 | `fe42748433c74195479579d7fe1f133d703f87ca601610224f200f219c585453` |

A matching root proves consistency with the committed leaf set. It does not independently
establish that each source artifact was semantically correct.

### M8.3 — RFC 3161 time anchor

```bash
fl-forensics m8-anchor-time \
  --config configs/timestamp-local-test-v1.yaml \
  --output artifacts/m8-timestamp-anchor-local-test-v1

fl-forensics m8-verify-timestamp \
  --config configs/timestamp-local-test-v1.yaml \
  --workspace artifacts/m8-timestamp-anchor-local-test-v1
```

`m8-anchor-time` is the only M8 step that needs network access. It submits the SHA-256 Merkle
root to the configured RFC 3161 timestamp authority and validates the response before
publication. The workspace retains the subject, request, response, parsed proof, TSA
certificate material, and the trust store used for offline verification.

| Field | Value |
|---|---|
| Timestamp ID | `m8-timestamp-anchor-88a57203d1340ff4892778e1` |
| Generation time | `Aug 26 12:28:09 2026 GMT` |
| Policy OID | `2.16.840.1.114412.7.1` |
| Response SHA-256 | `495763ccd6b1acd97cc08ac2daf6bd383e6d709c0b08343141a5fa349deeec5f` |

Offline verification checks the signed response, certificate chain against the retained
trust context, message imprint, policy, and subject binding. Long-term archival policy must
still decide how trust stores, algorithm deprecation, and certificate status are handled over
time.
At M8.3 this command also reconstructs the configured M8.2 workspace; verification with no
live M2–M8.3 source directories is provided by the M8.4 recovery verifier.

### M8.4 — deterministic recovery export

```bash
fl-forensics m8-export-recovery \
  --config configs/recovery-local-test-v1.yaml \
  --output artifacts/m8-recovery-export-local-test-v1

fl-forensics m8-verify-recovery \
  --workspace artifacts/m8-recovery-export-local-test-v1
```

This is the stage that actually copies the preserved payload into a self-contained archive.
“Self-contained” here means sufficient for the implemented offline verification profile; the
seven externally bound files still require separate retention. The deterministic USTAR
package contains the 2,381 inventoried artifact files and 11 assurance
entries needed to authenticate the inventory, Merkle tree, and timestamp. Paths, ordering,
metadata, and archive serialization are normalized so an equivalent export has a stable
identity.

The outer workspace contains:

- `recovery-export.tar`: the offline payload and assurance package;
- `package-inventory.json`: every archive member, size, role, and digest;
- `recovery-manifest.json`: package identity and upstream commitments;
- `manifest.json`: workspace output digests.

| Field | Value |
|---|---|
| Recovery ID | `m8-recovery-export-76702dfab9ac61350f18b31c` |
| Package ID | `m8-recovery-package-de3039b335b122bd831e0d07` |
| Payload entries | 2,381 |
| Assurance entries | 11 |
| Archive bytes | 2,648,248,320 |
| Archive SHA-256 | `d8c3e72733616c85d9c899f15f6f3e2947f24a6be2fb604e82ef8baf567ae9e2` |

`m8-verify-recovery` deliberately verifies from the archive rather than trusting the live
M2–M7 directories. It re-hashes the package, checks every member against the inventory,
recomputes the Merkle root, and validates the retained timestamp evidence.

### M8.5 — offline campaign invariant accounting

```bash
fl-forensics m8-account-campaign \
  --config configs/campaign-accounting-local-test-v1.yaml \
  --output artifacts/m8-campaign-invariant-accounting-local-test-v1

fl-forensics m8-verify-campaign-accounting \
  --workspace artifacts/m8-campaign-invariant-accounting-local-test-v1 \
  --recovery-workspace artifacts/m8-recovery-export-local-test-v1
```

Accounting reads M5 and trust evidence through the recovery package. It does not consult the
live campaign workspace. The checks cover campaign/round continuity, 15-client participation,
attestation refresh intervals, identities, contexts, accepted decisions, contribution counts,
example weighting, checkpoint linkage, selected round, and final M7 lineage. Creation validates
the versioned campaign and trust roots against the authenticated preservation inventory; the
standalone verifier reconstructs those roots from the same inventory instead of relying on
hard-coded workspace names.

| Field | Value |
|---|---|
| Accounting ID | `m8-campaign-accounting-754be120eb3082973ded38af` |
| Campaign ID | `campaign-aa22aafea800a7d59fe308fc` |
| Rounds | 30 |
| Clients | 15 |
| Contributions | 450 |
| Invariant checks | 3,150 |
| Accounted training examples | 212,880 |
| Attestation references | 90 |

### M8.6 — final preservation verification

```bash
fl-forensics m8-verify-final-preservation \
  --recovery-workspace artifacts/m8-recovery-export-local-test-v1 \
  --accounting-workspace artifacts/m8-campaign-invariant-accounting-local-test-v1
```

This command is read-only and creates no new workspace. It composes the offline recovery and
accounting verifiers and emits the final receipt to standard output.

Reference result:

| Field | Value |
|---|---|
| Status | `verified` |
| Verified stages | 5 |
| Errors | 0 |
| Offline inputs only | `true` |
| Final verification ID | `m8-final-verification-18a7463101b543b5f97df3f1` |
| Canonical core SHA-256 | `18a7463101b543b5f97df3f18f556840f1eb8dd1de9f26593c4c70555e61f9fe` |
| Receipt SHA-256 | `bd4b5561b88a59c91af5460897153311346b0426c5fd1bc5f94c0c3d53d0ed39` |

The final assurance state is
`merkle-committed-time-anchored-recovery-exported-campaign-accounted-finally-verified`.

## What is saved and what is reconstructed

| Object | Saved directly? | Reconstructed or checked later? |
|---|---|---|
| M2–M7 payload files | Copied into recovery TAR | Size/digest and cross-stage references |
| Private signing keys | No; excluded | Not reconstructed |
| Mutable challenge state | No; excluded | Relevant immutable attestation evidence is checked |
| External bound files | Digest/path binding only in this profile | Binding integrity; bytes require separate retention |
| Preservation inventory | Yes | Rebuilt against package entries |
| Merkle tree | Yes | Every level and root recomputed |
| RFC 3161 request/response/certificates | Yes | Signature, chain, imprint, policy, and root binding |
| M5 campaign records | Yes, as payload | Round chain, clients, decisions, contributions, weights |
| M7 investigation artifacts | Yes, as payload | Final report lineage back to M2 source records |
| Final verification output | Printed receipt | Deterministically reproducible from retained inputs |

In short, M8 saves both the experiment bytes needed for recovery and the independent assurance
material needed to detect tampering. It reconstructs relationships and invariants rather than
merely checking that an archive can be opened.

## Retention and restoration procedure

Before removing live `artifacts/` workspaces:

1. run all six M8 stages and require zero errors;
2. retain `recovery-export.tar`, its outer manifests, the accounting workspace, and a captured
   copy of the final JSON receipt;
3. retain the seven externally bound files separately when policy requires their bytes;
4. copy the retained material to access-controlled storage with redundancy and retention;
5. record the archive SHA-256 and Merkle root in the thesis experiment register;
6. test restoration in an empty directory using `m8-verify-recovery` and
   `m8-verify-final-preservation`.

Do not treat a Git commit, cloud-sync success message, or archive existence as verification.
The acceptance condition is successful offline reconstruction from the retained package.

## Limitations

- The recovery TAR is not encrypted by this workflow; storage encryption and access control
  are deployment responsibilities.
- The archive is large because it retains the actual experimental payload rather than only
  hashes.
- Excluded secrets cannot be recovered from M8 and must have their own secure key-management
  lifecycle if operational reuse is required.
- The timestamp proves existence of the committed root no later than the signed time, subject
  to the TSA and retained trust context; it does not prove evidentiary meaning.
- M8 preserves one declared reference chain. A new run, changed report, or changed policy
  requires a new inventory, root, timestamp, and recovery package.
- Long-term legal admissibility depends on jurisdiction, procedures, documentation, and
  organizational controls beyond this software prototype.
