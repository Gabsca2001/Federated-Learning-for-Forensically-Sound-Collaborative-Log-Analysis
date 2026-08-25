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

`configs/preservation.yaml` freezes the upstream chain:

| Stage | Canonical input |
|---|---|
| M2 | `artifacts/m2-data24-parquet` |
| M3 | `artifacts/m3-data24-parquet-iid` plus the selected partition/server manifests |
| M4 | `artifacts/m4-trust` and declared public trust-policy context |
| M5 | `artifacts/m5-secure-multiround-v2` |
| M7 prediction | `artifacts/m7-prediction-bundle-test-first6-v1` |
| M7 explanation | `artifacts/m7-explanation-bundle-test-first6-v1` |
| M7 ATT&CK mapping | `artifacts/m7-attack-mapping-test-first6-v1` |
| M7 report | `artifacts/m7-investigation-report-test-first6-v1` |

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
  --config configs/preservation.yaml \
  --output artifacts/m8-preservation-manifest-v1

fl-forensics m8-verify-preservation \
  --config configs/preservation.yaml \
  --workspace artifacts/m8-preservation-manifest-v1
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
| Preservation ID | `m8-preservation-07101d8294c8798f9a0b8f15` |
| Inventoried artifacts | 2,363 |
| Inventoried payload bytes | 2,631,940,087 |
| External bindings | 7 |
| Inventory SHA-256 | `b32c5a97e52b69105b7b9777eb7ce7d302f18c8c568558a2f86fb8a63b0afdde` |

The verifier reconstructs the inventory from the live declared inputs and rejects a missing,
extra, moved, resized, or modified required object.

### M8.2 — Merkle commitment

```bash
fl-forensics m8-build-merkle \
  --config configs/merkle.yaml \
  --output artifacts/m8-merkle-tree-v1

fl-forensics m8-verify-merkle \
  --config configs/merkle.yaml \
  --workspace artifacts/m8-merkle-tree-v1
```

The leaves cover 2,363 artifact entries plus seven external bindings. Sorting, leaf encoding,
node encoding, and the duplicate-last rule for an odd level are deterministic. The complete
tree is stored so the verifier can recompute every level and the root.

| Field | Value |
|---|---|
| Merkle tree ID | `m8-merkle-tree-bd598d3ac8ed86eacff47611` |
| Leaves | 2,370 |
| Levels | 13 |
| Root SHA-256 | `7009578ca603562350a1ed469ed434c932b114154afd5da75fb5e1b89b0a449e` |

A matching root proves consistency with the committed leaf set. It does not independently
establish that each source artifact was semantically correct.

### M8.3 — RFC 3161 time anchor

```bash
fl-forensics m8-anchor-time \
  --config configs/timestamp.yaml \
  --output artifacts/m8-timestamp-anchor-v1

fl-forensics m8-verify-timestamp \
  --config configs/timestamp.yaml \
  --workspace artifacts/m8-timestamp-anchor-v1
```

`m8-anchor-time` is the only M8 step that needs network access. It submits the SHA-256 Merkle
root to the configured RFC 3161 timestamp authority and validates the response before
publication. The workspace retains the subject, request, response, parsed proof, TSA
certificate material, and the trust store used for offline verification.

| Field | Value |
|---|---|
| Timestamp ID | `m8-timestamp-anchor-7fe093ea54ecce8bf8e791db` |
| Generation time | `Aug 25 10:54:41 2026 GMT` |
| Policy OID | `2.16.840.1.114412.7.1` |
| Response SHA-256 | `f019fe4f088ff483f4d19f4af8ca2ada68d27b46e6da8370eee657c7f7613aa8` |

Offline verification checks the signed response, certificate chain against the retained
trust context, message imprint, policy, and subject binding. Long-term archival policy must
still decide how trust stores, algorithm deprecation, and certificate status are handled over
time.
At M8.3 this command also reconstructs the configured M8.2 workspace; verification with no
live M2–M8.3 source directories is provided by the M8.4 recovery verifier.

### M8.4 — deterministic recovery export

```bash
fl-forensics m8-export-recovery \
  --config configs/recovery.yaml \
  --output artifacts/m8-recovery-export-v1

fl-forensics m8-verify-recovery \
  --workspace artifacts/m8-recovery-export-v1
```

This is the stage that actually copies the preserved payload into a self-contained archive.
“Self-contained” here means sufficient for the implemented offline verification profile; the
seven externally bound files still require separate retention. The deterministic USTAR
package contains the 2,363 inventoried artifact files and 11 assurance
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
| Recovery ID | `m8-recovery-export-eec242458090f9a22b62d86a` |
| Package ID | `m8-recovery-package-813e4ac3b68fcedda9aa9ec2` |
| Payload entries | 2,363 |
| Assurance entries | 11 |
| Archive bytes | 2,637,803,520 |
| Archive SHA-256 | `8f136f00ae8cdaa0b480e96bdfc81c193f46e070fee3ff3d43b7798322a0fc68` |

`m8-verify-recovery` deliberately verifies from the archive rather than trusting the live
M2–M7 directories. It re-hashes the package, checks every member against the inventory,
recomputes the Merkle root, and validates the retained timestamp evidence.

### M8.5 — offline campaign invariant accounting

```bash
fl-forensics m8-account-campaign \
  --config configs/campaign-accounting.yaml \
  --output artifacts/m8-campaign-invariant-accounting-v1

fl-forensics m8-verify-campaign-accounting \
  --workspace artifacts/m8-campaign-invariant-accounting-v1 \
  --recovery-workspace artifacts/m8-recovery-export-v1
```

Accounting reads M5 and trust evidence through the recovery package. It does not consult the
live campaign workspace. The checks cover campaign/round continuity, 15-client participation,
attestation refresh intervals, identities, contexts, accepted decisions, contribution counts,
example weighting, checkpoint linkage, selected round, and final M7 lineage.

| Field | Value |
|---|---|
| Accounting ID | `m8-campaign-accounting-8145d39622bf25d39a135c38` |
| Campaign ID | `campaign-0824bcc4005bacc3420d2c1b` |
| Rounds | 30 |
| Clients | 15 |
| Contributions | 450 |
| Invariant checks | 3,150 |
| Accounted training examples | 212,880 |
| Attestation references | 90 |

### M8.6 — final preservation verification

```bash
fl-forensics m8-verify-final-preservation \
  --recovery-workspace artifacts/m8-recovery-export-v1 \
  --accounting-workspace artifacts/m8-campaign-invariant-accounting-v1
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
| Final verification ID | `m8-final-verification-2b1eb8e1ecba88dcaf234edc` |
| Canonical core SHA-256 | `2b1eb8e1ecba88dcaf234edc8c323fb139aa33bb299ded66ecfeee68471835de` |
| Receipt SHA-256 | `1a423720c396277ab77356670b8ba9b798a2e6be882b54b6a26ed0752ea40848` |

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
