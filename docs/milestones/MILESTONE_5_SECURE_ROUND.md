# Milestone 5 — attestation-gated secure federated round

## Purpose and scope

M3 remains the reproducible 30-round scientific baseline. M5 adds the missing
operational security boundary around one equivalent FedAvg round: 15 separate
client containers train on 15 separately mounted snapshots, each contribution
is signed by that client's enrolled TPM ESK, and a coordinator aggregates only
after validating the complete M4 and M5 binding chain.

M4 answers *which measured node and key are trusted now*; M5 answers *whether
this exact update was produced for this exact round, base model, snapshot, and
active attestation*. A successful M3 run alone does not answer either question.

## Data and privilege boundaries

- `clientNN` mounts only its own `dataset.json`, partition manifest, node
  workspace, paired TPM socket, public round files, and private submission
  directory.
- Client containers have a read-only root filesystem, no Linux capabilities,
  `no-new-privileges`, and no network namespace.
- The coordinator never mounts client datasets. It sees the public partition
  manifest, M4 trust registry/results, and submitted bundle directories.
- Each TPM service has a private state volume and exports only its own socket.
- `swtpm` validates protocol behavior; it does not protect against a hostile
  host administrator.
- The present PCR profile is a source-file measurement prototype, not a Linux
  measured-boot proof of the final container image or resolved dependency
  graph. Image-digest attestation remains later hardening work. M8 now anchors
  the final preservation Merkle root with an RFC 3161 timestamp; that closes
  the preserved campaign but does not convert the M5 PCR profile into a
  measured-boot proof.

## Signed and committed artifacts

1. The coordinator validates all 15 current Attestation Result v2 objects and
   their enrollment, revocation, node, and mTLS bindings.
2. It signs a short-lived `secure_round_context` containing the base-model,
   training-contract, federation-config, partition-manifest, snapshot,
   enrollment, and attestation commitments.
3. Each client trains from the committed base model and writes immutable
   `update.json` and `metrics.json` objects.
4. The TPM ESK signs a `secure_update_bundle` core that commits to those objects
   and every round/client binding.
5. The coordinator preserves a signed `secure_contribution_decision` after
   checking the ESK signature, fresh M4 attestation, active enrollment, exact
   round/base/snapshot, row count, file digests, tensor names/shapes/dtypes, and
   finite numeric values.
6. The replay slot is `(campaign, round, client)`. An identical bundle is an
   idempotent retry; a different bundle in an occupied slot is quarantined.
7. Exactly 15 accepted decisions are required. The signed checkpoint manifest
   lists every actual decision, bundle, update digest, and example weight.
8. `m5-verify` independently reloads the 15 updates and recomputes FedAvg byte
   for byte. `matches_reference_checkpoint` refers to this independent
   recomputation, not to test-set model selection or the M3 selected checkpoint.

## Why a fresh M4 baseline is required

The M5 trust profile measures the secure client image, topology, secure-round
implementation and schemas, TPM signing adapter, model code, and federation
policy. TPM PCRs enrolled under the previous M4-only measurement list cannot
truthfully attest this enlarged runtime. Preserve old artifacts if useful, but
provision a new namespace and enrollment for the M5 experiment.

Build the relatively large M5 image before issuing the short-lived final
attestations:

```bash
export COMPOSE_PROJECT_NAME=flforensics_m5

python scripts/run_m5_secure_round.py build \
  --partition-workspace artifacts/m3-data24-parquet-iid
```

Then initialize and provision fresh measured state, enroll it, and run M4:

```bash
fl-forensics m4-init --workspace artifacts/m4-trust --project-root .
python scripts/run_m4_swtpm.py provision
fl-forensics m4-enroll \
  --workspace artifacts/m4-trust \
  --node-root artifacts/m4-nodes
fl-forensics m4-mtls-test \
  --workspace artifacts/m4-trust \
  --node-root artifacts/m4-nodes
fl-forensics m4-challenge \
  --workspace artifacts/m4-trust \
  --node-root artifacts/m4-nodes
python scripts/run_m4_swtpm.py quote
docker compose -f compose.m4.yaml --profile verify run --rm verifier
```

If the default M4 artifact directories contain an earlier campaign, move them
to clearly named archive directories before `m4-init`; do not mix measurement
baselines in one registry. The new Compose project name creates new TPM volumes
without deleting the old namespace.

## Runtime gate

Immediately after M4 reports 15 passed clients, run:

```bash
python scripts/run_m5_secure_round.py run \
  --partition-workspace artifacts/m3-data24-parquet-iid \
  --workspace artifacts/m5-secure-round \
  --workers 4
```

Do not stop or recreate the TPM services between Quote verification and M5.
The orchestrator deliberately refuses to start a missing TPM service because a
restart changes volatile PCR state and requires a fresh M4 attestation.

The final verifier output must contain:

```json
{
  "accepted_count": 15,
  "error_count": 0,
  "matches_reference_checkpoint": true,
  "status": "verified"
}
```

The actions `prepare`, `clients`, `aggregate`, and `verify` may be run
separately for debugging. `stop` stops containers without `--volumes`.

## Negative acceptance coverage

Automated tests cover a nominal ESK-signed bundle, wrong base-model binding,
content tampering, revocation, non-finite tensors, the 15 isolated
client/TPM/snapshot mount pairs, and the mandatory security policy. Runtime
verification additionally checks all checkpoint input hashes and recomputes the
weighted aggregate.
