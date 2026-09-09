# Real post-training TPM attestation failure

## Purpose

The completed M6 disagreement campaign uses genuine update anomalies but intentionally models
its failed-trust cells as controlled policy inputs: all underlying `swtpm` appraisals pass. This
separate experiment closes that validation gap without rewriting the preserved reference run.
It asks a narrower runtime question:

> If a client is authorized to train, but a fresh TPM Quote reports a changed measured state
> before aggregation, does the deployed admission path exclude its signed update from FedAvg?

The experiment does not use a Boolean failure flag and does not edit an Attestation Result. It
extends a real `swtpm` PCR, issues a new one-use challenge, obtains an AK-signed Quote over the
new PCR value, and lets the M4 verifier issue a signed `failed_measurement` result.

## Round sequence

The opt-in contract in `configs/real-attestation-failure.yaml` is copied into every round's
public workspace before the Round Context is signed. The configured intervention is active only
for `client03` in round 30.

1. The ordinary M4 gate appraises all 15 clients. The passing result bound into the Round
   Context authorizes local training.
2. All 15 isolated clients train and TPM ESK-sign their Update Bundles.
3. Before aggregation, `client03` extends PCR 10 with the declared SHA-256 measurement.
4. A new signed challenge and AK-signed Quote are created only for `client03`.
5. M4 verifies the Quote's AK, nonce, identity, certificate, and observed PCRs, but rejects the
   measurement against the enrolled baseline as `failed_measurement`.
6. The already computed update is retained as an experimental probe. Its bytes and metrics do
   not change; the client ESK re-signs only the bundle metadata so it references the new signed
   appraisal. The original bundle is preserved as `pre-reattestation-bundle.json`.
7. The in-round M5/M6 gate accepts the bundle's structure, identity, ESK signature, and digests,
   fails only `fresh_attestation`, emits `trust_quarantined`, and gives the update zero effective
   FedAvg weight.
8. The ordinary round verifier recomputes the remaining weighted FedAvg. The experiment verifier
   additionally proves Quote authenticity against the observed PCR value, event chronology, the
   failed baseline appraisal, and absence of `client03` from checkpoint inputs.

This post-training placement is deliberate. It simulates a measured-state change between the
authorization and commit boundaries and produces an update whose exclusion can be verified.
In production, an earlier continuous-attestation failure could also stop local work and avoid
the wasted computation; that is a different availability/efficiency policy.

## Fresh workspace requirement

The new source files are part of M4 measurement baseline `1.3`. Historical trust/node workspaces
belong to older baselines and must not be reused or overwritten. Create fresh workspaces and a
fresh Compose project:

```bash
export COMPOSE_PROJECT_NAME=flforensics_real_attestation_failure_v1
export M4_TRUST_WORKSPACE="$PWD/artifacts/m4-trust-real-attestation-failure-v1"
export M4_NODE_ROOT="$PWD/artifacts/m4-nodes-real-attestation-failure-v1"

fl-forensics m4-verify-deployment \
  --compose compose.m4.yaml \
  --clients configs/clients.yaml

fl-forensics m4-init \
  --workspace "$M4_TRUST_WORKSPACE" \
  --project-root .

python scripts/run_m4_swtpm.py provision \
  --trust-workspace "$M4_TRUST_WORKSPACE" \
  --node-root "$M4_NODE_ROOT"

fl-forensics m4-enroll \
  --workspace "$M4_TRUST_WORKSPACE" \
  --node-root "$M4_NODE_ROOT"

fl-forensics m4-mtls-test \
  --workspace "$M4_TRUST_WORKSPACE" \
  --node-root "$M4_NODE_ROOT"
```

Confirm that the 15 TPM services are healthy before starting the campaign:

```bash
docker compose -f compose.m5.yaml ps --services --status running \
  | grep -c '^tpm'
```

The expected count is `15`. Then run and independently verify the complete 30-round campaign:

```bash
python scripts/run_m4_m6_real_attestation_failure.py run \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --workspace artifacts/m6-real-attestation-failure-local-test-v1 \
  --trust-workspace "$M4_TRUST_WORKSPACE" \
  --node-root "$M4_NODE_ROOT" \
  --rounds 30 \
  --workers 8 \
  --attestation-refresh-interval 3

python scripts/run_m4_m6_real_attestation_failure.py verify \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --workspace artifacts/m6-real-attestation-failure-local-test-v1 \
  --trust-workspace "$M4_TRUST_WORKSPACE" \
  --node-root "$M4_NODE_ROOT" \
  --rounds 30 \
  --workers 8 \
  --attestation-refresh-interval 3
```

The effective refresh interval of three rounds is part of this completed run's execution
contract. It was chosen after the first partial attempt showed that long local execution could
outlive the wider cadence; it does not alter the active round-30 intervention.

## Evidence to inspect

The active round retains the most useful proof objects under:

```text
artifacts/m6-real-attestation-failure-local-test-v1/
└── rounds/round-030/
    ├── public/real-attestation-failure-contract.json
    ├── real-attestation-evidence/
    │   ├── pcr-mutation.json
    │   ├── quote-evidence.json
    │   └── attestation-result.json
    ├── submissions/client03/
    │   ├── pre-reattestation-bundle.json
    │   ├── bundle.json
    │   ├── update.json
    │   └── metrics.json
    ├── decisions/client03.json
    ├── in-round-decisions/client03.json
    └── checkpoint/manifest.json
```

The completed experiment-verifier summary contains `authentic_quote_verified: true`,
`failed_measurement_verified: true`, `fedavg_exclusion_verified: true`, and zero errors. Across
450 submissions, 368 were fully accepted, 75 were downweighted, six were statistically
quarantined, and exactly one (`client03`) was trust-quarantined. The selected round is 25, with
validation macro-F1 `0.961719`, isolated test macro-F1 `0.935467`, and test accuracy `0.976504`.

The clean paired campaign also selected round 25. Because the real failure occurs only in round
30, selected validation and test metrics are identical by construction; this is not evidence
that TPM exclusions generally have zero utility cost. At the active round, validation macro-F1
remains `0.900661`, validation loss changes by `-0.000813667`, and the clean/failure checkpoint
distance is `0.020355122` L2. Restoring only the target's nominal weight produces an independently
reconstructed aggregate shift of `0.020356380` L2.

Generate a pure verifier receipt and rebuild the sanitized snapshot with:

```bash
fl-forensics m6-verify-real-attestation-failure-round \
  --workspace artifacts/m6-real-attestation-failure-local-test-v1/rounds/round-030 \
  --trust-workspace artifacts/m4-trust-real-attestation-failure-v1 \
  --submissions artifacts/m6-real-attestation-failure-local-test-v1/rounds/round-030/submissions \
  > /tmp/m6-real-attestation-verification.json

python scripts/render_real_attestation_failure_summary.py \
  --workspace artifacts/m6-real-attestation-failure-local-test-v1 \
  --trust-workspace artifacts/m4-trust-real-attestation-failure-v1 \
  --clean-workspace artifacts/m5-in-round-composite-local-test-v1 \
  --clean-results results/m5-in-round-composite-local-test-v1 \
  --verification-receipt /tmp/m6-real-attestation-verification.json \
  --attestation-refresh-interval 3 \
  --output results/m6-real-attestation-failure-local-test-v1 \
  --replace-existing-snapshot
```

The public snapshot includes a compact receipt, all 450 outcome rows, the human-readable target
explanation, source hashes, and four thesis-facing figures. It deliberately excludes raw Quotes,
updates, models, certificates, and private TPM/trust state.

## Claim boundary

The run validates the protocol with one real software TPM state transition, one client, one late
round, and one seed. It does not estimate the population-level utility cost of earlier or repeated
failures, and it does not establish
physical TPM key non-exportability, resistance to a compromised host controlling the data before
measurement, WAN behavior, or production revocation/storage guarantees. It complements rather
than replaces the controlled 2×2 disagreement experiment: the latter compares policies with both
signals available; this run validates the concrete fail-closed M4→M5/M6 enforcement path.
