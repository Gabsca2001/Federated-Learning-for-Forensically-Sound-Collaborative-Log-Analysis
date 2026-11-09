# Live derivation campaign with swtpm

References: R03–R09. This laboratory protocol connects actual training, fresh
attestation, composite admission, receipts, multiround derivation, and computed
M7 products. It uses 15 distinct swtpm instances and the tpm2-tools interfaces.
This is not a physical-TPM experiment: the inspected WSL environment exposes
neither `/dev/tpm0` nor `/dev/tpmrm0`.

`scripts/revision_attested_chain.py` creates three three-round trajectories:
baseline, removal of client15 before training in the first round only, and a
control without intervention. Every client participates again in later rounds.
The dataset, class weights, local algorithm, seeds, and client order are the
same; each branch uses its own current checkpoint. Statistical decisions are
recomputed by `admit_and_aggregate_in_round`, without substituting fixtures for
the actual scoring operation.

The runtime is built with `Dockerfile.revision-live` and preserved as a Docker
image identified by digest. The dedicated configurations are
`configs/revision-live-federation.yaml` and `configs/revision-live-trust.yaml`.
The PCR baseline measures the complete Python package and the declared scripts
and configurations. Changing these bytes requires a new baseline and new
workspaces: do not reuse attestations from an older source release.

Each round follows this order:

1. Issue a challenge with a fresh nonce for each of the 15 clients.
2. Produce an AK/PCR Quote and verify it with `tpm2_checkquote`, then sign the context.
3. Train locally from the current base, produce an Update Bundle signed by the
   TPM ESK, and retain a receipt copy in that client's volume.
4. Collect the copies and sign the input inventory before making decisions.
5. Bind the derivation, evaluate trust/scoring/policy, and aggregate.
6. Fully verify receipts, decisions, masses, coefficients, and the checkpoint.

Each client mounts only its own socket, enrollment, partition, submission, and
receipt-copy volume, together with read-only public inputs. It does not mount
the Docker socket or the emulator's persistent state. Laboratory transport uses
isolated local volumes; this campaign does not measure network performance or
administrative independence across distributed operators.

## Receipt snapshot for subsequent verification

The round retains `client-receipts/`, an exact copy of the external receipt
collection used to commit the inventory. The original volumes are preserved
separately in the experimental workspace. The campaign verifier and M7
checkpoint verifier pass this directory to the full round verifier. Client
signatures and committed digests remain the validity checks.

A local receipt does not become an administratively independent witness.
Completeness remains relative to the supplied evidence; a client signature
proves neither delivery nor compliance with an external deadline. Verification
of a bound round without the required evidence must fail, without falling back
to the legacy profile.

## Products and comparison

The third baseline and removal rounds produce predictions for the first two
validation windows in lexicographic order, Integrated Gradients, prototype
references, ATT&CK mappings, and reports. Selection does not use labels,
predictions, or metrics. The M7 verifiers repeat the relevant computations.

The graph binds the nine round occurrences and the products actually created.
The query retains numerical, decision, and audit paths; numerical effects are
reported separately by comparing models. The control without intervention must
produce the same model bytes as the baseline in every round. Quotes,
timestamps, contexts, and signatures belong to fresh executions and are not
expected to have identical bytes.

A signed experimental manifest links the protocol, selected historical
submission, removal schedule, branch derivations, and comparison. Removing a
benign contribution selected in advance demonstrates the replay mechanism; it
does not demonstrate malicious intent, damage, or certified unlearning.

## Operation and preservation

The runner requires Docker and the M2 data in `artifacts/m2-data24-parquet`.
It does not start or reset earlier project instances: it creates containers
and directories dedicated to the experiment version. Incomplete attempts must
be preserved and identified; do not present them as verified trajectories.

Offline verification uses the preserved image and public evidence package,
with M2 mounted read-only. It does not require coordinator or client private
keys. Do not regenerate artifacts as a substitute for verifying historical
evidence. Summaries, outputs, and hashes are retained in the original local experiment workspace
report under `output/live-chain-20261102` and in the laboratory workspace
identified by that report.

Graph closure is relative to the supplied manifest view. Fresh attestation
cannot establish that no unregistered products exist; that stronger property
would require independent registration with a declared boundary.
