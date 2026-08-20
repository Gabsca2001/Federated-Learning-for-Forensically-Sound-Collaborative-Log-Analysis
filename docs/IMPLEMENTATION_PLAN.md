# Incremental implementation plan

Each milestone ends with an executable acceptance gate. A later milestone may add fields or artifact types, but it must not silently rewrite previously preserved objects.

| Milestone | Deliverable | Acceptance gate | Thesis requirements |
| --- | --- | --- | --- |
| M0 — Contract | Repository, configs, artifact schemas, architecture map | Configuration and schemas load; status is explicit | SIC6, FOR5, ML2 |
| M1 — Evidence vertical slice | Acquisition, hash chain, ECDSA, signed attestation result, admission, content-addressed vault, custody chain, deterministic snapshot | Tampering, wrong identity, expired attestation, chain conflict, and raw/snapshot separation are tested | SIC1–SIC5, FOR1–FOR5 |
| M2 — Data and centralized baseline | UWF-ZeekData24 inventory, group/time split, frozen feature schema, scaler fitted on training only, MLP encoder+head | Repeated preprocessing yields the same digest; centralized metrics include macro-F1 and per-class recall | ML2–ML4, ML8 |
| M3 — Federated baseline | 15 logical clients, IID/non-IID manifests, Flower ClientApp/ServerApp, FedAvg, round audit, model registry | No raw client mount at server; same frozen snapshots support local and FedAvg comparisons | ML1, ML3, ML4, FOR6 |
| M4 — Trust deployment | 15 `swtpm` pairs, enrollment, AK/ESK separation, Quote verification, mTLS, physical TPM adapter | Nonce replay, altered measurement, revoked identity, and wrong pair are rejected and preserved | SIC1–SIC6, FOR1–FOR4 |
| M5 — Secure round protocol | Signed round context and Update Bundles, replay/idempotency checks, structural validator, checkpoint manifests | Wrong round/base model/snapshot/tensor is rejected; every checkpoint lists actual inputs | SIC4, SIC7, FOR6, FOR8 |
| M6 — Byzantine experiments | Label flip, Gaussian noise, sign flip, model replacement, backdoor, prototype poisoning, collusion; clipping and robust aggregators | Same frozen updates feed FedAvg, median, trimmed mean, MultiKrum, Bulyan; invalid `n,f` halts explicitly | ML5–ML8, T1–T4 |
| M7 — Investigation | Inference bundles, Integrated Gradients, prototype distances, ATT&CK mapping, deterministic report | A prediction is reportable only with complete, digest-valid lineage to Zeek events | FOR6, FOR9, FOR10, ML9 |
| M8 — Campaign and recovery | Experiment manifests, repeated seeds, contamination propagation, rollback branch, root anchoring, export | Invariants have zero violations; statistical results include dispersion and confidence intervals | SIC8, FOR2–FOR10 |

The optional secure-aggregation profile is evaluated only after M6 because it conflicts with defenses that require inspection of individual updates. Optional DP-SGD is outside the core acceptance path and must not delay the thesis experiments.

## Completed M2 gate

The M2 gate uses UWF-ZeekData24 exclusively. The official CSV bytes are verified against a controlled-ingestion manifest; the audit records the real schema and dataset risks; capture dates are split without group overlap; the final week is isolated as a temporal holdout; standardization is fitted on training only; and the centralized MLP emits macro metrics, per-class recall/support, confusion matrices, model weights, and digest-linked manifests. Two independent preparations of the real release produced the same dataset and scaler SHA-256 digests.

## M3 implementation gate

M3 freezes two 15-client partition profiles over the verified M2 snapshot. IID is
stratified round-robin; non-IID is label-Dirichlet with `alpha = 0.3`. The
partition verifier enforces exact one-client coverage of every training and
validation window and prevents raw-event fields from entering client or server
feature artifacts. The clean PyTorch/Flower runner preserves content-addressed
local updates and global checkpoints, chains round records, performs full-client
example-weighted FedAvg, and records a local-only comparison. Runtime execution
and final metric validation remain the acceptance gate before M3 is marked
complete.

## M4 implementation gate

M4 preserves new versioned Enrollment Request, Enrollment Record, Attestation
Challenge, Quote Evidence, Revocation Record, and Attestation Result v2 objects.
The Compose topology statically enforces 15 one-to-one client/swtpm socket pairs
without client access to TPM state. The Verifier reconstructs PCR values from the
approved ordered measurement log and supplies those independent expected values
to `tpm2_checkquote`, while nonce consumption is recorded with idempotent replay
semantics. TLS 1.3 client certificates are bound to the same enrolled client.
The protocol, topology, adverse cases, and 15-swtpm Docker campaign are tested;
the separate physical-node experiment remains a runtime acceptance gate.

## M5 implementation gate

M5 implements one attestation-gated FedAvg round with 15 isolated Docker client
containers. A signed short-lived Round Context binds M4 attestation,
enrollment, client snapshot, base model, training contract, and federation
configuration for every participant. TPM ESK-signed Update Bundles pass a
fail-closed structural and cryptographic validator before signed Contribution
Decisions are preserved. Replay slots accept only byte-identical retries, and
the signed checkpoint enumerates every admitted digest and weight. Unit, topology, and 15-swtpm runtime gates are complete. All 15 TPM-signed
bundles were accepted without errors, and independent verification reproduced
the stored FedAvg checkpoint exactly.