# M6 untargeted adaptive continuation branch — seed 342593

## Decision and provenance

The source campaign m6-adaptive-untargeted-paired-s342593-v1 stopped after 93 of 120 arm-rounds had passed the official M6 verifier. The signed M5 context for gated_adaptive round 24 expired before client signing completed. Its selected query and candidate were bound to that expired context, so the partial round is not resumed, edited, or used.

This predeclared continuation creates a separate evidence branch at
artifacts/m6-adaptive-untargeted-paired-s342593-v1-continuation-v2/.
It copies byte-for-byte the existing execution lock, coordinator authorities,
campaign precommits and 93 verified rounds: rounds 1–23 for all four arms and
gated_clean round 24. It excludes the entire partial
gated_adaptive/round-024 directory. The branch records the omitted
context digest and source hashes, then creates a new M5 context for that round
against the copied round-23 checkpoint. It also creates the not-yet-started
tpm_clean and tpm_adaptive round 24 and all rounds 25–30.

## Scientific controls

The seed, partition, four arms, adaptive objective, attackers, round schedule,
query count and budget, attack radii, validation-only selection, runtime image,
M4 trust checks, policy, aggregation, source code and locked inputs remain
identical to the source plan. No test data is accessed until all four complete
trajectories pass the round verifiers and M5 campaign gates.

This is an explicitly documented continuation branch, not a second independent
replication. The source workspace and all failed-attempt logs and receipts are
preserved unchanged. Results from the source workspace are not combined with
the branch; only the completed, independently verified branch is reported as
the campaign result. If a lock, signature, TPM identity or round verification
fails, stop and preserve the partial branch for diagnosis.

## Verification and outputs

The continuation launcher checks the 109-file source lock, source execution
lock, the exact 93-round inventory, previous verification markers, M4 network
receipt, all TPM start times, and absence of an existing branch before copying.
The copy is staged under a separate name and atomically published only after a
byte-for-byte hash inventory check. Each newly created round is aggregated and
passed through the original independent M6 verifier. The final step runs the
original M5 finalization and verification for all four complete campaigns.

Plan: configs/m6-adaptive-untargeted-continuation-s342593-v2.json.
Lock: configs/m6-adaptive-untargeted-continuation-s342593-v2.lock.json.
Launcher: scripts/resume_m6_adaptive_untargeted_paired_s342593_v2.py.
The source scientific plan and lock remain
configs/m6-adaptive-untargeted-paired-s342593-v1.json and
configs/m6-adaptive-untargeted-paired-s342593-v1.lock.json.
