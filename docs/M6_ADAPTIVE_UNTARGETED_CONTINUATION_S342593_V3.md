# M6 untargeted adaptive continuation branch — seed 342593

## Decision and provenance

The source campaign m6-adaptive-untargeted-paired-s342593-v1 stopped after 93 of 120 arm-rounds had passed the official M6 verifier. The signed M5 context for gated_adaptive round 24 expired before client signing completed. Its selected query and candidate were bound to that expired context, so the partial round is not resumed, edited, or used.

This predeclared continuation creates a separate evidence branch at
artifacts/m6-adaptive-untargeted-paired-s342593-v1-continuation-v3/.
It copies byte-for-byte the existing execution lock, coordinator authorities,
campaign precommits and 93 verified rounds: rounds 1–23 for all four arms and
gated_clean round 24. It excludes the entire partial
gated_adaptive/round-024 directory. The branch records the omitted
context digest and source hashes, then creates a new M5 context for that round
against the copied round-23 checkpoint. It also creates the not-yet-started
tpm_clean and tpm_adaptive round 24 and all rounds 25–30.

## Launcher correction

The first v2 launch wrote its own immutable process receipt before copying, then an incorrectly placed duplicate-run guard detected that receipt and stopped. No branch directory, staging tree, model round, signature or TPM operation was created. The v2 log and receipt are preserved. This v3 launcher checks for an old receipt before writing a new one; all other scientific inputs and continuation rules are unchanged.

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

Plan: configs/m6-adaptive-untargeted-continuation-s342593-v3.json.
Lock: configs/m6-adaptive-untargeted-continuation-s342593-v3.lock.json.
Launcher: scripts/resume_m6_adaptive_untargeted_paired_s342593_v3.py.
The source scientific plan and lock remain
configs/m6-adaptive-untargeted-paired-s342593-v1.json and
configs/m6-adaptive-untargeted-paired-s342593-v1.lock.json.


## Verified outcome — 2026-10-01

The separate v3 continuation completed and passed the final campaign verification for all four arms. The final marker is in `artifacts/m6-adaptive-untargeted-paired-s342593-v1-continuation-v3/complete.json`; its completion receipt records 30 rounds per arm and `status: verified`. The report is generated at `results/m6-adaptive-untargeted-paired-s342593-v1-continuation-v3/`, and all eight files match its manifest.

| Arm | Selected round | Validation macro-F1 | Test macro-F1 | Test accuracy |
|---|---:|---:|---:|---:|
| Gated-composite, clean | 30 | 0.967462 | 0.962488 | 0.978935 |
| Gated-composite, adaptive | 30 | 0.966994 | 0.962301 | 0.978732 |
| TPM-only, clean | 27 | 0.966004 | 0.957628 | 0.976707 |
| TPM-only, adaptive | 10 | 0.926522 | 0.904285 | 0.949159 |

The paired clean-minus-adaptive test macro-F1 loss is 0.000187 for gated-composite and 0.053343 for TPM-only; TPM-only minus gated-composite is 0.053156. Against the prespecified 0.01 practical threshold, only TPM-only exceeds the threshold in this seed. Treat this as a descriptive exploratory comparison: it is one seed and does not establish statistical significance or general robustness. Adaptive search and checkpoint selection use validation data; the held-out test evaluation was performed by the fixed M5 finalizer after all four trajectories passed their round gates.

## Interpretation of the adaptive rounds

The attack is active in rounds 11–30. The frozen search-success rule requires a feasible selected proposal to lower all-class validation macro-F1 by at least 0.01 against that round's clean control. This flag was true in 19/20 TPM-only adaptive rounds and 4/20 gated-composite adaptive rounds. Mean validation macro-F1 over rounds 11–30 was 0.6078 for TPM-only and 0.9344 for gated-composite. Across the clean and adaptive arms (900 decisions per policy), gated-composite recorded 714 accepted, 159 downweighted and 27 quarantined contributions; TPM-only accepted all 900.

Checkpoint timing matters when reading the held-out scores: TPM-only adaptive selected round 10, immediately before the attack starts, whereas gated-composite adaptive selected round 30. Therefore the TPM-only test score is from an unpoisoned pre-attack checkpoint. The large clean-minus-adaptive test gap reflects that validation-based selection fell back to this earlier checkpoint after later attacked rounds had poor validation performance; it is not evidence that the selected TPM-only checkpoint contains a successful poisoned update. This distinction and the single-seed scope should be retained in thesis claims.
## Attacker-versus-benign admission outcomes

In the adaptive rounds 11-30, the gated arm recorded 10 full-weight acceptances,
42 downweights, and 8 quarantines among the 60 contributions from clients
02/05/14. Its other 390 contributions comprised 339 acceptances, 47 downweights,
and 4 quarantines. The TPM-only adaptive arm accepted all 60 attack-period
contributions and all 390 other contributions. Clients 02/05/14 are counted as
benign before round 11, when the adaptive treatment starts. These values quantify
gate decisions; they do not by themselves establish successful poisoning or attacker
intent. The additional seed-level replication protocol is in
[M6 adaptive untargeted replication v1](M6_ADAPTIVE_UNTARGETED_REPLICATION_V1.md).
