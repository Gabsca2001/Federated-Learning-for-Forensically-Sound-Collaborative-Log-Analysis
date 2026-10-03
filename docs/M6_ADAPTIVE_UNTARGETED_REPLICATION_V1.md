# Untargeted adaptive M6 seed extension v1

Planned 2026-10-01 after the verified seed-342593 outcome was known. This is an
outcome-aware exploratory replication, not a confirmatory study. The existing
seed-342593 campaign remains unchanged and is not rerun.

## Question and frozen design

Does the observed difference between gated-composite and TPM-only admission recur
when the same bounded untargeted adaptive attack is run on additional prespecified
training/partition seeds?

Run the existing four-arm protocol without changing its attack or decision rules:
gated_clean, gated_adaptive, tpm_clean, and tpm_adaptive; 30 rounds per arm;
attack active in rounds 11-30; clients client02, client05, and client14;
66 fixed-budget queries per attacked round; the same four radii, step schedule,
feasibility and selection rule; validation-only search; the same M4/M5 checks,
runtime image, numerical runtime, policy and aggregation code. The practical
search-success rule remains a feasible selected proposal with at least 0.01
absolute all-class validation macro-F1 loss against that round's clean control.
Do not retune any parameter after observing seed 342593.

The additional seed set is fixed as 343593, 344593, and 345593, using their
existing verified IID partitions and seed-specific CPU federation configurations.
These seeds were already in the repository's earlier M6 seed schedule, though that
schedule used a different adaptive objective. The completed seed-342593 four-arm
campaign is the first exploratory observation; together the available set will
contain four seed-level campaigns if all three replicas verify.

Each added seed requires fresh campaign, trust and TPM-node destinations and a
distinct Docker namespace. The 342593 continuation branch and all historical
artifacts remain preserved. Each campaign has 120 secure rounds and at most 2,640
adaptive-search queries; the three added seeds require 360 rounds and at most
7,920 queries.

## Outcomes and interpretation

For each seed, report both policy-paired selected-checkpoint test macro-F1 losses
(clean minus adaptive) and their difference (TPM-only minus gated-composite).
Also report the per-round validation-search success count, selected round,
attacker-versus-benign admission/downweight/quarantine counts with denominators,
per-class test recall, reconnaissance-to-benign ASR as a secondary metric, and
execution failures. Test evaluation remains behind successful completion and
verification of all four trajectories for that seed. Never use test outcomes to
change the attack, thresholds, policies, or seed set.

The seed-342593 result is descriptive: gated search met its validation success
criterion in 4/20 attacked rounds and TPM-only in 19/20. Of the 60 attacked
client-round contributions, gated-composite accepted 10 at full weight,
downweighted 42, and quarantined 8; the TPM-only arm accepted all 60. Among 390
benign client-round contributions in the gated-adaptive arm, 339 were accepted,
47 downweighted, and 4 quarantined. The TPM-only arm accepted all 390 benign
contributions. These counts describe policy decisions, not proof of attacker intent
or successful test-set poisoning.

The additional campaigns reuse UWF-ZeekData24 and existing partitions; they are
training/partition-seed replications, not independent dataset replications. The
test observations and rounds are not independent experimental units. Report each
seed separately and summarize the small seed-level sample descriptively (mean,
sample standard deviation, and individual paired differences); do not claim
statistical significance, universal robustness, or generalization to other datasets.
Preserve the checkpoint caveat from seed 342593: its TPM-only adaptive arm selected
round 10, before the attack began, so its lower selected-test score is not evidence
that the selected checkpoint contains a poisoned update.

## Execution and recovery

Plans and immutable per-seed locks will be created for the three new seeds before
training. The new per-seed runners are fresh-only and must pass all preflights before
any campaign starts. Run the three seeds sequentially. Stop at the first error,
partial round, integrity or signature mismatch, missing runtime image, or changed
TPM start time. Preserve all workspaces, logs, locks and receipts; diagnose from
the frozen evidence and use a separate documented recovery branch only if the existing
recovery rules permit it. Never restart WSL, Docker, or TPMs during an active pair.

## Prepared per-seed inputs

Fresh-only plans, seed-specific runner/verifier copies, and SHA-256 locks are now present for seeds 343593, 344593, and 345593. The preparation script is scripts/prepare_m6_adaptive_untargeted_replicas_v1.py. Run every seed-specific runner with action preflight before starting any campaign; do not reuse the seed-342593 runner or workspace.
